package retrieve

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/provider"
	"foco/internal/requests"
)

// readWorkers bounds concurrent snapshot reads. Reads mix I/O with content
// detection, and the detector meters its own CPU use, so this allows more
// workers than CPUs to keep the detector busy while other reads wait on disk.
func readWorkers() int { return max(2, 2*runtime.GOMAXPROCS(0)) }

// readSnapshots reads every path concurrently and returns the results in input
// order. Callers keep consuming results (and recording issues and progress) in
// their original order, so concurrency changes timing but not outcomes.
func readSnapshots(ctx context.Context, reader Reader, paths []string) []files.SnapshotResult {
	out := make([]files.SnapshotResult, len(paths))
	workers := min(len(paths), readWorkers())
	if workers <= 1 {
		for index, path := range paths {
			out[index] = reader.ReadSnapshotReuse(ctx, path)
		}
		return out
	}
	var next atomic.Int64
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				index := int(next.Add(1)) - 1
				if index >= len(paths) {
					return
				}
				out[index] = reader.ReadSnapshotReuse(ctx, paths[index])
			}
		}()
	}
	wait.Wait()
	return out
}

type prefetcher interface {
	Prefetch(ctx context.Context, request provider.Request)
}

// prefetchEvaluator turns every Evaluate into a Prefetch, so running the
// normal request builders through it warms exactly the requests they would
// later send.
type prefetchEvaluator struct{ inner prefetcher }

func (p prefetchEvaluator) Requests() int { return 0 }

func (p prefetchEvaluator) Evaluate(ctx context.Context, request provider.Request, _ provider.EvalOptions) (map[string]float64, error) {
	p.inner.Prefetch(ctx, request)
	return nil, errPrefetched
}

var errPrefetched = errors.New("prefetched")

// startCandidatePrefetch warms the role-assessment and first selection-pass
// requests of each candidate as discovery admits it. Those requests depend
// only on the query, the path and the file content, so they can be sent while
// discovery is still waiting on navigation, using concurrency it leaves idle.
// The final passes then build identical requests and get memoized answers.
func startCandidatePrefetch(ctx context.Context, evaluator Evaluator, reader Reader, query string, discovery *discoveryState, outlineMode bool) func() {
	source, ok := evaluator.(prefetcher)
	if !ok {
		return func() {}
	}
	warm := prefetchEvaluator{inner: source}
	child, cancel := context.WithCancel(ctx)
	var running sync.WaitGroup
	var mu sync.Mutex
	type job struct {
		path    string
		preview *requests.FilePreview
		assess  bool
	}
	queue := []job{}
	active := 0
	read := func(relative string) (files.Snapshot, bool) {
		result := reader.ReadSnapshotReuse(child, absPath(reader.Root(), relative))
		if result.Status != enums.SnapshotStatusSnapshot || result.Snapshot == nil {
			return files.Snapshot{}, false
		}
		snapshot := *result.Snapshot
		snapshot.Path = relative
		return snapshot, true
	}
	work := func(next job) {
		if next.assess {
			if outlineMode {
				if snapshot, ok := read(next.path); ok && outlinable(snapshot) {
					return
				}
			}
			_, _ = assessFile(child, warm, query, candidate{Path: next.path}, next.preview)
			return
		}
		snapshot, ok := read(next.path)
		if !ok {
			return
		}
		if outlineMode && outlinable(snapshot) {
			_, _, _, _ = outlineFile(child, snapshot, query, 0, prefetchThenEvaluate{warm: source, inner: evaluator}, warm, nil)
			return
		}
		_, _ = selectFile(child, snapshot, query, 0, warm, nil, nil)
	}
	// A fixed pool of StageWorkers drains the admitted paths, so a repository
	// with thousands of candidates never holds thousands of goroutines or reads
	// at once. Assessment and selection are separate jobs, so a worker waiting
	// on one request never holds back the other.
	discovery.Admitted = func(relative string) {
		preview := discovery.Previews[relative]
		mu.Lock()
		defer mu.Unlock()
		queue = append(queue, job{path: relative, preview: preview, assess: true}, job{path: relative})
		for spawned := 0; spawned < 2 && active < StageWorkers; spawned++ {
			active++
			running.Add(1)
			go func() {
				defer running.Done()
				for {
					mu.Lock()
					if len(queue) == 0 || child.Err() != nil {
						active--
						mu.Unlock()
						return
					}
					next := queue[0]
					queue = queue[1:]
					mu.Unlock()
					work(next)
				}
			}()
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			discovery.Admitted = nil
			cancel()
			running.Wait()
		})
	}
}

// readAhead reads the files of one discovery level ahead of the sequential
// consumer. A background walker lists the level's directories in the same
// order discover visits them (each seed, then the subdirectories found one
// level below) and starts reads for their files, so detection runs in parallel
// across directories instead of one small directory at a time. The consumer
// still takes results in its own order and records issues itself; the walker
// only warms results.
type readAhead struct {
	ctx     context.Context
	cancel  context.CancelFunc
	reader  Reader
	mu      sync.Mutex
	pending map[string]*pendingRead
	pages   map[pageKey]*pageCall
	taken   map[string]bool
	ahead   chan struct{}
	workers chan struct{}
	done    sync.WaitGroup
}

type pageKey struct {
	directory string
	offset    int
}

type pageCall struct {
	ready chan struct{}
	page  files.Page
	err   error
}

type pageLister func(ctx context.Context, directory string, offset int) (files.Page, error)

// listPage lists one directory page at most once for the walker and the
// consumer together, so read-ahead adds no directory listings of its own.
func (r *readAhead) listPage(ctx context.Context, directory string, offset int) (files.Page, error) {
	key := pageKey{directory: directory, offset: offset}
	r.mu.Lock()
	call, ok := r.pages[key]
	if !ok {
		call = &pageCall{ready: make(chan struct{})}
		r.pages[key] = call
	}
	r.mu.Unlock()
	if ok {
		select {
		case <-call.ready:
		case <-ctx.Done():
			return files.Page{Path: directory, Entries: []files.Entry{}, Excluded: map[string]int{}}, ctx.Err()
		}
		if call.err != nil && ctx.Err() == nil {
			return r.reader.ListPage(ctx, directory, offset)
		}
		return call.page, call.err
	}
	call.page, call.err = r.reader.ListPage(ctx, directory, offset)
	close(call.ready)
	return call.page, call.err
}

type pendingRead struct {
	ready  chan struct{}
	result files.SnapshotResult
}

func startReadAhead(ctx context.Context, reader Reader, root string, directories []string) *readAhead {
	child, cancel := context.WithCancel(ctx)
	ahead := &readAhead{
		ctx: child, cancel: cancel, reader: reader, pending: map[string]*pendingRead{}, pages: map[pageKey]*pageCall{}, taken: map[string]bool{},
		ahead: make(chan struct{}, 4*readWorkers()), workers: make(chan struct{}, readWorkers()),
	}
	ahead.done.Add(1)
	go ahead.walk(root, directories)
	return ahead
}

func (r *readAhead) stop() {
	r.cancel()
	r.done.Wait()
}

func (r *readAhead) walk(root string, directories []string) {
	defer r.done.Done()
	level := make([]levelDirectory, 0, len(directories))
	for _, directory := range directories {
		level = append(level, levelDirectory{Path: directory})
	}
	seen := map[string]bool{}
	listed := 0
	for index := 0; index < len(level) && listed < DiscoveryLimit; index++ {
		current := level[index]
		if seen[current.Path] {
			continue
		}
		seen[current.Path] = true
		entries := r.list(absPath(root, current.Path), DiscoveryLimit-listed)
		listed += len(entries)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		for _, entry := range entries {
			if entry.IsDir {
				if current.Depth == 0 {
					level = append(level, levelDirectory{Path: relPath(root, entry.Path), Depth: 1})
				}
				continue
			}
			if !r.submit(entry.Path) {
				return
			}
		}
	}
}

func (r *readAhead) list(directory string, limit int) []files.Entry {
	entries := []files.Entry{}
	offset := 0
	for r.ctx.Err() == nil && len(entries) < limit {
		page, err := r.listPage(r.ctx, directory, offset)
		if err != nil || page.Issue != enums.UnknownFileIssueKind {
			break
		}
		entries = append(entries, page.Entries...)
		if page.NextOffset == 0 || page.NextOffset == offset {
			break
		}
		offset = page.NextOffset
	}
	return entries
}

func (r *readAhead) submit(path string) bool {
	select {
	case r.ahead <- struct{}{}:
	case <-r.ctx.Done():
		return false
	}
	r.mu.Lock()
	if _, ok := r.pending[path]; ok || r.taken[path] {
		r.mu.Unlock()
		<-r.ahead
		return true
	}
	pending := &pendingRead{ready: make(chan struct{})}
	r.pending[path] = pending
	r.mu.Unlock()
	select {
	case r.workers <- struct{}{}:
	case <-r.ctx.Done():
		pending.result = r.reader.ReadSnapshotReuse(r.ctx, path)
		close(pending.ready)
		return false
	}
	r.done.Add(1)
	go func() {
		defer r.done.Done()
		defer func() { <-r.workers }()
		pending.result = r.reader.ReadSnapshotReuse(r.ctx, path)
		close(pending.ready)
	}()
	return true
}

// get returns the read for path, waiting for read-ahead when it already
// started and reading directly otherwise.
func (r *readAhead) get(ctx context.Context, path string) files.SnapshotResult {
	r.mu.Lock()
	pending, ok := r.pending[path]
	if ok {
		delete(r.pending, path)
	}
	r.taken[path] = true
	r.mu.Unlock()
	if !ok {
		return r.reader.ReadSnapshotReuse(ctx, path)
	}
	<-pending.ready
	<-r.ahead
	return pending.result
}
