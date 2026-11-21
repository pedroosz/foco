package retrieve

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/provider"
	"foco/internal/requests"
)

var errSourceInvalid = errors.New("source invalid")

type Input struct {
	Query    string
	Progress func(ProgressSnapshot)
	// Pipeline is PipelineClassic (the default) or PipelineOutline.
	Pipeline string
	// NavigationBatchSize and NavigationBatchBytes cap the items and the
	// serialized size of one navigation request; zero means the default.
	NavigationBatchSize  int
	NavigationBatchBytes int
}

type runState struct {
	root      string
	reader    Reader
	evaluator Evaluator
	issues    *issueSet
	mu        sync.Mutex
	inspected map[string]bool
	bytes     int
	Progress  func(ProgressSnapshot)
}

func (r *runState) report(relative string, snapshot *files.Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inspected[relative] {
		return
	}
	r.inspected[relative] = true
	r.bytes += len(snapshot.Source)
	if r.Progress != nil {
		// Progress is observational and must never change search behavior.
		func() {
			defer func() { _ = recover() }()
			r.Progress(ProgressSnapshot{Files: len(r.inspected), Bytes: r.bytes})
		}()
	}
}

// load reads a snapshot without recording issues, so parallel stages can merge
// them later in candidate order.
func (r *runState) load(ctx context.Context, relative string) (*files.Snapshot, enums.FileIssueKind) {
	result := r.reader.ReadSnapshotReuse(ctx, absPath(r.root, relative))
	if result.Status == enums.SnapshotStatusIssue {
		return nil, result.Issue
	}
	if result.Status != enums.SnapshotStatusSnapshot || result.Snapshot == nil {
		return nil, enums.UnknownFileIssueKind
	}
	snapshot := *result.Snapshot
	snapshot.Path = relative
	r.report(relative, &snapshot)
	return &snapshot, enums.UnknownFileIssueKind
}

func (r *runState) validate(ctx context.Context, donors []Donor) bool {
	for _, donor := range donors {
		result := r.reader.ReadSnapshotReuse(ctx, absPath(r.root, donor.Path))
		if result.Status != enums.SnapshotStatusSnapshot || result.Snapshot == nil || result.Snapshot.ContentHash != donor.ContentHash {
			return false
		}
	}
	return true
}

func Run(ctx context.Context, input Input, evaluator Evaluator, reader Reader) (RetrievalResult, error) {
	state := &runState{
		root: reader.Root(), reader: reader, evaluator: evaluator,
		issues: &issueSet{counts: map[enums.RetrievalIssueCode]int{}}, inspected: map[string]bool{}, Progress: input.Progress,
	}
	discovery := &discoveryState{
		Visited: map[string]bool{}, Candidates: map[string]candidate{},
		Pruned: map[string]requests.NavigationItem{}, Previews: map[string]*requests.FilePreview{},
		Donors: map[string][]Donor{},
	}
	outlineMode := input.Pipeline == PipelineOutline
	navigator := newNavigator(ctx, input.Query, evaluator, state.issues, func(item requests.NavigationItem) []Donor {
		return discovery.Donors[item.Path]
	}, state.validate, func(ctx context.Context, relative string) probeOutcome {
		snapshot, issue := state.load(ctx, relative)
		if issue != enums.UnknownFileIssueKind {
			return probeOutcome{apply: func() { state.issues.add(retrievalIssueForFileIssue(issue)) }}
		}
		if snapshot == nil {
			return probeOutcome{}
		}
		var result selectionResult
		var err error
		if outlineMode && outlinable(*snapshot) {
			result, _, _, err = outlineFile(ctx, *snapshot, input.Query, WeakScoreCeiling, evaluator, evaluator, nil)
		} else {
			result, err = selectFile(ctx, *snapshot, input.Query, WeakScoreCeiling, evaluator, nil, nil)
		}
		if err != nil {
			return probeOutcome{}
		}
		outcome := probeOutcome{apply: func() { mergeSelectionIssues(state.issues, result) }}
		for _, decision := range result.File.SourceDecisions {
			if decision.Score > SourceConfidenceBoundary {
				outcome.confident = true
				break
			}
		}
		return outcome
	})
	if input.NavigationBatchSize > 0 {
		navigator.batchSize = input.NavigationBatchSize
	}
	if input.NavigationBatchBytes > 0 {
		navigator.batchBytes = input.NavigationBatchBytes
	}
	stopPrefetch := startCandidatePrefetch(ctx, evaluator, reader, input.Query, discovery, outlineMode)
	defer stopPrefetch()
	if err := discover(ctx, state.root, reader, input.Query, []string{"."}, nil, navigator, state.issues.add, state.issues.fatal, state.report, discovery); err != nil {
		return RetrievalResult{}, err
	}
	if !state.issues.fatal() {
		if anchor, _, ok := findAnchor(ctx, reader, state.root, sortedCandidates(discovery)); ok {
			seeds, err := reconsider(ctx, reader, navigator, state.root, discovery.Pruned, anchor, discovery.Donors, state.issues.add, state.report)
			if err != nil {
				return RetrievalResult{}, err
			}
			if len(seeds) > 0 && !state.issues.fatal() {
				if err := discover(ctx, state.root, reader, input.Query, seeds, anchor, navigator, state.issues.add, state.issues.fatal, state.report, discovery); err != nil {
					return RetrievalResult{}, err
				}
			}
		}
	}
	ordered := sortedCandidates(discovery)
	// Role assessment and the first source-selection pass are independent, so
	// they run concurrently. Their outcomes are merged afterwards in the
	// sequential order: assessments first, then selection.
	assessments := map[string]assessment{}
	var assessed []assessmentOutcome
	var assessing sync.WaitGroup
	if !state.issues.fatal() {
		assessed = make([]assessmentOutcome, len(ordered))
		assessing.Add(1)
		go func() {
			defer assessing.Done()
			parallelCandidates(ordered, func(index int, entry candidate) {
				if ctx.Err() != nil || state.issues.fatal() {
					return
				}
				if outlineMode {
					if read := reader.ReadSnapshotReuse(ctx, absPath(state.root, entry.Path)); read.Snapshot != nil {
						snapshot := *read.Snapshot
						snapshot.Path = entry.Path
						if outlinable(snapshot) {
							return
						}
					}
				}
				result, failure := assessFile(ctx, evaluator, input.Query, entry, discovery.Previews[entry.Path])
				assessed[index] = assessmentOutcome{result: &result, failure: failure}
			})
		}()
	}
	outlineRoles := make([]*assessment, len(ordered))
	outlined := make([]bool, len(ordered))
	mergeAssessments := func() {
		assessing.Wait()
		defer func() {
			for index, entry := range ordered {
				if outlineRoles[index] != nil {
					assessments[entry.Path] = *outlineRoles[index]
				}
			}
		}()
		for index, entry := range ordered {
			if assessed == nil {
				break
			}
			outcome := assessed[index]
			if outcome.failure != nil {
				recordFailure(state.issues, outcome.failure)
				continue
			}
			if outcome.result != nil {
				assessments[entry.Path] = *outcome.result
			}
		}
	}
	filesByPath := map[string]FileEvidence{}
	groupsByPath := map[string]int{}
	selectOutcomes := func(evidence []requests.Evidence) []selectionOutcome {
		outcomes := make([]selectionOutcome, len(ordered))
		parallelCandidates(ordered, func(index int, entry candidate) {
			if ctx.Err() != nil || state.issues.fatal() {
				return
			}
			snapshot, issue := state.load(ctx, entry.Path)
			outcomes[index].issue = issue
			if snapshot == nil {
				return
			}
			var prepare func(context.Context) ([]requests.Evidence, bool, error)
			if evidence != nil {
				prepare = func(ctx context.Context) ([]requests.Evidence, bool, error) {
					fresh := make([]requests.Evidence, 0, len(evidence))
					for _, item := range evidence {
						if state.issues.fatal() {
							return nil, false, nil
						}
						donor, ok := discovery.Candidates[item.Path]
						if !ok {
							continue
						}
						result := reader.ReadSnapshotReuse(ctx, absPath(state.root, item.Path))
						switch {
						case result.Status == enums.SnapshotStatusSnapshot && result.Snapshot != nil && result.Snapshot.ContentHash == donor.ContentHash:
							state.report(item.Path, result.Snapshot)
							fresh = append(fresh, item)
						case result.Status == enums.SnapshotStatusIssue:
							state.issues.add(retrievalIssueForFileIssue(result.Issue))
						default:
							state.issues.add(enums.IssueCodeChanged)
						}
						if state.issues.fatal() {
							return nil, false, nil
						}
					}
					return fresh, true, nil
				}
			}
			validate := func(ctx context.Context) error {
				if !state.validate(ctx, discovery.Donors[entry.Path]) {
					return errSourceInvalid
				}
				return nil
			}
			if outlineMode && outlinable(*snapshot) {
				outlined[index] = true
				if evidence != nil {
					return
				}
				result, roles, _, err := outlineFile(ctx, *snapshot, input.Query, entry.Score, evaluator, evaluator, validate)
				if err != nil {
					if ctx.Err() == nil {
						outcomes[index].failure = asFailure(err)
					}
					return
				}
				outcomes[index].result, outlineRoles[index] = &result, roles
				return
			}
			result, err := selectFile(ctx, *snapshot, input.Query, entry.Score, evaluator, prepare, validate)
			if err != nil {
				if ctx.Err() == nil {
					outcomes[index].failure = asFailure(err)
				}
				return
			}
			outcomes[index].result = &result
		})
		return outcomes
	}
	mergeSelection := func(outcomes []selectionOutcome) {
		for index, entry := range ordered {
			outcome := outcomes[index]
			if outcome.issue != enums.UnknownFileIssueKind {
				state.issues.add(retrievalIssueForFileIssue(outcome.issue))
				continue
			}
			if outcome.failure != nil {
				recordFailure(state.issues, outcome.failure)
				continue
			}
			if outcome.result == nil {
				continue
			}
			mergeSelectionIssues(state.issues, *outcome.result)
			filesByPath[entry.Path] = outcome.result.File
			groupsByPath[entry.Path] = outcome.result.Groups
		}
	}
	first := selectOutcomes(nil)
	mergeAssessments()
	// A fatal assessment failure stops the sequential flow before selection
	// starts, so its selection outcomes are discarded.
	if !state.issues.fatal() {
		mergeSelection(first)
		if outlineMode && ctx.Err() == nil {
			resolveReferences(ctx, reader, state.root, ordered, outlined, filesByPath)
		}
	}
	evidence := []requests.Evidence{}
	if !state.issues.fatal() && ctx.Err() == nil {
		donors := make([]string, 0, len(filesByPath))
		for path, file := range filesByPath {
			if len(file.Excerpts) > 0 {
				donors = append(donors, path)
			}
		}
		sort.Slice(donors, func(i, j int) bool {
			if groupsByPath[donors[i]] != groupsByPath[donors[j]] {
				return groupsByPath[donors[i]] < groupsByPath[donors[j]]
			}
			return donors[i] < donors[j]
		})
		for _, path := range donors {
			file := filesByPath[path]
			if !state.validate(ctx, []Donor{{Path: path, ContentHash: file.ContentHash}}) {
				continue
			}
			for _, excerpt := range file.Excerpts {
				evidence = append(evidence, requests.Evidence{
					Path: path, StartLine: excerpt.Range.StartLine, EndLine: excerpt.Range.EndLine, Source: excerpt.Source,
				})
			}
		}
		// The reference sends all evidence or none: an oversized set is dropped
		// entirely rather than truncated.
		if serializedSize(evidence) > EvidenceBytes {
			evidence = []requests.Evidence{}
		}
		if len(evidence) > 0 {
			mergeSelection(selectOutcomes(evidence))
		}
	}
	stopPrefetch()
	for path, result := range assessments {
		file, ok := filesByPath[path]
		if !ok || file.SourceOmitted {
			continue
		}
		file.Roles = result.Labels
		priority := result.Priority
		file.Priority = &priority
		filesByPath[path] = file
	}
	for _, entry := range ordered {
		file, ok := filesByPath[entry.Path]
		if !ok {
			file = FileEvidence{
				Path: entry.Path, ContentHash: entry.ContentHash, Score: entry.Score,
				Roles:                []enums.AssessmentRole{},
				Selected:             []EvidenceRange{},
				Rendered:             []EvidenceRange{},
				Excerpts:             []Excerpt{},
				PresentationExcerpts: []Excerpt{},
				PresentationSelected: []EvidenceRange{},
				SourceDecisions:      []SourceDecision{},
			}
		}
		result := reader.ReadSnapshotReuse(ctx, absPath(state.root, entry.Path))
		if result.Status == enums.SnapshotStatusSnapshot && result.Snapshot != nil && result.Snapshot.ContentHash == entry.ContentHash {
			state.report(entry.Path, result.Snapshot)
			filesByPath[entry.Path] = file
			continue
		}
		if result.Status == enums.SnapshotStatusIssue {
			state.issues.add(retrievalIssueForFileIssue(result.Issue))
		} else {
			state.issues.add(enums.IssueCodeChanged)
		}
		file.SourceOmitted = true
		file.Roles = nil
		file.Priority = nil
		file.Selected = []EvidenceRange{}
		file.Rendered = []EvidenceRange{}
		file.Excerpts = []Excerpt{}
		file.PresentationExcerpts = []Excerpt{}
		file.PresentationSelected = []EvidenceRange{}
		file.SourceDecisions = []SourceDecision{}
		filesByPath[entry.Path] = file
	}
	finalFiles := make([]FileEvidence, 0, len(ordered))
	for _, entry := range ordered {
		if file, ok := filesByPath[entry.Path]; ok {
			finalFiles = append(finalFiles, file)
		}
	}
	// Authentication with no admitted files is fatal. Check it before the
	// AGENTS lookup so a failed run never inspects instruction files.
	if state.issues.has(enums.IssueCodeAuthentication) && len(finalFiles) == 0 {
		status := enums.RetrievalStatusIncomplete
		if ctx.Err() != nil {
			status = enums.RetrievalStatusInterrupted
		}
		return RetrievalResult{
			Root: state.root, Query: input.Query, Status: status, Files: finalFiles,
			Issues: state.issues.list(), ProviderFailure: state.issues.failureMessage(),
			Counts: Counts{
				Requests: evaluator.Requests(), CacheHits: cacheHits(evaluator), InspectedFiles: len(state.inspected),
			},
		}, &provider.Failure{
			Kind: enums.FailureAuthentication, Message: "API authentication failed.",
		}
	}
	contextResult, err := gatherRepositoryContext(ctx, reader, finalFiles)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return RetrievalResult{}, err
		}
		contextResult = RepositoryContext{}
	}
	interrupted := ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	if interrupted && !state.issues.has(enums.IssueCodeInterrupted) {
		state.issues.add(enums.IssueCodeInterrupted)
	}
	status := enums.RetrievalStatusComplete
	if interrupted {
		status = enums.RetrievalStatusInterrupted
	} else if len(state.issues.list()) > 0 {
		status = enums.RetrievalStatusIncomplete
	}
	return RetrievalResult{
		Root: state.root, Query: input.Query, Status: status, Files: finalFiles,
		Issues: state.issues.list(), ProviderFailure: state.issues.failureMessage(),
		RepositoryContext: contextResult,
		Counts: Counts{
			Requests: evaluator.Requests(), CacheHits: cacheHits(evaluator), InspectedFiles: len(state.inspected),
		},
	}, nil
}

type assessmentOutcome struct {
	result  *assessment
	failure *provider.Failure
}

type selectionOutcome struct {
	result  *selectionResult
	failure *provider.Failure
	issue   enums.FileIssueKind
}

func mergeSelectionIssues(issues *issueSet, result selectionResult) {
	issues.mu.Lock()
	defer issues.mu.Unlock()
	for _, issue := range result.Issues {
		for count := 0; count < issue.Count; count++ {
			issues.addLocked(issue.Kind)
		}
	}
	if result.ProviderFailure != "" && issues.providerFailure == "" {
		issues.providerFailure = result.ProviderFailure
	}
}

// resolveReferences adds locally resolved references to outlined files, in
// place of the provider's evidence pass.
func resolveReferences(ctx context.Context, reader Reader, root string, ordered []candidate, outlined []bool, filesByPath map[string]FileEvidence) {
	evidence := map[string][]Excerpt{}
	for path, file := range filesByPath {
		if len(file.Excerpts) > 0 {
			evidence[path] = file.Excerpts
		}
	}
	for index, entry := range ordered {
		file, ok := filesByPath[entry.Path]
		if !outlined[index] || !ok || file.SourceOmitted {
			continue
		}
		read := reader.ReadSnapshotReuse(ctx, absPath(root, entry.Path))
		if read.Snapshot == nil || read.Snapshot.ContentHash != file.ContentHash {
			continue
		}
		snapshot := *read.Snapshot
		snapshot.Path = entry.Path
		if updated, changed := withReferences(ctx, snapshot, file, referencedWindows(snapshot, file, evidence)); changed {
			filesByPath[entry.Path] = updated
		}
	}
}

func recordFailure(issues *issueSet, failure *provider.Failure) {
	if failure == nil {
		return
	}
	if failure.Kind == enums.FailureProvider {
		if failure.Message != "" {
			issues.addProvider(failure.Message)
		} else {
			issues.add(enums.IssueCodeProvider)
		}
		return
	}
	issues.add(retrievalIssueForProviderFailure(failure.Kind))
}

func cacheHits(evaluator Evaluator) int {
	if counter, ok := evaluator.(interface{ CacheHits() int }); ok {
		return counter.CacheHits()
	}
	return 0
}

func serializedSize(value any) int {
	blob, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(blob)
}

func parallelCandidates(items []candidate, work func(int, candidate)) {
	var wait sync.WaitGroup
	slots := make(chan struct{}, StageWorkers)
	for index, item := range items {
		wait.Add(1)
		slots <- struct{}{}
		go func(index int, entry candidate) {
			defer wait.Done()
			defer func() { <-slots }()
			work(index, entry)
		}(index, item)
	}
	wait.Wait()
}
