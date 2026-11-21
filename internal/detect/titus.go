package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/praetorian-inc/titus/pkg/rule"
)

var _ Engine = (*Titus)(nil)
var _ ContentDetector = (*Titus)(nil)

// titusParallelThreshold mirrors the Titus portable matcher: content at or
// above this size is matched by a worker per CPU, below it on one goroutine.
const titusParallelThreshold = 10000

// titusExclusiveThreshold is the size from which a scan gets every CPU slot.
// Between the two thresholds a scan takes a quarter of the slots, so up to
// four mid-sized files overlap: Titus spreads one file's rules across all
// CPUs, but a few slow rules leave most of them idle near the end of each
// file. The overlap at most quadruples per-rule latency, which for content
// under this size stays milliseconds against Titus's 5s per-match timeout.
const titusExclusiveThreshold = 256 << 10

// Titus is an Engine that detects sensitive content with the Titus scanner.
//
// The scanner is safe for concurrent use. Scans are admitted through a
// CPU-weighted semaphore (see scanWeight) so concurrent scans keep the CPUs
// busy without starving any regex toward Titus's per-match timeout.
//
// Loading the rules (~20ms of YAML parsing plus matcher compilation) runs in
// the background from NewTitus, so cheaper engines in the union can answer
// first; the first Titus scan waits for it.
type Titus struct {
	mu      sync.RWMutex
	scanner *titusRules
	loadErr error
	loaded  chan struct{}
	closed  bool
	cpu     *cpuSlots
	slots   int
}

// cpuSlots is a weighted semaphore over CPU slots. Acquisitions of more than
// one slot are serialized so two wide scans can never each hold part of the
// pool and wait on the other.
type cpuSlots struct {
	tokens chan struct{}
	wide   sync.Mutex
}

func newCPUSlots(n int) *cpuSlots {
	return &cpuSlots{tokens: make(chan struct{}, n)}
}

func (c *cpuSlots) acquire(ctx context.Context, n int) error {
	if n > 1 {
		c.wide.Lock()
		defer c.wide.Unlock()
	}
	for taken := 0; taken < n; taken++ {
		select {
		case c.tokens <- struct{}{}:
		case <-ctx.Done():
			c.release(taken)
			return ctx.Err()
		}
	}
	return nil
}

func (c *cpuSlots) release(n int) {
	for range n {
		<-c.tokens
	}
}

// NewTitus returns a Titus engine over the builtin Titus rules.
// Noisy rules are excluded, matching the default behaviour of `titus scan`.
func NewTitus() (*Titus, error) {
	slots := max(1, runtime.GOMAXPROCS(0))
	t := &Titus{cpu: newCPUSlots(slots), slots: slots, loaded: make(chan struct{})}
	go func() {
		defer close(t.loaded)
		rules, err := rule.NewLoader().LoadBuiltinRules()
		if err != nil {
			t.loadErr = fmt.Errorf("detect: loading titus rules: %w", err)
			return
		}
		t.scanner, t.loadErr = newTitusRules(rule.FilterNoisy(rules, false), prefilterTitusRules)
	}()
	return t, nil
}

// ready waits for the rules to load.
func (t *Titus) ready(ctx context.Context) (*titusRules, error) {
	select {
	case <-t.loaded:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if t.loadErr != nil {
		return nil, t.loadErr
	}
	return t.scanner, nil
}

// DetectPath reports whether path contains content the scanner treats as sensitive.
func (t *Titus) DetectPath(ctx context.Context, path string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, err := t.ready(ctx); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading file: %w", err)
	}
	return t.DetectContent(ctx, path, data)
}

func (t *Titus) DetectContent(ctx context.Context, _ string, content []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	scanner, err := t.ready(ctx)
	if err != nil {
		return false, err
	}
	weight := scanWeight(len(content), t.slots)
	if err := t.cpu.acquire(ctx, weight); err != nil {
		return false, err
	}
	defer t.cpu.release(weight)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if t.closed {
		return false, errors.New("detect: engine closed")
	}
	return scanner.match(content)
}

func scanWeight(size, slots int) int {
	switch {
	case size < titusParallelThreshold:
		return 1
	case size < titusExclusiveThreshold:
		return max(1, (slots+3)/4)
	default:
		return slots
	}
}

// Close releases the underlying scanner. Additional calls are no-ops.
func (t *Titus) Close() error {
	<-t.loaded
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.scanner == nil {
		return nil
	}
	t.closed = true
	return t.scanner.close()
}
