package detect

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/sources"
)

// Betterleaks scans with a pool of betterleaks detectors. Building a detector
// compiles its rules (~10ms) and mutates its config, so each detector gets its
// own config and they are built in the background, one at a time; each joins
// the pool as soon as it is built, so the first scan waits for one detector,
// not for the whole pool.
type Betterleaks struct {
	pool chan *detect.Detector
}

func NewBetterleaks(workers int) (*Betterleaks, error) {
	if workers < 1 {
		workers = 1
	}
	first, err := config.Default()
	if err != nil {
		return nil, err
	}
	b := &Betterleaks{pool: make(chan *detect.Detector, workers)}
	go func() {
		for i := 0; i < workers; i++ {
			cfg := first
			if i > 0 {
				next, err := config.Default()
				if err != nil {
					return
				}
				cfg = next
			}
			detector := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
			detector.SkipFindingAppend = true
			b.pool <- detector
		}
	}()
	return b, nil
}

func (b *Betterleaks) acquire(ctx context.Context) (*detect.Detector, error) {
	select {
	case detector := <-b.pool:
		return detector, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *Betterleaks) DetectPath(ctx context.Context, path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	return b.scan(ctx, path, file)
}

func (b *Betterleaks) DetectContent(ctx context.Context, path string, content []byte) (bool, error) {
	return b.scan(ctx, path, bytes.NewReader(content))
}

func (b *Betterleaks) scan(ctx context.Context, path string, content io.Reader) (bool, error) {
	detector, err := b.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer func() { b.pool <- detector }()

	var found bool
	var firstErr error
	for result := range detector.Run(ctx, &sources.File{Path: path, Content: content}) {
		if result.Err != nil {
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
		if result.Finding.RuleID != "" {
			found = true
		}
	}
	return found, firstErr
}

func (b *Betterleaks) Close() error { return nil }

var _ Engine = (*Betterleaks)(nil)
var _ ContentDetector = (*Betterleaks)(nil)
