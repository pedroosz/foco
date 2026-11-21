package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"foco/internal/config"
	"foco/internal/detect/catalog"
	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/provider"
	"foco/internal/retrieve"
)

func runSearch(ctx context.Context, opts SearchOptions, stdout, stderr io.Writer) int {
	path, err := config.CredentialsPath()
	if err != nil {
		return finish(stdout, err)
	}
	credentials, err := config.Load(path)
	if err != nil {
		return finish(stdout, err)
	}
	profile, err := config.Resolve(credentials)
	if err != nil {
		return finish(stdout, err)
	}
	// --parallel caps the CPU cores the whole search may use. Secret detection
	// is the CPU-heavy part and sizes its worker pools from this limit.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(max(1, opts.Parallel)))
	detector, err := newDetector()
	if err != nil {
		return finish(stdout, err)
	}
	defer detector.Close()

	policy := files.DefaultPolicy()
	policy.Hidden = opts.Policy.Hidden
	policy.NoIgnore = opts.Policy.NoIgnore
	policy.IncludeDependencies = opts.Policy.IncludeDependencies
	policy.IncludeSensitive = opts.Policy.IncludeSensitive
	policy.Exclude = opts.Policy.Exclude
	policy.Only = categorySet(opts.Policy.Only)
	policy.ExcludeTypes = categorySet(opts.Policy.ExcludeTypes)
	if catalogValue, err := catalog.Load(); err == nil {
		policy.SensitivePaths = catalogValue
	}
	reader, err := files.New(opts.Root, policy, detector, nil)
	if err != nil {
		return finish(stdout, err)
	}
	defer reader.Close()

	client := provider.New(profile, credentials.APIKey, provider.Options{
		Concurrency: opts.Concurrency, RequestLimit: opts.MaxRequests,
	})
	progress := newProgress(
		terminalWriter(stdout) && terminalWriter(stderr) && os.Getenv("CI") == "",
		stderr,
	)
	progress.Start()
	defer progress.Done()
	result, err := retrieve.Run(ctx, retrieve.Input{
		Query: opts.Query, Progress: progress.Update,
		NavigationBatchSize: opts.NavBatchSize, NavigationBatchBytes: opts.NavBatchBytes, Pipeline: opts.Pipeline,
	}, client, reader)
	return finishSearch(result, err, opts, stdout, progress)
}

func finishSearch(result retrieve.RetrievalResult, err error, opts SearchOptions, stdout io.Writer, progress *Progress) int {
	progress.Done()
	if pipeClosed(stdout) {
		return 0
	}
	if err != nil {
		if result.Status == enums.RetrievalStatusInterrupted ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			result.Status = enums.RetrievalStatusInterrupted
			fmt.Fprint(stdout, RenderResult(result, opts.MaxSourceBytes, opts.MaxOutputBytes, opts.NoLocations))
			if pipeClosed(stdout) {
				return 0
			}
			return 130
		}
		return finish(stdout, err)
	}
	fmt.Fprint(stdout, RenderResult(result, opts.MaxSourceBytes, opts.MaxOutputBytes, opts.NoLocations))
	if pipeClosed(stdout) {
		return 0
	}
	return exitCodeForResult(result)
}

func categorySet(values []enums.FileCategory) map[enums.FileCategory]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[enums.FileCategory]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
