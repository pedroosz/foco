package retrieve

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/provider"
	"foco/internal/requests"
)

func pipelineEvaluator(roleHook func()) *scriptedEvaluator {
	return &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		out := map[string]float64{}
		switch state := request.State.(type) {
		case requests.NavigationRequestState:
			for index, item := range state.Items {
				value := 0.1
				if item.Kind == enums.NavigationKindFile && strings.HasSuffix(item.Path, ".ts") {
					value = 0.9
				}
				out["q"+itoa(index)] = value
			}
		case requests.EvidenceState:
			for index := range state.Declarations {
				out["q"+itoa(index)] = 0.9
				out["scope"+itoa(index)] = 0.9
				if state.SelectedEvidence != nil {
					out["ref"+itoa(index)] = 0.9
				}
			}
		case requests.AssessmentState:
			if roleHook != nil {
				roleHook()
			}
			out["implementation"] = 0.9
			out["caller"] = 0.1
			out["test"] = 0.1
			out["fixture"] = 0.1
			out["helper"] = 0.1
			out["priority"] = 0.9
		}
		return out, nil
	}}
}

func TestRunReturnsSourceRolesContextAndCounts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src/events.ts"), []byte("export function record(name: string) { return name; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("guidance\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var progress []ProgressSnapshot
	result, err := Run(context.Background(), Input{
		Query:    "event recording",
		Progress: func(snapshot ProgressSnapshot) { progress = append(progress, snapshot) },
	}, pipelineEvaluator(nil), reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != enums.RetrievalStatusComplete {
		t.Fatalf("status = %q issues=%+v", result.Status, result.Issues)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "src/events.ts" {
		t.Fatalf("files = %+v", result.Files)
	}
	file := result.Files[0]
	if len(file.Roles) != 1 || file.Roles[0] != enums.AssessmentRoleImplementation {
		t.Fatalf("roles = %v", file.Roles)
	}
	if file.Priority == nil || *file.Priority != 0.9 {
		t.Fatalf("priority = %v", file.Priority)
	}
	source := ""
	for _, excerpt := range file.Excerpts {
		source += excerpt.Source
	}
	if !strings.Contains(source, "export function record") {
		t.Fatalf("source = %q", source)
	}
	if len(result.RepositoryContext.InstructionFiles) != 1 || result.RepositoryContext.InstructionFiles[0] != "AGENTS.md" {
		t.Fatalf("context = %+v", result.RepositoryContext)
	}
	if result.Counts.Requests == 0 || result.Counts.CacheHits != 0 || result.Counts.InspectedFiles != 2 {
		t.Fatalf("counts = %+v", result.Counts)
	}
	if len(progress) == 0 || progress[len(progress)-1].Files != 2 {
		t.Fatalf("progress = %+v", progress)
	}
}

func TestRunInvalidatesSourceChangedDuringAssessment(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.ts")
	if err := os.WriteFile(path, []byte("export function first() { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	result, err := Run(context.Background(), Input{Query: "first"}, pipelineEvaluator(func() {
		_ = os.WriteFile(path, []byte("export function second() { return 2; }\n"), 0o644)
	}), reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != enums.RetrievalStatusIncomplete {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Files) != 1 || !result.Files[0].SourceOmitted || len(result.Files[0].Excerpts) != 0 {
		t.Fatalf("file = %+v", result.Files)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == enums.IssueCodeChanged {
			found = true
		}
	}
	if !found {
		t.Fatalf("issues = %+v", result.Issues)
	}
}

func TestRunReturnsAuthenticationErrorWithoutFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.ts"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	counting := &lookupCountingReader{Reader: reader}
	evaluator := &scriptedEvaluator{answers: func(provider.Request) (map[string]float64, error) {
		return nil, &provider.Failure{Kind: enums.FailureAuthentication, Message: "API authentication failed."}
	}}
	result, err := Run(context.Background(), Input{Query: "x"}, evaluator, counting)
	if err == nil {
		t.Fatal("expected authentication error")
	}
	var failure *provider.Failure
	if !errors.As(err, &failure) || failure.Kind != enums.FailureAuthentication {
		t.Fatalf("err = %v", err)
	}
	if result.Status != enums.RetrievalStatusIncomplete {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Files) != 0 {
		t.Fatalf("files = %+v", result.Files)
	}
	if result.Counts.Requests == 0 || result.Counts.InspectedFiles == 0 {
		t.Fatalf("counts = %+v", result.Counts)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == enums.IssueCodeAuthentication {
			found = true
		}
	}
	if !found {
		t.Fatalf("issues = %+v", result.Issues)
	}
	if got := counting.Count(); got != 0 {
		t.Fatalf("AGENTS lookups = %d, want 0", got)
	}
}

type lookupCountingReader struct {
	Reader
	mu      sync.Mutex
	lookups int
}

func (r *lookupCountingReader) LookupFile(ctx context.Context, path string) (files.LookupResult, error) {
	r.mu.Lock()
	r.lookups++
	r.mu.Unlock()
	return r.Reader.LookupFile(ctx, path)
}

func (r *lookupCountingReader) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

type cancelOnLookupReader struct {
	Reader
	cancel context.CancelFunc
}

func (r *cancelOnLookupReader) LookupFile(context.Context, string) (files.LookupResult, error) {
	r.cancel()
	return files.LookupResult{}, context.Canceled
}

func TestRunCancellationDuringRepositoryContextIsInterrupted(t *testing.T) {
	root := t.TempDir()
	writeRetrieveFile(t, root, "a.ts", "export function record(name: string) { return name; }\n")
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result, err := Run(ctx, Input{Query: "record"}, pipelineEvaluator(nil), &cancelOnLookupReader{Reader: reader, cancel: cancel})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != enums.RetrievalStatusInterrupted {
		t.Fatalf("status = %q", result.Status)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == enums.IssueCodeInterrupted {
			found = true
		}
	}
	if !found {
		t.Fatalf("issues = %+v", result.Issues)
	}
	if len(result.RepositoryContext.InstructionFiles) != 0 || result.RepositoryContext.InstructionLookupIncomplete {
		t.Fatalf("context = %+v, want zero", result.RepositoryContext)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "a.ts" {
		t.Fatalf("files = %+v", result.Files)
	}
}

func TestRunStopsAfterFatalAssessment(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.ts", "b.ts", "c.ts"} {
		writeRetrieveFile(t, root, name, "export function handler() { return 1; }\n")
	}
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var mu sync.Mutex
	assessments, evidence := 0, 0
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		switch state := request.State.(type) {
		case requests.NavigationRequestState:
			out := map[string]float64{}
			for index := range state.Items {
				out["q"+itoa(index)] = 0.55
			}
			return out, nil
		case requests.EvidenceState:
			mu.Lock()
			evidence++
			mu.Unlock()
			out := map[string]float64{}
			for index := range state.Declarations {
				out["q"+itoa(index)] = 0.9
				out["scope"+itoa(index)] = 0.9
				if state.SelectedEvidence != nil {
					out["ref"+itoa(index)] = 0.9
				}
			}
			return out, nil
		case requests.AssessmentState:
			mu.Lock()
			assessments++
			mu.Unlock()
			return nil, &provider.Failure{Kind: enums.FailureAuthentication, Message: "API authentication failed."}
		}
		return map[string]float64{}, nil
	}}
	result, err := Run(context.Background(), Input{Query: "handler"}, evaluator, reader)
	if err != nil {
		t.Fatal(err)
	}
	if assessments != 3 {
		t.Fatalf("assessment requests = %d, want 3", assessments)
	}
	// Selection runs concurrently with assessment, but a fatal assessment
	// discards its outcome: no file may carry selected source.
	for _, file := range result.Files {
		if len(file.Excerpts) != 0 || len(file.SourceDecisions) != 0 {
			t.Fatalf("selection survived fatal assessment (evidence requests = %d): %+v", evidence, file)
		}
	}
	if result.Status != enums.RetrievalStatusIncomplete {
		t.Fatalf("status = %q", result.Status)
	}
	if len(result.Files) != 3 {
		t.Fatalf("files = %+v", result.Files)
	}
	for _, file := range result.Files {
		if file.Roles == nil || file.Selected == nil || file.Rendered == nil ||
			file.Excerpts == nil || file.PresentationExcerpts == nil ||
			file.PresentationSelected == nil || file.SourceDecisions == nil {
			t.Fatalf("file slices must be empty, not nil: %+v", file)
		}
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == enums.IssueCodeAuthentication {
			found = true
		}
	}
	if !found {
		t.Fatalf("issues = %+v", result.Issues)
	}
}

func TestRunMergesAssessmentIssuesInCandidateOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.ts", "b.ts", "c.ts"} {
		writeRetrieveFile(t, root, name, "export function handler() { return 1; }\n")
	}
	failures := map[string]*provider.Failure{
		"a.ts": &provider.Failure{Kind: enums.FailureAuthentication, Message: "authentication failed"},
		"b.ts": &provider.Failure{Kind: enums.FailureRequestLimit, Message: "request limit"},
		"c.ts": &provider.Failure{Kind: enums.FailureProvider, Message: "provider down"},
	}
	for attempt := 0; attempt < 5; attempt++ {
		reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
			switch state := request.State.(type) {
			case requests.NavigationRequestState:
				out := map[string]float64{}
				for index := range state.Items {
					out["q"+itoa(index)] = 0.55
				}
				return out, nil
			case requests.EvidenceState:
				out := map[string]float64{}
				for index := range state.Declarations {
					out["q"+itoa(index)] = 0.9
					out["scope"+itoa(index)] = 0.9
				}
				return out, nil
			case requests.AssessmentState:
				if state.Path == "a.ts" {
					time.Sleep(20 * time.Millisecond)
				} else if state.Path == "b.ts" {
					time.Sleep(10 * time.Millisecond)
				}
				return nil, failures[state.Path]
			}
			return map[string]float64{}, nil
		}}
		result, err := Run(context.Background(), Input{Query: "handler"}, evaluator, reader)
		if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		reader.Close()
		kinds := make([]string, 0, len(result.Issues))
		for _, issue := range result.Issues {
			kinds = append(kinds, issue.Kind.String())
		}
		if got, want := strings.Join(kinds, ","), "authentication,request-limit,provider"; got != want {
			t.Fatalf("attempt %d issue order = %q, want %q", attempt, got, want)
		}
	}
}

func TestRunDropsEvidenceAboveCap(t *testing.T) {
	root := t.TempDir()
	writeRetrieveFile(t, root, "big.ts", strings.Repeat("export function handler() { return 1; }\n", 3000))
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var mu sync.Mutex
	evidenceRequests := 0
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		switch state := request.State.(type) {
		case requests.NavigationRequestState:
			out := map[string]float64{}
			for index := range state.Items {
				out["q"+itoa(index)] = 0.9
			}
			return out, nil
		case requests.EvidenceState:
			if state.SelectedEvidence != nil {
				mu.Lock()
				evidenceRequests++
				mu.Unlock()
			}
			out := map[string]float64{}
			for index := range state.Declarations {
				out["q"+itoa(index)] = 0.9
				out["scope"+itoa(index)] = 0.9
				if state.SelectedEvidence != nil {
					out["ref"+itoa(index)] = 0.9
				}
			}
			return out, nil
		case requests.AssessmentState:
			return map[string]float64{"implementation": 0.9, "priority": 0.9}, nil
		}
		return map[string]float64{}, nil
	}}
	result, err := Run(context.Background(), Input{Query: "handler"}, evaluator, reader)
	if err != nil {
		t.Fatal(err)
	}
	if evidenceRequests != 0 {
		t.Fatalf("evidence request count = %d, want 0 after cap overflow", evidenceRequests)
	}
	if len(result.Files) != 1 || len(result.Files[0].Excerpts) == 0 {
		t.Fatalf("files = %+v", result.Files)
	}
}

func TestRunProgressPanicDoesNotChangeSearch(t *testing.T) {
	root := t.TempDir()
	writeRetrieveFile(t, root, "a.ts", "export function record(name: string) { return name; }\n")
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	result, err := Run(context.Background(), Input{
		Query:    "record",
		Progress: func(ProgressSnapshot) { panic("progress exploded") },
	}, pipelineEvaluator(nil), reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != enums.RetrievalStatusComplete || len(result.Files) != 1 {
		t.Fatalf("status = %q files = %+v", result.Status, result.Files)
	}
}

func TestEvidenceDonorChangeIsNotSentAndRecorded(t *testing.T) {
	root := t.TempDir()
	donor := filepath.Join(root, "a.ts")
	writeRetrieveFile(t, root, "a.ts", "export function alpha() { return 1; }\n")
	writeRetrieveFile(t, root, "b.ts", "export function beta() { return 2; }\n")
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var mu sync.Mutex
	rewritten := false
	secondPass := 0
	donorSent := false
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		switch state := request.State.(type) {
		case requests.NavigationRequestState:
			out := map[string]float64{}
			for index := range state.Items {
				out["q"+itoa(index)] = 0.9
			}
			return out, nil
		case requests.AssessmentState:
			if state.Path == "a.ts" {
				mu.Lock()
				first := !rewritten
				rewritten = true
				mu.Unlock()
				if first {
					if err := os.WriteFile(donor, []byte("export function alphaChanged() { return 3; }\n"), 0o644); err != nil {
						return nil, err
					}
				}
			}
			return map[string]float64{"implementation": 0.9, "priority": 0.9}, nil
		case requests.EvidenceState:
			out := map[string]float64{}
			for index := range state.Declarations {
				out["q"+itoa(index)] = 0.9
				out["scope"+itoa(index)] = 0.9
				if state.SelectedEvidence != nil {
					out["ref"+itoa(index)] = 0.9
				}
			}
			if state.SelectedEvidence != nil {
				mu.Lock()
				secondPass++
				for _, item := range *state.SelectedEvidence {
					if item.Path == "a.ts" {
						donorSent = true
					}
				}
				mu.Unlock()
			}
			return out, nil
		}
		return map[string]float64{}, nil
	}}
	result, err := Run(context.Background(), Input{Query: "handler"}, evaluator, reader)
	if err != nil {
		t.Fatal(err)
	}
	if secondPass == 0 {
		t.Fatal("expected an evidence pass")
	}
	if donorSent {
		t.Fatal("changed donor was sent in the evidence pass")
	}
	found := 0
	for _, issue := range result.Issues {
		if issue.Kind == enums.IssueCodeChanged {
			found = issue.Count
		}
	}
	if found < 2 {
		t.Fatalf("changed count = %d (issues = %+v), want the evidence pass plus finalization", found, result.Issues)
	}
}

type prefetchingEvaluator struct {
	*scriptedEvaluator
	mu         sync.Mutex
	prefetched map[string]bool
	evaluated  map[string]bool
}

func requestKey(request provider.Request) string {
	blob, _ := json.Marshal(request)
	return string(blob)
}

func (e *prefetchingEvaluator) Prefetch(_ context.Context, request provider.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prefetched[requestKey(request)] = true
}

func (e *prefetchingEvaluator) Evaluate(ctx context.Context, request provider.Request, options provider.EvalOptions) (map[string]float64, error) {
	e.mu.Lock()
	e.evaluated[requestKey(request)] = true
	e.mu.Unlock()
	return e.scriptedEvaluator.Evaluate(ctx, request, options)
}

func TestCandidatePrefetchWarmsExactlyTheFinalRequests(t *testing.T) {
	root := t.TempDir()
	writeRetrieveFile(t, root, "src/events.ts", "export function record(name: string) { return name; }\n")
	writeRetrieveFile(t, root, "src/other.ts", "export const other = 1;\n")
	writeRetrieveFile(t, root, "README.md", "docs\n")
	run := func(evaluator Evaluator) RetrievalResult {
		reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		result, err := Run(context.Background(), Input{Query: "event recording"}, evaluator, reader)
		if err != nil {
			t.Fatal(err)
		}
		result.Counts = Counts{}
		return result
	}
	plain := run(pipelineEvaluator(nil))
	warmed := &prefetchingEvaluator{scriptedEvaluator: pipelineEvaluator(nil), prefetched: map[string]bool{}, evaluated: map[string]bool{}}
	got := run(warmed)
	if !reflect.DeepEqual(plain, got) {
		t.Fatalf("prefetch changed the result:\n%+v\n%+v", plain, got)
	}
	if len(warmed.prefetched) == 0 {
		t.Fatal("no requests were prefetched")
	}
	for key := range warmed.prefetched {
		if !warmed.evaluated[key] {
			t.Fatalf("prefetched request never sent for real: %s", key)
		}
	}
}

func TestNoRequestExceedsTheQuestionLimit(t *testing.T) {
	root := t.TempDir()
	for index := range 250 {
		writeRetrieveFile(t, root, "f"+itoa(index)+".ts", "export const value"+itoa(index)+" = 1;\n")
	}
	writeRetrieveFile(t, root, "big.ts", strings.Repeat("export function handler() { return 1; }\n", 6000))
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var mu sync.Mutex
	most := 0
	inner := pipelineEvaluator(nil)
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		mu.Lock()
		most = max(most, len(request.Questions))
		mu.Unlock()
		return inner.answers(request)
	}}
	if _, err := Run(context.Background(), Input{Query: "handler"}, evaluator, reader); err != nil {
		t.Fatal(err)
	}
	if most == 0 || most > MaxQuestionsPerRequest {
		t.Fatalf("largest request had %d questions, limit %d", most, MaxQuestionsPerRequest)
	}
}

func TestOutlinePipelineFoldsRolesAndSendsOnlyChosenBodies(t *testing.T) {
	root := t.TempDir()
	writeRetrieveFile(t, root, "small.go", "package a\n\nfunc Handler() int { return ParseConfigFile() }\n")
	large := "package a\n\nfunc ParseConfigFile() int {\n\treturn 1\n}\n\n"
	for index := range 40 {
		large += "func Unrelated" + itoa(index) + "() {\n" + strings.Repeat("\t_ = \"filler line\"\n", 30) + "}\n\n"
	}
	writeRetrieveFile(t, root, "large.go", large)
	reader, err := files.New(root, files.DefaultPolicy(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var mu sync.Mutex
	assessments, outlines := 0, 0
	sentLarge := []string{}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		out := map[string]float64{}
		for _, question := range request.Questions {
			out[question.ID] = 0.1
		}
		switch state := request.State.(type) {
		case requests.NavigationRequestState:
			for index := range state.Items {
				out["q"+itoa(index)] = 0.9
			}
		case requests.AssessmentState:
			mu.Lock()
			assessments++
			mu.Unlock()
		case requests.OutlineState:
			mu.Lock()
			outlines++
			mu.Unlock()
			for index, declaration := range state.Declarations {
				if strings.Contains(declaration.Name, "Unrelated1") {
					out["d"+itoa(index)] = 0.9
				}
			}
			out["implementation"], out["priority"] = 0.9, 0.8
		case requests.EvidenceState:
			if state.Path == "large.go" {
				mu.Lock()
				sentLarge = append(sentLarge, state.Source)
				mu.Unlock()
			}
			for index, declaration := range state.Declarations {
				value := 0.2
				if strings.Contains(declaration.Name, "Handler") || strings.Contains(declaration.Name, "Unrelated1()") {
					value = 0.9
				}
				out["q"+itoa(index)], out["scope"+itoa(index)] = value, value
			}
			out["implementation"], out["priority"] = 0.9, 0.7
		}
		return out, nil
	}}
	result, err := Run(context.Background(), Input{Query: "handler", Pipeline: PipelineOutline}, evaluator, reader)
	if err != nil {
		t.Fatal(err)
	}
	if outlines == 0 {
		t.Skip("outlines unavailable in this build")
	}
	if assessments != 0 {
		t.Fatalf("assessment requests = %d, want 0 (roles ride on selection)", assessments)
	}
	byPath := map[string]FileEvidence{}
	for _, file := range result.Files {
		byPath[file.Path] = file
	}
	if file := byPath["small.go"]; len(file.Roles) == 0 || file.Priority == nil {
		t.Fatalf("small.go roles = %+v", file)
	}
	for _, source := range sentLarge {
		if strings.Contains(source, "func Unrelated20()") {
			t.Fatalf("an unchosen body was sent: %.200s", source)
		}
	}
	shown := ""
	for _, excerpt := range byPath["large.go"].Excerpts {
		shown += excerpt.Source
	}
	if !strings.Contains(shown, "func Unrelated1()") || !strings.Contains(shown, "func ParseConfigFile()") {
		t.Fatalf("large.go excerpts miss the chosen body or the locally resolved reference:\n%s", shown)
	}
}

func writeRetrieveFile(t *testing.T, root, relative, source string) {
	t.Helper()
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
}
