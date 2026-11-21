package retrieve

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"foco/internal/files"
	"foco/internal/outline"
	"foco/internal/provider"
	"foco/internal/requests"
)

// The outline pipeline handles files tree-sitter can outline:
//
//   - Small files (whole source fits one context) get one selection request
//     over declaration windows that also asks the file's role questions, so
//     no separate assessment request is sent.
//   - Large files first get one outline request asking, from signatures only,
//     which declarations could matter (plus the role questions). Only those
//     declarations' bodies are then sent for the usual relevance and scope
//     questions.
//   - The evidence pass's reference question is answered locally: a
//     declaration whose name appears in another file's selected evidence is
//     selected without asking the provider.
//
// Files without an outline keep the classic pipeline.
const (
	PipelineClassic = "classic"
	PipelineOutline = "outline"
	// OutlineCutoff is the outline score above which a declaration's body is
	// reviewed. It is lower than RelevanceBoundary because signatures carry
	// less information than source: the body review makes the final call.
	OutlineCutoff = 0.35
	// OutlineMaxBodies caps the declaration bodies reviewed per large file.
	OutlineMaxBodies = 24
	// ReferenceScore is the decision score of a locally resolved reference;
	// above SourceConfidenceBoundary so referenced code is shown.
	ReferenceScore = 0.75
	// MaxReferencesPerFile caps locally resolved references per file.
	MaxReferencesPerFile = 3
)

// outlinable reports whether a file takes the outline pipeline.
func outlinable(snapshot files.Snapshot) bool {
	return len(snapshot.Source) <= SourceInspectionLimit &&
		len(outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source)) > 0
}

// prefetchThenEvaluate warms a request and then reads its answer, for
// requests whose answers decide what to prefetch next.
type prefetchThenEvaluate struct {
	warm  prefetcher
	inner Evaluator
}

func (p prefetchThenEvaluate) Requests() int { return 0 }

func (p prefetchThenEvaluate) Evaluate(ctx context.Context, request provider.Request, options provider.EvalOptions) (map[string]float64, error) {
	p.warm.Prefetch(ctx, request)
	return p.inner.Evaluate(ctx, request, options)
}

func assessmentFrom(answers map[string]float64) *assessment {
	if answers == nil {
		return nil
	}
	result := assessment{Priority: answers["priority"]}
	for _, role := range assessmentRoles {
		if answers[role.String()] > 0.5 {
			result.Labels = append(result.Labels, role)
		}
	}
	return &result
}

// outlineFile runs the outline pipeline for one file. ok is false when the
// file has no outline and must use the classic pipeline. first answers the
// file's first request (selection or outline, with the role questions);
// second answers the body requests that depend on it.
func outlineFile(
	ctx context.Context, snapshot files.Snapshot, query string, score float64,
	first, second Evaluator, validate func(context.Context) error,
) (result selectionResult, roles *assessment, ok bool, err error) {
	if !outlinable(snapshot) {
		return selectionResult{}, nil, false, nil
	}
	index := newTextIndex(snapshot.Source)
	windows := declarationWindows(index, outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source))
	if len(index.bytes) <= WholeFileContextBytes {
		var answers map[string]float64
		result, err = selectFileWith(ctx, snapshot, query, score, first, nil, validate, &selectOptions{
			windows: windows, extra: requests.RoleQuestions(), extraAnswers: &answers,
		})
		return result, assessmentFrom(answers), true, err
	}
	chosen, answers, err := chooseDeclarations(ctx, index, snapshot.Path, query, windows, first)
	if err != nil {
		return selectionResult{}, nil, true, err
	}
	result, err = selectFileWith(ctx, snapshot, query, score, second, nil, validate, &selectOptions{
		windows: chosen, sparse: true,
	})
	return result, assessmentFrom(answers), true, err
}

// chooseDeclarations asks the outline questions and returns the windows whose
// bodies are worth reviewing, in file order, plus the role answers.
func chooseDeclarations(
	ctx context.Context, index *textIndex, path, query string, windows []window, evaluator Evaluator,
) ([]window, map[string]float64, error) {
	roles := requests.RoleQuestions()
	opening := strings.Join(index.lines[:min(20, len(index.lines))], "\n")
	type chunk struct {
		start, end int
		request    provider.Request
	}
	chunks := []chunk{}
	for start := 0; start < len(windows); {
		capacity := MaxQuestionsPerRequest
		if start == 0 {
			capacity -= len(roles)
		}
		end := min(len(windows), start+capacity)
		var extra []provider.Question
		if start == 0 {
			extra = roles
		}
		chunks = append(chunks, chunk{
			start: start, end: end,
			request: requests.OutlineRequest(query, path, opening, declarationsFor(windows[start:end]), extra),
		})
		start = end
	}
	answered := make([]map[string]float64, len(chunks))
	failed := make([]error, len(chunks))
	var wait sync.WaitGroup
	for position := range chunks {
		wait.Add(1)
		go func() {
			defer wait.Done()
			answered[position], failed[position] = evaluator.Evaluate(ctx, chunks[position].request, provider.EvalOptions{})
		}()
	}
	wait.Wait()
	type scored struct {
		position int
		value    float64
	}
	candidates := []scored{}
	for position, current := range chunks {
		if failed[position] != nil {
			return nil, nil, failed[position]
		}
		for offset := 0; offset < current.end-current.start; offset++ {
			value, ok := answered[position][outlineQuestion(offset)]
			if ok && !math.IsNaN(value) && value > OutlineCutoff {
				candidates = append(candidates, scored{current.start + offset, value})
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].value > candidates[j].value })
	if len(candidates) > OutlineMaxBodies {
		candidates = candidates[:OutlineMaxBodies]
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].position < candidates[j].position })
	chosen := make([]window, 0, len(candidates))
	for _, candidate := range candidates {
		chosen = append(chosen, windows[candidate.position])
	}
	return chosen, answered[0], nil
}

func outlineQuestion(offset int) string { return "d" + itoa(offset) }

var identifierPattern = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// commonNames are declaration names too generic to count as a reference.
var commonNames = map[string]bool{
	"New": true, "new": true, "String": true, "Error": true, "Close": true, "Open": true, "Get": true,
	"Set": true, "Init": true, "init": true, "main": true, "Main": true, "Run": true, "run": true,
	"Len": true, "Less": true, "Swap": true, "Name": true, "name": true, "Type": true, "type": true,
	"Value": true, "value": true, "Read": true, "Write": true, "Start": true, "Stop": true, "test": true,
	"setup": true, "setUp": true, "tearDown": true, "toString": true, "equals": true, "hashCode": true,
	"constructor": true, "render": true, "call": true, "self": true, "this": true, "default": true,
	"index": true, "update": true, "create": true, "delete": true, "handle": true, "process": true,
}

// declarationName returns the last component of a declared name, the part
// other code writes when it uses it.
func declarationName(name string) string {
	for _, separator := range []string{"::", ".", "#"} {
		if position := strings.LastIndex(name, separator); position >= 0 {
			name = name[position+len(separator):]
		}
	}
	return name
}

// referencedWindows returns windows of declarations named in evidence from
// other files or other declarations of this file, and not yet selected.
func referencedWindows(
	snapshot files.Snapshot, file FileEvidence, evidence map[string][]Excerpt,
) []window {
	declarations := outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source)
	if len(declarations) == 0 {
		return nil
	}
	used := map[string]bool{}
	for path, excerpts := range evidence {
		for _, excerpt := range excerpts {
			for _, identifier := range identifierPattern.FindAllString(excerpt.Source, -1) {
				if path != snapshot.Path {
					used[identifier] = true
				} else {
					used["\x00"+identifier] = true
				}
			}
		}
	}
	selected := func(startLine, endLine int) bool {
		for _, decision := range file.SourceDecisions {
			if decision.Score > RelevanceBoundary && decision.Range.StartLine <= startLine && endLine <= decision.Range.EndLine {
				return true
			}
		}
		return false
	}
	index := newTextIndex(snapshot.Source)
	out := []window{}
	for _, candidate := range declarationWindows(index, declarations) {
		if len(out) >= MaxReferencesPerFile || selected(candidate.Range.StartLine, candidate.Range.EndLine) {
			continue
		}
		for _, declaration := range declarations {
			if declaration.Container || declaration.StartLine < candidate.Range.StartLine || declaration.EndLine > candidate.Range.EndLine {
				continue
			}
			name := declarationName(declaration.Name)
			if len(name) < 4 || commonNames[name] {
				continue
			}
			if used[name] || (used["\x00"+name] && !selected(declaration.StartLine, declaration.EndLine)) {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

// localEvaluator answers selection requests from known window scores without
// a provider: already decided windows keep their scores and locally resolved
// references get ReferenceScore.
type localEvaluator struct{ scores map[[2]int]float64 }

func (l localEvaluator) Requests() int { return 0 }

func (l localEvaluator) Evaluate(_ context.Context, request provider.Request, _ provider.EvalOptions) (map[string]float64, error) {
	state, _ := request.State.(requests.EvidenceState)
	out := map[string]float64{}
	for position, declaration := range state.Declarations {
		value := l.scores[[2]int{declaration.StartLine, declaration.EndLine}]
		out["q"+itoa(position)], out["scope"+itoa(position)] = value, value
	}
	return out, nil
}

// withReferences re-renders an outlined file's evidence with its locally
// resolved references added. It sends no requests.
func withReferences(ctx context.Context, snapshot files.Snapshot, file FileEvidence, references []window) (FileEvidence, bool) {
	if len(references) == 0 {
		return file, false
	}
	declarations := outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source)
	index := newTextIndex(snapshot.Source)
	scores := map[[2]int]float64{}
	keep := []window{}
	for _, candidate := range declarationWindows(index, declarations) {
		for _, decision := range file.SourceDecisions {
			if decision.Range.StartLine == candidate.Range.StartLine && decision.Range.EndLine == candidate.Range.EndLine {
				scores[[2]int{candidate.Range.StartLine, candidate.Range.EndLine}] = decision.Score
				keep = append(keep, candidate)
				break
			}
		}
	}
	for _, reference := range references {
		key := [2]int{reference.Range.StartLine, reference.Range.EndLine}
		if _, ok := scores[key]; !ok {
			scores[key] = ReferenceScore
			keep = append(keep, reference)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Range.StartLine < keep[j].Range.StartLine })
	result, err := selectFileWith(ctx, snapshot, "", file.Score, localEvaluator{scores: scores}, nil, nil, &selectOptions{windows: keep, sparse: true})
	if err != nil || result.File.SourceOmitted {
		return file, false
	}
	updated := result.File
	updated.Roles, updated.Priority = file.Roles, file.Priority
	return updated, true
}
