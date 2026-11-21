package retrieve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/outline"
	"foco/internal/provider"
	"foco/internal/requests"
)

func selectionEvaluator(target string) *scriptedEvaluator {
	return &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		out := map[string]float64{}
		for index, declaration := range state.Declarations {
			value := 0.1
			if target == "" || declaration.Name == target {
				value = 0.9
			}
			out["q"+itoa(index)] = value
			out["scope"+itoa(index)] = 0.9
			if state.SelectedEvidence != nil {
				out["ref"+itoa(index)] = 0
			}
		}
		return out, nil
	}}
}

func TestSelectFileSelectsWindowAndExpandsThreeLines(t *testing.T) {
	lines := make([]string, 100)
	for index := range lines {
		lines[index] = "line " + itoa(index+1)
	}
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: strings.Join(lines, "\n")}
	result, err := selectFile(context.Background(), snapshot, "q", 0.9, selectionEvaluator("lines 1-40"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.File.Selected) != 1 || result.File.Selected[0].StartLine != 1 || result.File.Selected[0].EndLine != 40 {
		t.Fatalf("selected = %+v", result.File.Selected)
	}
	if len(result.File.Excerpts) != 1 {
		t.Fatalf("excerpts = %+v", result.File.Excerpts)
	}
	excerpt := result.File.Excerpts[0]
	if excerpt.Range.StartLine != 1 || excerpt.Range.EndLine != 43 {
		t.Fatalf("excerpt range = %+v", excerpt.Range)
	}
	if !strings.Contains(excerpt.Source, "line 43") || strings.Contains(excerpt.Source, "line 44") {
		t.Fatalf("excerpt source bounds wrong")
	}
}

func TestSelectFileUsesByteSpansForGiantLine(t *testing.T) {
	source := strings.Repeat("é", 18000) + "TARGET" + strings.Repeat("z", 75000) + "\n"
	snapshot := files.Snapshot{Path: "large.txt", ContentHash: "h", Source: source}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		out := map[string]float64{}
		for index := range state.Declarations {
			value := 0.0
			if strings.Contains(state.Source, "TARGET") {
				value = 0.9
			}
			out["q"+itoa(index)] = value
			out["scope"+itoa(index)] = 1
		}
		return out, nil
	}}
	result, err := selectFile(context.Background(), snapshot, "TARGET", 0.9, evaluator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.File.Selected) != 1 {
		t.Fatalf("selected = %+v", result.File.Selected)
	}
	selected := result.File.Selected[0]
	if selected.SourceByteStart == nil || *selected.SourceByteStart != 24000 || *selected.SourceByteEnd != 48000 {
		t.Fatalf("selected = %+v", selected)
	}
	if len(result.File.Excerpts) == 0 || !result.File.Excerpts[0].Partial {
		t.Fatalf("excerpts = %+v", result.File.Excerpts)
	}
}

func TestSelectFileReferenceCanRecoverScopeRejection(t *testing.T) {
	snapshot := files.Snapshot{Path: "helper.ts", ContentHash: "h", Source: "export function helper() { return 1; }\n"}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		out := map[string]float64{"q0": 0.95, "scope0": 0.1}
		if state.SelectedEvidence != nil {
			out["ref0"] = 0.9
		}
		return out, nil
	}}
	first, err := selectFile(context.Background(), snapshot, "target", 0.9, evaluator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.File.Selected) != 0 {
		t.Fatalf("selected without reference = %+v", first.File.Selected)
	}
	evidence := []requests.Evidence{{Path: "target.ts", StartLine: 1, EndLine: 1, Source: "helper()"}}
	second, err := selectFile(context.Background(), snapshot, "target", 0.9, evaluator, func(context.Context) ([]requests.Evidence, bool, error) {
		return evidence, true, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.File.Selected) != 1 || second.File.Selected[0].StartLine != 1 {
		t.Fatalf("selected with reference = %+v", second.File.Selected)
	}
}

func numberedLines(count int) []string {
	lines := make([]string, count)
	for index := range lines {
		lines[index] = "line " + itoa(index+1)
	}
	return lines
}

func windowCovers(entry window, line int) bool {
	return entry.Range.StartLine <= line && line <= entry.Range.EndLine
}

func selectionIssueCount(issues []Issue, kind enums.RetrievalIssueCode) int {
	for _, issue := range issues {
		if issue.Kind == kind {
			return issue.Count
		}
	}
	return 0
}

func TestBuildWindowsCoversLinesAcrossMidFileGiantLine(t *testing.T) {
	lines := numberedLines(60)
	lines[19] = strings.Repeat("x", 30_000)
	index := newTextIndex(strings.Join(lines, "\n"))
	windows := buildWindows(index, nil)
	for line := 1; line <= len(index.lines); line++ {
		covered := false
		for _, entry := range windows {
			if windowCovers(entry, line) {
				covered = true
				break
			}
		}
		if !covered {
			t.Fatalf("line %d is not covered by windows %+v", line, windows)
		}
	}
	position := index.offsets[19]
	for _, entry := range windows {
		if !entry.Partial || entry.Range.StartLine != 20 || entry.Range.EndLine != 20 {
			continue
		}
		if entry.StartByte != position {
			t.Fatalf("giant line byte windows not contiguous: expected start %d, got %+v", position, entry)
		}
		if entry.EndByte-entry.StartByte > WindowMaxBytes {
			t.Fatalf("giant line window exceeds byte cap: %+v", entry)
		}
		position = entry.EndByte
	}
	if position != index.offsets[20] {
		t.Fatalf("giant line bytes covered up to %d, want %d", position, index.offsets[20])
	}
	if windows[len(windows)-1].Range.EndLine != len(index.lines) {
		t.Fatalf("last window does not reach final line: %+v", windows)
	}
}

func TestBuildWindowsUsesFixedOverlap(t *testing.T) {
	index := newTextIndex(strings.Join(numberedLines(100), "\n"))
	windows := buildWindows(index, nil)
	want := []Range{{StartLine: 1, EndLine: 40}, {StartLine: 31, EndLine: 70}, {StartLine: 61, EndLine: 100}}
	if len(windows) != len(want) {
		t.Fatalf("windows = %+v", windows)
	}
	for position, entry := range windows {
		if entry.Range != want[position] || entry.Partial {
			t.Fatalf("window %d = %+v, want %+v", position, entry.Range, want[position])
		}
	}
}

func TestBuildWindowsAdvancesPastRepeatedCapShrunkWindows(t *testing.T) {
	lines := make([]string, 8)
	for position := range lines {
		lines[position] = strings.Repeat("y", 13_000)
	}
	index := newTextIndex(strings.Join(lines, "\n"))
	windows := buildWindows(index, nil)
	if len(windows) != len(lines) {
		t.Fatalf("windows = %d, want %d: %+v", len(windows), len(lines), windows)
	}
	for position, entry := range windows {
		line := position + 1
		if entry.Range.StartLine != line || entry.Range.EndLine != line || entry.Partial {
			t.Fatalf("window %d = %+v, want single line %d", position, entry, line)
		}
	}
}

func TestSelectFileCoversWindowsAfterMidFileGiantLine(t *testing.T) {
	lines := numberedLines(60)
	lines[19] = strings.Repeat("x", 30_000)
	snapshot := files.Snapshot{Path: "giant.txt", ContentHash: "h", Source: strings.Join(lines, "\n")}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		out := map[string]float64{}
		for index := range state.Declarations {
			out["q"+itoa(index)] = 0
			out["scope"+itoa(index)] = 0
		}
		return out, nil
	}}
	result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.File.SourceDecisions) == 0 {
		t.Fatal("no source decisions")
	}
	last := result.File.SourceDecisions[len(result.File.SourceDecisions)-1]
	if last.Range.EndLine != len(lines) {
		t.Fatalf("last decision ends at line %d, want %d", last.Range.EndLine, len(lines))
	}
}

func TestSelectFileSourceDecisionsKeepInsertionOrder(t *testing.T) {
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: strings.Join(numberedLines(100), "\n")}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		out := map[string]float64{}
		for index := range state.Declarations {
			out["q"+itoa(index)] = 0.9
			out["scope"+itoa(index)] = 0.9
		}
		return out, nil
	}}
	want := []Range{{StartLine: 1, EndLine: 40}, {StartLine: 31, EndLine: 70}, {StartLine: 61, EndLine: 100}}
	for attempt := 0; attempt < 25; attempt++ {
		result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.File.SourceDecisions) != len(want) {
			t.Fatalf("source decisions = %+v", result.File.SourceDecisions)
		}
		for position, decision := range result.File.SourceDecisions {
			if decision.Range.StartLine != want[position].StartLine || decision.Range.EndLine != want[position].EndLine {
				t.Fatalf("attempt %d decision %d = %+v, want %+v", attempt, position, decision.Range, want[position])
			}
		}
	}
}

func TestSelectFileMalformedAnswerDiscardsWholeGroup(t *testing.T) {
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: strings.Join(numberedLines(100), "\n")}
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		return map[string]float64{"q0": 0.9, "scope0": 0.9, "q1": 0.9}, nil
	}}
	result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.File.Selected) != 0 {
		t.Fatalf("group with malformed answer selected positions: %+v", result.File.Selected)
	}
	if len(result.File.SourceDecisions) != 0 {
		t.Fatalf("group with malformed answer decided positions: %+v", result.File.SourceDecisions)
	}
	if count := selectionIssueCount(result.Issues, enums.IssueCodeProvider); count != 1 {
		t.Fatalf("provider issues = %d, want 1: %+v", count, result.Issues)
	}
}

func TestSelectFileMapsPreparationErrors(t *testing.T) {
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: "line 1\nline 2\n"}
	cases := []struct {
		name string
		err  error
		want enums.RetrievalIssueCode
	}{
		{"cancelled", context.Canceled, enums.IssueCodeInterrupted},
		{"deadline", context.DeadlineExceeded, enums.IssueCodeInterrupted},
		{"stale", errors.New("stale"), enums.IssueCodeChanged},
	}
	for _, test := range cases {
		t.Run("prepare/"+test.name, func(t *testing.T) {
			evaluator := &scriptedEvaluator{answers: func(provider.Request) (map[string]float64, error) {
				t.Fatal("evaluator called after prepare error")
				return nil, nil
			}}
			result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator,
				func(context.Context) ([]requests.Evidence, bool, error) { return nil, false, test.err }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.File.SourceOmitted {
				t.Fatal("file not omitted")
			}
			if count := selectionIssueCount(result.Issues, test.want); count != 1 {
				t.Fatalf("%s issues = %d, want 1: %+v", test.want, count, result.Issues)
			}
		})
		t.Run("validate/"+test.name, func(t *testing.T) {
			evaluator := &scriptedEvaluator{answers: func(provider.Request) (map[string]float64, error) {
				t.Fatal("evaluator called after validate error")
				return nil, nil
			}}
			result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator, nil,
				func(context.Context) error { return test.err })
			if err != nil {
				t.Fatal(err)
			}
			if !result.File.SourceOmitted {
				t.Fatal("file not omitted")
			}
			if count := selectionIssueCount(result.Issues, test.want); count != 1 {
				t.Fatalf("%s issues = %d, want 1: %+v", test.want, count, result.Issues)
			}
		})
	}
}

func TestSelectFileRecordsInterruptedAfterCancelledLoop(t *testing.T) {
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: "line 1\nline 2\n"}
	evaluator := &scriptedEvaluator{answers: func(provider.Request) (map[string]float64, error) {
		t.Fatal("evaluator called with cancelled context")
		return nil, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := selectFile(ctx, snapshot, "q", 0.9, evaluator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count := selectionIssueCount(result.Issues, enums.IssueCodeInterrupted); count != 1 {
		t.Fatalf("interrupted issues = %d, want 1: %+v", count, result.Issues)
	}
}

func TestStateSizeMatchesUnescapedJSON(t *testing.T) {
	state := requests.EvidenceState{
		Query: "q", Path: "p", Source: "if a < b && c > d { & }",
		Declarations: []requests.Declaration{{Name: "f<g>&h", StartLine: 1, EndLine: 2}},
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		t.Fatal(err)
	}
	want := buffer.Len() - 1
	if got := stateSize(state); got != want {
		t.Fatalf("stateSize = %d, want unescaped length %d", got, want)
	}
	escaped, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(escaped) <= want {
		t.Fatalf("expected HTML escaping to inflate json.Marshal: %d <= %d", len(escaped), want)
	}
}

func TestSelectFileOmitsPresentEmptyEvidence(t *testing.T) {
	snapshot := files.Snapshot{Path: "a.ts", ContentHash: "h", Source: "export function helper() { return 1; }\n"}
	seenEvidence := false
	seenReferences := false
	evaluator := &scriptedEvaluator{answers: func(request provider.Request) (map[string]float64, error) {
		state := request.State.(requests.EvidenceState)
		if state.SelectedEvidence != nil {
			seenEvidence = true
		}
		out := map[string]float64{}
		for index := range state.Declarations {
			out["q"+itoa(index)] = 0.9
			out["scope"+itoa(index)] = 0.9
			if _, ok := requestAnswer(request, "ref"+itoa(index)); ok {
				seenReferences = true
			}
		}
		return out, nil
	}}
	result, err := selectFile(context.Background(), snapshot, "q", 0.9, evaluator,
		func(context.Context) ([]requests.Evidence, bool, error) { return []requests.Evidence{}, true, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seenEvidence {
		t.Fatal("present but empty evidence must be omitted")
	}
	if seenReferences {
		t.Fatal("ref questions must be omitted when evidence is empty")
	}
	if len(result.File.Selected) != 1 {
		t.Fatalf("selected = %+v", result.File.Selected)
	}
}

func requestAnswer(request provider.Request, id string) (string, bool) {
	for _, question := range request.Questions {
		if question.ID == id {
			return question.Instructions, true
		}
	}
	return "", false
}

func TestDeclarationWindowsFollowDeclarations(t *testing.T) {
	source := "package a\n\nimport \"fmt\"\n\nfunc Small() {}\n\nfunc Tiny() {}\n\n" +
		"func Large() {\n" + strings.Repeat("\tfmt.Println(1)\n", 120) + "}\n\nvar tail = 1\n"
	index := newTextIndex(source)
	declarations := outline.Of("a.go", "TestDeclarationWindows", source)
	if len(declarations) != 3 {
		t.Skipf("outlines unavailable in this build: %+v", declarations)
	}
	windows := buildWindows(index, declarations)
	names := []string{}
	covered := map[int]bool{}
	for _, entry := range windows {
		names = append(names, fmt.Sprintf("%s %d-%d", entry.Name, entry.Range.StartLine, entry.Range.EndLine))
		for line := entry.Range.StartLine; line <= entry.Range.EndLine; line++ {
			covered[line] = true
		}
	}
	if windows[0].Name != "lines 1-4" || windows[1].Name != "func Small(); func Tiny()" || !strings.HasPrefix(windows[2].Name, "func Large() (part)") {
		t.Fatalf("windows = %v", names)
	}
	for line := 1; line <= len(index.lines); line++ {
		if !covered[line] && strings.TrimSpace(index.lines[line-1]) != "" {
			t.Fatalf("line %d is in no window: %v", line, names)
		}
	}
}
