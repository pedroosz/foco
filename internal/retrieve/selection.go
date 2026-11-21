package retrieve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/outline"
	"foco/internal/provider"
	"foco/internal/requests"
)

type window struct {
	Name      string
	Range     Range
	StartByte int
	EndByte   int
	Partial   bool
}

type span struct {
	start int
	end   int
}

type selectionResult struct {
	File            FileEvidence
	Groups          int
	Issues          []Issue
	ProviderFailure string
}

func backUpRune(data []byte, start, finish int) int {
	for finish > start && finish < len(data) && (data[finish]&0xc0) == 0x80 {
		finish--
	}
	return finish
}

// windowsIn cuts lines first..last into overlapping WindowLines-line windows,
// byte-capped at WindowMaxBytes. label names the windows; empty means
// "lines a-b".
func windowsIn(index *textIndex, first, last int, label string) []window {
	lineCount := last
	var out []window
	name := func(start, end int) string {
		if label != "" {
			return label
		}
		return fmt.Sprintf("lines %d-%d", start, end)
	}
	for start := first; start <= lineCount; {
		end := min(lineCount, start+WindowLines-1)
		for end > start && index.offsets[end]-index.offsets[start-1] > WindowMaxBytes {
			end--
		}
		startByte, endByte := index.offsets[start-1], index.offsets[end]
		if endByte-startByte > WindowMaxBytes {
			position := startByte
			for position < endByte {
				finish := min(endByte, position+WindowMaxBytes)
				finish = backUpRune(index.bytes, position, finish)
				if finish <= position {
					finish = min(endByte, position+WindowMaxBytes)
				}
				out = append(out, window{
					Name: name(start, end), Range: Range{StartLine: start, EndLine: end},
					StartByte: position, EndByte: finish, Partial: true,
				})
				position = finish
			}
		} else {
			out = append(out, window{
				Name: name(start, end), Range: Range{StartLine: start, EndLine: end},
				StartByte: startByte, EndByte: endByte,
			})
		}
		if end == lineCount {
			break
		}
		// A byte-capped window ends before the usual span; resume at the next line so no
		// line is skipped. Otherwise advance by the regular overlap.
		if end < start+WindowLines-1 {
			start = end + 1
		} else {
			start = end - WindowOverlap + 1
		}
	}
	return out
}

func buildWindows(index *textIndex, declarations []outline.Declaration) []window {
	if len(declarations) == 0 {
		return windowsIn(index, 1, len(index.lines), "")
	}
	return declarationWindows(index, declarations)
}

// declarationWindows asks about whole declarations instead of fixed line
// windows: each function, method or type is one window named by its
// signature, consecutive small declarations share a window up to
// WindowLines lines, declarations too large for one window are split into
// line windows, and source between declarations keeps line windows.
func declarationWindows(index *textIndex, declarations []outline.Declaration) []window {
	lineCount := len(index.lines)
	members := map[int]bool{}
	for _, declaration := range declarations {
		if declaration.Container {
			continue
		}
		for _, container := range declarations {
			if container.Container && container.StartLine <= declaration.StartLine && declaration.EndLine <= container.EndLine {
				members[container.StartLine*1_000_000+container.EndLine] = true
			}
		}
	}
	leaves := []outline.Declaration{}
	for _, declaration := range declarations {
		if declaration.Container && members[declaration.StartLine*1_000_000+declaration.EndLine] {
			continue
		}
		if declaration.EndLine > lineCount || declaration.StartLine < 1 {
			continue
		}
		if len(leaves) > 0 && declaration.StartLine <= leaves[len(leaves)-1].EndLine {
			continue
		}
		leaves = append(leaves, declaration)
	}
	out := []window{}
	gap := func(first, last int) {
		if first <= last && !index.blankLines(first, last) {
			out = append(out, windowsIn(index, first, last, "")...)
		}
	}
	fits := func(first, last int) bool {
		return last-first+1 <= 2*WindowLines && index.offsets[last]-index.offsets[first-1] <= WindowMaxBytes
	}
	cursor := 1
	for position := 0; position < len(leaves); {
		first := leaves[position]
		gap(cursor, first.StartLine-1)
		if !fits(first.StartLine, first.EndLine) {
			out = append(out, windowsIn(index, first.StartLine, first.EndLine, first.Label()+" (part)")...)
			cursor = first.EndLine + 1
			position++
			continue
		}
		end := first.EndLine
		labels := []string{first.Label()}
		next := position + 1
		for next < len(leaves) && leaves[next].EndLine-first.StartLine+1 <= WindowLines &&
			index.blankLines(end+1, leaves[next].StartLine-1) && fits(first.StartLine, leaves[next].EndLine) {
			end = leaves[next].EndLine
			labels = append(labels, leaves[next].Label())
			next++
		}
		out = append(out, window{
			Name: joinLabels(labels), Range: Range{StartLine: first.StartLine, EndLine: end},
			StartByte: index.offsets[first.StartLine-1], EndByte: index.offsets[end],
		})
		cursor = end + 1
		position = next
	}
	gap(cursor, lineCount)
	return out
}

func joinLabels(labels []string) string {
	out := strings.Join(labels, "; ")
	if runes := []rune(out); len(runes) > 240 {
		out = string(runes[:240]) + "…"
	}
	return out
}

func groupWindows(index *textIndex, windows []window, limit int) [][]window {
	var groups [][]window
	current := []window{}
	for _, entry := range windows {
		if len(current) > 0 {
			byteLength := index.offsets[entry.Range.EndLine] - index.offsets[current[0].Range.StartLine-1]
			if len(current) >= limit || byteLength > SelectionGroupSourceBytes {
				groups = append(groups, current)
				current = []window{}
			}
		}
		current = append(current, entry)
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups
}

func contextFor(index *textIndex, group []window) string {
	partial := false
	for _, entry := range group {
		if entry.Partial {
			partial = true
			break
		}
	}
	first := max(1, group[0].Range.StartLine-8)
	last := min(len(index.lines), group[len(group)-1].Range.EndLine+8)
	oversized := false
	for _, line := range index.lines[:min(20, len(index.lines))] {
		if len(line) > WindowMaxBytes {
			oversized = true
		}
	}
	for _, line := range index.lines[first-1 : last] {
		if len(line) > WindowMaxBytes {
			oversized = true
		}
	}
	if partial || oversized {
		parts := make([]string, 0, len(group))
		for _, entry := range group {
			parts = append(parts, fmt.Sprintf(
				"Source lines %d-%d; source bytes %d-%d:\n%s",
				entry.Range.StartLine, entry.Range.EndLine, entry.StartByte, entry.EndByte,
				string(index.bytes[entry.StartByte:entry.EndByte]),
			))
		}
		return strings.Join(parts, "\n")
	}
	if len(index.bytes) <= WholeFileContextBytes {
		return index.source
	}
	return fmt.Sprintf(
		"Opening context:\n%s\nSource lines %d-%d:\n%s",
		strings.Join(index.lines[:min(20, len(index.lines))], "\n"),
		first, last, strings.Join(index.lines[first-1:last], "\n"),
	)
}

func declarationsFor(group []window) []requests.Declaration {
	out := make([]requests.Declaration, len(group))
	for index, entry := range group {
		out[index] = requests.Declaration{
			Name: entry.Name, StartLine: entry.Range.StartLine, EndLine: entry.Range.EndLine,
		}
	}
	return out
}

func sortSpans(spans []span) {
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && (spans[j].start < spans[j-1].start || (spans[j].start == spans[j-1].start && spans[j].end < spans[j-1].end)); j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
}

func mergeSpans(spans []span) []span {
	filtered := make([]span, 0, len(spans))
	for _, entry := range spans {
		if entry.end > entry.start {
			filtered = append(filtered, entry)
		}
	}
	sortSpans(filtered)
	merged := []span{}
	for _, entry := range filtered {
		if len(merged) > 0 && entry.start <= merged[len(merged)-1].end {
			if entry.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = entry.end
			}
			continue
		}
		merged = append(merged, entry)
	}
	return merged
}

func retract(spans []span, start, end int) []span {
	out := []span{}
	for _, entry := range spans {
		if entry.end <= start || entry.start >= end {
			out = append(out, entry)
			continue
		}
		if entry.start < start {
			out = append(out, span{entry.start, start})
		}
		if entry.end > end {
			out = append(out, span{end, entry.end})
		}
	}
	return out
}

func spanForRange(value EvidenceRange, index *textIndex) span {
	start := index.offsets[value.StartLine-1]
	end := index.offsets[value.EndLine]
	if value.SourceByteStart != nil {
		start = *value.SourceByteStart
	}
	if value.SourceByteEnd != nil {
		end = *value.SourceByteEnd
	}
	return span{start, end}
}

func rangesForSpans(spans []span, index *textIndex) []EvidenceRange {
	out := make([]EvidenceRange, 0, len(spans))
	for _, entry := range spans {
		out = append(out, index.rangeForSpan(entry.start, entry.end))
	}
	return out
}

func rangesForSpansToRanges(spans []span, index *textIndex) []Range {
	out := make([]Range, 0, len(spans))
	for _, entry := range spans {
		value := index.rangeForSpan(entry.start, entry.end)
		out = append(out, Range{StartLine: value.StartLine, EndLine: value.EndLine})
	}
	return out
}

func hasWindowEndingAt(windows []Range, line int) bool {
	for _, entry := range windows {
		if entry.EndLine == line {
			return true
		}
	}
	return false
}

func excerptsFor(index *textIndex, ranges []Range, chosen []span, comments []Range) ([]EvidenceRange, []Excerpt) {
	windows := make([]Range, 0, len(ranges))
	for _, entry := range ranges {
		windows = append(windows, Range{
			StartLine: max(1, entry.StartLine-3), EndLine: min(len(index.lines), entry.EndLine+3),
		})
	}
	for position := range windows {
		window := &windows[position]
		absorb := func(comment Range) bool {
			qualifies := (comment.StartLine <= window.EndLine && comment.EndLine >= window.StartLine) ||
				(comment.EndLine < window.StartLine && index.blankLines(comment.EndLine+1, window.StartLine-1)) ||
				(comment.StartLine > window.EndLine && index.blankLines(window.EndLine+1, comment.StartLine-1))
			if !qualifies {
				return false
			}
			start := min(window.StartLine, comment.StartLine)
			end := max(window.EndLine, comment.EndLine)
			if start == window.StartLine && end == window.EndLine {
				return false
			}
			window.StartLine, window.EndLine = start, end
			return true
		}
		changed := true
		for changed {
			changed = false
			for _, comment := range comments {
				if absorb(comment) {
					changed = true
				}
			}
			for cursor := len(comments) - 1; cursor >= 0; cursor-- {
				if absorb(comments[cursor]) {
					changed = true
				}
			}
		}
	}
	rendered := []span{}
	for _, window := range windows {
		segmentStart := index.offsets[window.StartLine-1]
		for line := window.StartLine; line <= window.EndLine; line++ {
			start, end := index.offsets[line-1], index.offsets[line]
			if end-start > WindowMaxBytes {
				rendered = append(rendered, span{segmentStart, start})
				for _, selected := range chosen {
					if selected.start < end && selected.end > start {
						rendered = append(rendered, span{max(selected.start, start), min(selected.end, end)})
					}
				}
				segmentStart = end
			}
		}
		rendered = append(rendered, span{segmentStart, index.offsets[window.EndLine]})
	}
	output := mergeSpans(rendered)
	rangesOut := make([]EvidenceRange, 0, len(output))
	excerpts := make([]Excerpt, 0, len(output))
	for _, entry := range output {
		value := index.rangeForSpan(entry.start, entry.end)
		if value.SourceByteStart == nil && entry.end == len(index.bytes) && hasWindowEndingAt(windows, len(index.lines)) {
			value.EndLine = len(index.lines)
		}
		rangesOut = append(rangesOut, value)
		excerpt := Excerpt{Range: value}
		if value.SourceByteStart != nil {
			excerpt.Source = string(index.bytes[entry.start:entry.end])
			start, end := entry.start, entry.end
			excerpt.SourceByteStart, excerpt.SourceByteEnd, excerpt.Partial = &start, &end, true
		} else {
			excerpt.Source = strings.Join(index.lines[value.StartLine-1:value.EndLine], "\n")
		}
		excerpts = append(excerpts, excerpt)
	}
	return rangesOut, excerpts
}

func stateSize(value any) int {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return 0
	}
	if buffer.Len() == 0 {
		return 0
	}
	return buffer.Len() - 1
}

func issueKindForContext(err error) enums.RetrievalIssueCode {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return enums.IssueCodeInterrupted
	}
	return enums.IssueCodeChanged
}

func selectFile(
	ctx context.Context, snapshot files.Snapshot, query string, score float64,
	evaluator Evaluator,
	prepare func(context.Context) ([]requests.Evidence, bool, error),
	validate func(context.Context) error,
) (selectionResult, error) {
	issues := &issueSet{counts: map[enums.RetrievalIssueCode]int{}}
	base := FileEvidence{
		Path: snapshot.Path, ContentHash: snapshot.ContentHash, Score: score,
		PresentationExcerpts: []Excerpt{},
	}
	if len(snapshot.Source) > SourceInspectionLimit {
		issues.add(enums.IssueCodeSourceInspectionLimit)
		base.SourceOmitted = true
		return selectionResult{File: base, Issues: issues.list()}, nil
	}
	index := newTextIndex(snapshot.Source)
	// Each window asks q and scope, plus ref when evidence is sent.
	perWindow := 2
	if prepare != nil {
		perWindow = 3
	}
	groups := groupWindows(index, buildWindows(index, outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source)), min(SelectionBatchSize, MaxQuestionsPerRequest/perWindow))
	groupCount := len(groups)
	queue := append([][]window{}, groups...)
	selected := []span{}
	selectedWindows := []window{}
	decisions := []SourceDecision{}
	decisionIndex := map[string]int{}
	omitted := false
	interrupted := false
	validAnswer := func(value float64) bool {
		return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
	}
	// Window groups are independent questions: preparing a request never
	// depends on an earlier answer. Prepare every request in order first, send
	// them concurrently, then apply the answers in the original order so the
	// result matches a sequential evaluation.
	type job struct {
		group    []window
		request  provider.Request
		evidence *[]requests.Evidence
	}
	jobs := []job{}
	terminal := enums.UnknownRetrievalIssueCode
	for len(queue) > 0 && !omitted && ctx.Err() == nil {
		group := queue[0]
		queue = queue[1:]
		var evidence []requests.Evidence
		present := false
		if prepare != nil {
			value, ok, err := prepare(ctx)
			if err != nil {
				kind := issueKindForContext(err)
				if kind == enums.IssueCodeInterrupted {
					interrupted = true
				}
				terminal = kind
				omitted = true
				break
			}
			if !ok {
				terminal = enums.IssueCodeChanged
				omitted = true
				break
			}
			evidence = value
			present = true
		}
		var evidencePointer *[]requests.Evidence
		// The reference treats empty evidence as absent and omits ref* questions.
		if present && len(evidence) > 0 {
			evidencePointer = &evidence
		}
		request := requests.EvidenceRequest(query, snapshot.Path, contextFor(index, group), declarationsFor(group), evidencePointer)
		// Split an oversized group only when a single window would fit: when the
		// shared parts (evidence, opening context) alone exceed the budget,
		// splitting multiplies requests without making any of them fit.
		if len(group) > 1 && stateSize(request.State) > SelectionStateBytes &&
			stateSize(requests.EvidenceRequest(query, snapshot.Path, contextFor(index, group[:1]), declarationsFor(group[:1]), evidencePointer).State) <= SelectionStateBytes {
			middle := (len(group) + 1) / 2
			queue = append([][]window{group[:middle], group[middle:]}, queue...)
			groupCount++
			continue
		}
		if validate != nil {
			if err := validate(ctx); err != nil {
				kind := issueKindForContext(err)
				if kind == enums.IssueCodeInterrupted {
					interrupted = true
				}
				terminal = kind
				omitted = true
				break
			}
		}
		jobs = append(jobs, job{group: group, request: request, evidence: evidencePointer})
	}
	answered := make([]map[string]float64, len(jobs))
	failed := make([]error, len(jobs))
	if len(jobs) == 1 {
		answered[0], failed[0] = evaluator.Evaluate(ctx, jobs[0].request, provider.EvalOptions{})
	} else {
		var wait sync.WaitGroup
		for position := range jobs {
			wait.Add(1)
			go func() {
				defer wait.Done()
				answered[position], failed[position] = evaluator.Evaluate(ctx, jobs[position].request, provider.EvalOptions{})
			}()
		}
		wait.Wait()
	}
	for position, current := range jobs {
		group := current.group
		evidencePointer := current.evidence
		answers, err := answered[position], failed[position]
		if err != nil {
			failure := asFailure(err)
			kind := retrievalIssueForProviderFailure(failure.Kind)
			if kind == enums.IssueCodeInterrupted {
				interrupted = true
			}
			if failure.Kind == enums.FailureProvider {
				if failure.Message != "" {
					issues.addProvider(failure.Message)
				} else {
					issues.add(enums.IssueCodeProvider)
				}
			} else {
				issues.add(kind)
			}
			if fatalIssue(kind) {
				break
			}
			continue
		}
		values := make([]float64, len(group))
		malformed := false
		for position := range group {
			q, qok := answers[fmt.Sprintf("q%d", position)]
			scope, sok := answers[fmt.Sprintf("scope%d", position)]
			ref := 0.0
			refok := true
			if evidencePointer != nil {
				ref, refok = answers[fmt.Sprintf("ref%d", position)]
			}
			if !qok || !sok || !refok || !validAnswer(q) || !validAnswer(scope) || !validAnswer(ref) {
				malformed = true
				break
			}
			values[position] = math.Max(math.Min(q, scope), ref)
		}
		if malformed {
			issues.add(enums.IssueCodeProvider)
			continue
		}
		for position, entry := range group {
			value := values[position]
			key := fmt.Sprintf("%d:%d", entry.StartByte, entry.EndByte)
			decision := SourceDecision{Range: index.rangeForSpan(entry.StartByte, entry.EndByte), Score: value}
			if existing, ok := decisionIndex[key]; ok {
				decisions[existing] = decision
			} else {
				decisionIndex[key] = len(decisions)
				decisions = append(decisions, decision)
			}
			if evidencePointer != nil && value <= 0.5 {
				selected = retract(selected, entry.StartByte, entry.EndByte)
				filtered := selectedWindows[:0]
				for _, existing := range selectedWindows {
					if existing.StartByte != entry.StartByte || existing.EndByte != entry.EndByte {
						filtered = append(filtered, existing)
					}
				}
				selectedWindows = filtered
			}
			if value > 0.5 {
				selected = append(selected, span{entry.StartByte, entry.EndByte})
				selectedWindows = append(selectedWindows, entry)
			}
		}
	}
	if terminal != enums.UnknownRetrievalIssueCode {
		issues.add(terminal)
	}
	if ctx.Err() != nil && !interrupted {
		issues.add(enums.IssueCodeInterrupted)
	}
	chosen := mergeSpans(selected)
	displayed := []span{}
	for _, decision := range decisions {
		if decision.Score <= SourceConfidenceBoundary {
			continue
		}
		decisionSpan := spanForRange(decision.Range, index)
		for _, selectedSpan := range chosen {
			start := max(decisionSpan.start, selectedSpan.start)
			end := min(decisionSpan.end, selectedSpan.end)
			if start < end {
				displayed = append(displayed, span{start, end})
			}
		}
	}
	displayed = mergeSpans(displayed)
	comments := commentRanges(index.lines)
	ranges := make([]Range, 0, len(selectedWindows))
	for _, entry := range selectedWindows {
		ranges = append(ranges, entry.Range)
	}
	rendered, excerpts := excerptsFor(index, ranges, chosen, comments)
	_, presentationExcerpts := excerptsFor(index, rangesForSpansToRanges(displayed, index), displayed, comments)
	if omitted {
		base.SourceOmitted = true
		base.Excerpts = []Excerpt{}
		base.PresentationExcerpts = []Excerpt{}
		return selectionResult{
			File: base, Groups: groupCount, Issues: issues.list(), ProviderFailure: issues.providerFailure,
		}, nil
	}
	base.Selected = rangesForSpans(chosen, index)
	base.Rendered = rendered
	base.Excerpts = excerpts
	base.PresentationSelected = rangesForSpans(displayed, index)
	base.PresentationExcerpts = presentationExcerpts
	base.SourceDecisions = make([]SourceDecision, 0, len(decisions))
	base.SourceDecisions = append(base.SourceDecisions, decisions...)
	return selectionResult{
		File: base, Groups: groupCount, Issues: issues.list(), ProviderFailure: issues.providerFailure,
	}, nil
}
