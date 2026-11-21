package retrieve

import (
	"context"
	"encoding/json"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/outline"
	"foco/internal/requests"
)

func extension(value string) string {
	base := path.Base(strings.ReplaceAll(value, "\\", "/"))
	if base == "." || base == ".." {
		return ""
	}
	index := strings.LastIndexByte(base, '.')
	if index <= 0 {
		return ""
	}
	return base[index:]
}

func runeStartAtOrBefore(source string, index int) int {
	if index >= len(source) {
		return len(source)
	}
	if index <= 0 {
		return 0
	}
	for index > 0 && !utf8.RuneStart(source[index]) {
		index--
	}
	return index
}

func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }

func previewDirectory(ctx context.Context, reader Reader, directory string, issue func(enums.RetrievalIssueCode)) *requests.DirectoryPreview {
	preview := &requests.DirectoryPreview{
		Entries: []requests.DirectoryEntry{}, SampledExtensions: map[string]int{},
	}
	offset := 0
	bytesSeen := 0
	for {
		page, err := reader.ListPage(ctx, directory, offset)
		if err != nil {
			if ctx.Err() != nil {
				issue(enums.IssueCodeInterrupted)
			} else {
				issue(enums.IssueCodeUnreadable)
			}
			return preview
		}
		if page.Issue != enums.UnknownFileIssueKind {
			issue(retrievalIssueForFileIssue(page.Issue))
			return preview
		}
		for _, entry := range page.Entries {
			child := requests.DirectoryEntry{Name: path.Base(strings.ReplaceAll(entry.Path, "\\", "/")), Kind: enums.NavigationKindFile}
			if entry.IsDir {
				child.Kind = enums.NavigationKindDirectory
			}
			blob, _ := jsonMarshal(child)
			if len(preview.Entries) >= 64 || bytesSeen+len(blob) > 4096 {
				preview.Truncated = true
				break
			}
			preview.Entries = append(preview.Entries, child)
			bytesSeen += len(blob)
			if entry.IsDir {
				preview.SampledDirectories++
			} else {
				preview.SampledFiles++
				key := extension(entry.Path)
				if key == "" {
					key = "[no extension]"
				}
				preview.SampledExtensions[key]++
			}
		}
		if preview.Truncated {
			break
		}
		if page.NextOffset == 0 {
			break
		}
		offset = page.NextOffset
	}
	sort.Slice(preview.Entries, func(i, j int) bool { return preview.Entries[i].Name < preview.Entries[j].Name })
	return preview
}

func previewFile(snapshot files.Snapshot) *requests.FilePreview {
	data := []byte(snapshot.Source)
	limit := len(data)
	if limit > PreviewBytes {
		limit = PreviewBytes
		for limit > 0 && !utf8.RuneStart(data[limit]) {
			limit--
		}
	}
	text := string(data[:limit])
	truncated := len(data) > PreviewBytes
	preview := &requests.FilePreview{
		SizeBytes: len(data), Extension: extension(snapshot.Path), Text: text,
		PreviewBytes: len(text), Truncated: truncated, Range: "opening bytes",
	}
	if truncated {
		if outlined, ok := outlinePreview(snapshot); ok {
			preview.Text, preview.PreviewBytes, preview.Range = outlined, len(outlined), "opening bytes and declaration outline"
		}
	}
	for {
		blob, _ := jsonMarshal(preview)
		if len(blob) <= PreviewJSONBytes {
			break
		}
		if len(preview.Text) == 0 {
			break
		}
		next := len(preview.Text) * 3 / 4
		if next >= len(preview.Text) {
			next = len(preview.Text) - 1
		}
		next = runeStartAtOrBefore(preview.Text, next)
		preview.Text = preview.Text[:next]
		preview.PreviewBytes = len(preview.Text)
		preview.Truncated = true
	}
	return preview
}

// withDirectoryContent samples the file children of a directory item. Reads
// found in prefetched (keyed by absolute path) are used as is; the rest are
// read concurrently here.
// outlinePreview replaces the opening 16 KB of a large file with a shorter
// opening plus the file's declaration outline: every declaration's line range
// and signature. The provider sees the whole file's structure in fewer bytes,
// so navigation judges large files on more than their first lines and more
// files fit in each navigation request.
func outlinePreview(snapshot files.Snapshot) (string, bool) {
	declarations := outline.Of(snapshot.Path, snapshot.ContentHash, snapshot.Source)
	if len(declarations) == 0 {
		return "", false
	}
	opening := snapshot.Source[:runeStartAtOrBefore(snapshot.Source, OutlineOpeningBytes)]
	var out strings.Builder
	out.WriteString(opening)
	out.WriteString("\n\nDeclaration outline (lines, signature):\n")
	for _, declaration := range declarations {
		line := itoa(declaration.StartLine) + "-" + itoa(declaration.EndLine) + " " + declaration.Label() + "\n"
		if out.Len()+len(line) > PreviewBytes {
			out.WriteString("…\n")
			break
		}
		out.WriteString(line)
	}
	return out.String(), true
}

func withDirectoryContent(ctx context.Context, reader Reader, item requests.NavigationItem, issue func(enums.RetrievalIssueCode), report func(string, *files.Snapshot), prefetched map[string]files.SnapshotResult) (requests.NavigationItem, []Donor) {
	if item.ChildPreview == nil {
		return item, nil
	}
	preview := *item.ChildPreview
	preview.ContentSamples = []requests.ContentSample{}
	donors := []Donor{}
	children := make([]requests.DirectoryEntry, 0, len(preview.Entries))
	for _, child := range preview.Entries {
		if child.Kind == enums.NavigationKindFile {
			children = append(children, child)
		}
	}
	perFile := 16000
	if len(children) > 1 {
		perFile = 16000 / len(children)
	}
	if perFile < 80 {
		perFile = 80
	}
	results := make([]files.SnapshotResult, len(children))
	missing := []string{}
	missingAt := []int{}
	for index, child := range children {
		full := absPath(reader.Root(), path.Join(item.Path, child.Name))
		if result, ok := prefetched[full]; ok {
			results[index] = result
			continue
		}
		missing = append(missing, full)
		missingAt = append(missingAt, index)
	}
	for position, result := range readSnapshots(ctx, reader, missing) {
		results[missingAt[position]] = result
	}
	for index, child := range children {
		relative := path.Join(item.Path, child.Name)
		result := results[index]
		if result.Status == enums.SnapshotStatusIssue {
			if issue != nil {
				issue(retrievalIssueForFileIssue(result.Issue))
			}
			continue
		}
		if result.Status != enums.SnapshotStatusSnapshot || result.Snapshot == nil || len(result.Snapshot.Source) > SourceInspectionLimit {
			continue
		}
		if report != nil {
			report(relative, result.Snapshot)
		}
		source := result.Snapshot.Source
		donors = append(donors, Donor{Path: relative, ContentHash: result.Snapshot.ContentHash})
		part := perFile / 3
		offsets := []int{0, max(0, len(source)/2-part/2), max(0, len(source)-part)}
		sample := requests.ContentSample{Name: child.Name}
		if len(source) <= perFile {
			sample.Source = source
		} else {
			sample.Truncated = true
			pieces := make([]string, 0, len(offsets))
			for _, rawOffset := range offsets {
				offset := runeStartAtOrBefore(source, rawOffset)
				end := runeStartAtOrBefore(source, min(len(source), offset+part))
				pieces = append(pieces, "[character offset "+itoa(offset)+"]\n"+source[offset:end])
			}
			sample.Source = strings.Join(pieces, "\n...\n")
		}
		preview.ContentSamples = append(preview.ContentSamples, sample)
	}
	for {
		blob, _ := jsonMarshal(preview)
		if len(blob) <= PreviewSampleJSONBytes {
			break
		}
		changed := false
		for index := range preview.ContentSamples {
			sample := &preview.ContentSamples[index]
			if len(sample.Source) <= 80 {
				continue
			}
			next := max(80, len(sample.Source)*4/5)
			next = runeStartAtOrBefore(sample.Source, next)
			sample.Source = sample.Source[:next]
			sample.Truncated = true
			changed = true
		}
		if !changed {
			break
		}
	}
	item.ChildPreview = &preview
	return item, donors
}

type textChunk struct {
	Text      string
	StartLine int
	EndLine   int
}

func splitText(source string, maxBytes int) []textChunk {
	if maxBytes < 4 {
		maxBytes = 4
	}
	index := newTextIndex(source)
	var out []textChunk
	start := 0
	for start < len(source) {
		finish := min(len(source), start+maxBytes)
		if finish < len(source) {
			finish = runeStartAtOrBefore(source, finish)
			if newline := strings.LastIndexByte(source[start:finish], '\n'); newline >= 0 {
				finish = start + newline + 1
			}
		}
		if finish <= start {
			finish = min(len(source), start+maxBytes)
			for finish < len(source) && !utf8.RuneStart(source[finish]) {
				finish++
			}
			if finish <= start {
				finish = len(source)
			}
		}
		text := source[start:finish]
		endLine := index.lineAt(max(start, finish-1))
		out = append(out, textChunk{Text: text, StartLine: index.lineAt(start), EndLine: endLine})
		start = finish
	}
	return out
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
