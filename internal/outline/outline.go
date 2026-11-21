// Package outline extracts declarations (functions, methods, types) from
// source files with tree-sitter, so previews can show a file's structure and
// source selection can ask about whole declarations instead of fixed line
// windows.
package outline

import (
	"path"
	"sort"
	"strings"
	"sync"
)

// Declaration is one named declaration. Lines are 1-based and inclusive.
// Container is set for declarations that group others, such as classes,
// impl blocks and modules; their members are listed separately.
type Declaration struct {
	Name      string
	Kind      string
	Signature string
	StartLine int
	EndLine   int
	Container bool
}

// Label names the declaration for a provider question, such as
// "func (d *Detector) DetectBytes".
func (d Declaration) Label() string {
	if d.Signature != "" {
		return d.Signature
	}
	return d.Kind + " " + d.Name
}

const maxSignatureRunes = 160

var (
	cacheMu sync.Mutex
	cache   = map[string]*entry{}
	order   []string
)

// entry is one cached outline; ready closes once it is parsed, so concurrent
// callers for the same file wait for one parse instead of each parsing.
type entry struct {
	ready chan struct{}
	value []Declaration
}

const cacheEntries = 4096

// Of returns the declarations of source, sorted by start line, or nil when
// the file's language is not supported or it does not parse cleanly. Results
// are cached by contentHash, so discovery and selection parse a file once.
func Of(filePath, contentHash, source string) []Declaration {
	language, ok := languageFor(filePath)
	if !ok || source == "" {
		return nil
	}
	key := language.name + "\x00" + contentHash
	cacheMu.Lock()
	if found, ok := cache[key]; ok {
		cacheMu.Unlock()
		<-found.ready
		return found.value
	}
	pending := &entry{ready: make(chan struct{})}
	cache[key] = pending
	order = append(order, key)
	if len(order) > cacheEntries {
		delete(cache, order[0])
		order = order[1:]
	}
	cacheMu.Unlock()
	out := parse(language, []byte(source))
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartLine != out[j].StartLine {
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].EndLine > out[j].EndLine
	})
	pending.value = out
	close(pending.ready)
	return out
}

// language describes which syntax nodes are declarations for one grammar.
type language struct {
	name string
	// declarations maps node kinds to the kind word shown to the provider.
	declarations map[string]string
	// containers are declaration kinds whose bodies hold further declarations.
	containers map[string]bool
	// scopes are non-declaration nodes to search inside, such as export
	// statements, decorators and namespace bodies.
	scopes map[string]bool
}

func languageFor(filePath string) (*language, bool) {
	ext := strings.ToLower(path.Ext(strings.ReplaceAll(filePath, "\\", "/")))
	name, ok := extensions[ext]
	if !ok {
		return nil, false
	}
	value, ok := languages[name]
	return value, ok && grammarAvailable(name)
}

var extensions = map[string]string{
	".go": "go", ".py": "python", ".rb": "ruby", ".rake": "ruby",
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
	".java": "java", ".c": "c", ".h": "c",
	".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
	".rs": "rust",
}

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

var javascriptLike = &language{
	declarations: map[string]string{
		"function_declaration": "function", "generator_function_declaration": "function",
		"class_declaration": "class", "abstract_class_declaration": "class",
		"method_definition": "method", "interface_declaration": "interface",
		"type_alias_declaration": "type", "enum_declaration": "enum",
		"internal_module": "namespace",
	},
	containers: set("class_declaration", "abstract_class_declaration", "internal_module"),
	scopes:     set("program", "export_statement", "class_body", "statement_block", "ambient_declaration"),
}

func clone(base *language, name string) *language {
	copy := *base
	copy.name = name
	return &copy
}

var languages = map[string]*language{
	"go": {
		name: "go",
		declarations: map[string]string{
			"function_declaration": "func", "method_declaration": "func", "type_spec": "type",
		},
		scopes: set("source_file", "type_declaration"),
	},
	"python": {
		name: "python",
		declarations: map[string]string{
			"function_definition": "def", "class_definition": "class",
		},
		containers: set("class_definition"),
		scopes:     set("module", "decorated_definition", "block"),
	},
	"ruby": {
		name: "ruby",
		declarations: map[string]string{
			"method": "def", "singleton_method": "def", "class": "class", "module": "module",
		},
		containers: set("class", "module"),
		scopes:     set("program", "body_statement"),
	},
	"javascript": clone(javascriptLike, "javascript"),
	"typescript": clone(javascriptLike, "typescript"),
	"tsx":        clone(javascriptLike, "tsx"),
	"java": {
		name: "java",
		declarations: map[string]string{
			"class_declaration": "class", "interface_declaration": "interface",
			"enum_declaration": "enum", "record_declaration": "record",
			"method_declaration": "method", "constructor_declaration": "constructor",
		},
		containers: set("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"),
		scopes:     set("program", "class_body", "interface_body", "enum_body", "enum_body_declarations"),
	},
	"c": {
		name:         "c",
		declarations: map[string]string{"function_definition": "function", "struct_specifier": "struct"},
		scopes:       set("translation_unit", "declaration", "type_definition", "preproc_ifdef", "preproc_if", "preproc_else"),
	},
	"cpp": {
		name: "cpp",
		declarations: map[string]string{
			"function_definition": "function", "class_specifier": "class", "struct_specifier": "struct",
			"namespace_definition": "namespace",
		},
		containers: set("class_specifier", "struct_specifier", "namespace_definition"),
		scopes: set("translation_unit", "declaration_list", "field_declaration_list", "template_declaration",
			"declaration", "type_definition", "preproc_ifdef", "preproc_if", "preproc_else"),
	},
	"rust": {
		name: "rust",
		declarations: map[string]string{
			"function_item": "fn", "struct_item": "struct", "enum_item": "enum", "trait_item": "trait",
			"impl_item": "impl", "mod_item": "mod",
		},
		containers: set("trait_item", "impl_item", "mod_item"),
		scopes:     set("source_file", "declaration_list"),
	},
}

// signature returns the declaration's header: its source up to the body,
// with whitespace collapsed and a length cap.
func signature(header string) string {
	fields := strings.Fields(header)
	out := strings.Join(fields, " ")
	out = strings.TrimRight(out, " {:")
	runes := []rune(out)
	if len(runes) > maxSignatureRunes {
		out = string(runes[:maxSignatureRunes]) + "…"
	}
	return out
}
