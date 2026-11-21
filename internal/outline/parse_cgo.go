//go:build cgo

package outline

import (
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"
	treesitterc "github.com/tree-sitter/tree-sitter-c/bindings/go"
	treesittercpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"
	treesittergo "github.com/tree-sitter/tree-sitter-go/bindings/go"
	treesitterjava "github.com/tree-sitter/tree-sitter-java/bindings/go"
	treesitterjavascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"
	treesitterruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	treesitterrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
	treesittertypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

var grammars = map[string]func() unsafe.Pointer{
	"go": treesittergo.Language, "python": treesitterpython.Language, "ruby": treesitterruby.Language,
	"javascript": treesitterjavascript.Language, "typescript": treesittertypescript.LanguageTypescript,
	"tsx": treesittertypescript.LanguageTSX, "java": treesitterjava.Language,
	"c": treesitterc.Language, "cpp": treesittercpp.Language, "rust": treesitterrust.Language,
}

func grammarAvailable(name string) bool { _, ok := grammars[name]; return ok }

// maxErrorShare is the largest share of a file's top-level nodes that may be
// parse errors before the outline is discarded; a grammar mismatch (such as
// C++ in a .h file) yields mostly errors and misleading declarations.
const maxErrorShare = 0.2

func parse(lang *language, source []byte) []Declaration {
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(sitter.NewLanguage(grammars[lang.name]())); err != nil {
		return nil
	}
	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()
	root := tree.RootNode()
	if count := root.NamedChildCount(); count > 0 {
		errors := 0
		for index := uint(0); index < count; index++ {
			if child := root.NamedChild(index); child != nil && (child.Kind() == "ERROR" || child.IsMissing()) {
				errors++
			}
		}
		if float64(errors) > maxErrorShare*float64(count) {
			return nil
		}
	}
	out := []Declaration{}
	var walk func(node *sitter.Node, depth int)
	walk = func(node *sitter.Node, depth int) {
		if depth > 12 {
			return
		}
		for index := uint(0); index < node.NamedChildCount(); index++ {
			child := node.NamedChild(index)
			if child == nil {
				continue
			}
			kind := child.Kind()
			if word, ok := lang.declarations[kind]; ok {
				if declaration, ok := describe(child, word, lang.containers[kind], source); ok {
					out = append(out, declaration)
				}
				if lang.containers[kind] {
					walk(child, depth+1)
				}
				continue
			}
			if lang.scopes[kind] || kind == "body" || kind == "class_body" {
				walk(child, depth+1)
			}
		}
	}
	walk(root, 0)
	return out
}

func describe(node *sitter.Node, word string, container bool, source []byte) (Declaration, bool) {
	name := nameOf(node, source)
	if name == "" {
		return Declaration{}, false
	}
	start := node.StartByte()
	headerEnd := node.EndByte()
	if body := node.ChildByFieldName("body"); body != nil {
		headerEnd = body.StartByte()
	}
	if limit := start + 400; headerEnd > limit {
		headerEnd = limit
	}
	return Declaration{
		Name: name, Kind: word, Signature: signature(string(source[start:headerEnd])),
		StartLine: int(node.StartPosition().Row) + 1, EndLine: int(node.EndPosition().Row) + 1,
		Container: container,
	}, true
}

// nameOf finds the declared name: the name field, or for C-family functions
// the identifier inside the declarator chain.
func nameOf(node *sitter.Node, source []byte) string {
	if name := node.ChildByFieldName("name"); name != nil {
		return name.Utf8Text(source)
	}
	if node.Kind() == "impl_item" {
		if value := node.ChildByFieldName("type"); value != nil {
			return value.Utf8Text(source)
		}
	}
	declarator := node.ChildByFieldName("declarator")
	for depth := 0; declarator != nil && depth < 8; depth++ {
		switch declarator.Kind() {
		case "identifier", "field_identifier", "qualified_identifier", "destructor_name", "operator_name":
			return declarator.Utf8Text(source)
		}
		next := declarator.ChildByFieldName("declarator")
		if next == nil {
			break
		}
		declarator = next
	}
	return ""
}
