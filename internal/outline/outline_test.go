//go:build cgo

package outline

import (
	"strings"
	"testing"
)

func names(declarations []Declaration) string {
	out := []string{}
	for _, declaration := range declarations {
		out = append(out, declaration.Kind+" "+declaration.Name)
	}
	return strings.Join(out, ", ")
}

func TestOutlines(t *testing.T) {
	cases := []struct {
		path, source, want string
	}{
		{"a.go", "package a\n\ntype Detector struct{}\n\nfunc New() *Detector { return nil }\n\nfunc (d *Detector) Scan(b []byte) bool {\n\treturn false\n}\n",
			"type Detector, func New, func Scan"},
		{"a.py", "import os\n\nclass Repo:\n    def open(self):\n        pass\n\n@cache\ndef load(path):\n    return path\n",
			"class Repo, def open, def load"},
		{"a.rb", "module Shop\n  class Cart\n    def total\n      0\n    end\n  end\nend\n",
			"module Shop, class Cart, def total"},
		{"a.ts", "export class Store {\n  get(key: string) { return key; }\n}\nexport function make(): Store { return new Store(); }\ninterface Opts { a: number }\n",
			"class Store, method get, function make, interface Opts"},
		{"A.java", "class A {\n  A() {}\n  int size() { return 0; }\n}\n", "class A, constructor A, method size"},
		{"a.c", "struct point { int x; };\nint add(int a, int b) {\n  return a + b;\n}\n", "struct point, function add"},
		{"a.rs", "struct S;\nimpl S {\n    fn run(&self) {}\n}\nfn main() {}\n", "struct S, impl S, fn run, fn main"},
	}
	for _, c := range cases {
		got := Of(c.path, c.path, c.source)
		if names(got) != c.want {
			t.Errorf("%s: got %q, want %q", c.path, names(got), c.want)
		}
	}
}

func TestOutlineLinesAndSignature(t *testing.T) {
	got := Of("b.go", "b", "package b\n\n// Scan reports.\nfunc (d *Detector) Scan(\n\tb []byte,\n) bool {\n\treturn false\n}\n")
	if len(got) != 1 || got[0].StartLine != 4 || got[0].EndLine != 8 || got[0].Signature != "func (d *Detector) Scan( b []byte, ) bool" {
		t.Fatalf("got %+v", got)
	}
}

func TestUnsupportedAndBrokenFiles(t *testing.T) {
	if got := Of("notes.md", "m", "# Title\n"); got != nil {
		t.Fatalf("markdown: %+v", got)
	}
	if got := Of("bad.go", "bad", "}}}} {{{{ ))) func (\n"+strings.Repeat("@@@ ### !!!\n", 20)); got != nil {
		t.Fatalf("unparseable file kept an outline: %+v", got)
	}
}
