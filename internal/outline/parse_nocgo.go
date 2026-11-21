//go:build !cgo

package outline

// Tree-sitter needs cgo; without it no language has an outline and callers
// fall back to fixed line windows.
func grammarAvailable(string) bool { return false }

func parse(*language, []byte) []Declaration { return nil }
