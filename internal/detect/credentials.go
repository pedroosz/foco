package detect

import (
	"bytes"
	"context"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudflare/ahocorasick"
)

var _ Engine = (*Credentials)(nil)
var _ ContentDetector = (*Credentials)(nil)

// Credentials catches hand-written credentials that provider-specific rules
// miss because they have no recognizable prefix: passwords under secret-like
// keys, host:password pairs and maps from hosts to passwords, plus AWS access
// key IDs, which the other engines skip when they are AWS's documented
// example key. Excluding a file is the safe failure for foco, so these rules
// prefer recall, but each one also requires a value that looks like a real
// password (mixed character classes or high entropy) so ordinary
// configuration, ports and prose are not excluded.
type Credentials struct{}

func NewCredentials() *Credentials { return &Credentials{} }

// secretKeywords name values that are secrets themselves. serviceKeywords
// name services whose values are as often a database name or file path as a
// password, so their values must look strongly like a password.
var (
	secretKeywords  = []string{"pass", "pwd", "secret", "token", "api_key", "api-key", "apikey", "access_key", "access-key", "private_key", "private-key", "credential", "dbpass", "db_pass", "db-pass", "conn_str", "connstr", "connection_string", "connectionstring"}
	serviceKeywords = []string{"smtp", "postgres", "mysql", "mariadb", "redis", "mongo", "database"}
	keywordMatcher  = ahocorasick.NewStringMatcher(append(append([]string{}, secretKeywords...), serviceKeywords...))
	versionLike     = regexp.MustCompile(`^v?\d+(?:\.\d+)+`)
	pathLike        = regexp.MustCompile(`^-?[\w.-]*(?:/[\w.-]+)+$`)
	constantLike    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

var placeholders = []string{
	"${", "{{", "%s", "%(", "<", ">", "xxxx", "****", "....", "changeme", "change_me", "placeholder",
	"your_", "your-", "yourpass", "redacted", "dummy", "process.env", "os.environ", "getenv", "config.",
	"settings.", "env[", "env.", "secrets.", "vault:", "()", "[]", "\\n", "{", "}", "%2f",
}

// secretLike reports whether value looks like a password or key rather than
// an identifier, path, URL, version or number.
func secretLike(value string, strong bool) bool {
	if len(value) < 8 || len(value) > 512 {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range placeholders {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") ||
		versionLike.MatchString(value) || (pathLike.MatchString(value) && !keyLike(value)) || constantLike.MatchString(value) {
		return false
	}
	if strong && (hostPort(value) || strings.Contains(value, "/") || strings.HasSuffix(lower, ".sqlite3") || strings.HasSuffix(lower, ".db")) {
		return false
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range value {
		switch {
		case r > 127:
			return false
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '_' || r == '-' || r == '.':
		default:
			hasSymbol = true
		}
	}
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			classes++
		}
	}
	if !hasDigit {
		return false
	}
	if strong {
		return hasSymbol && hasDigit && (hasLower || hasUpper) && classes >= 3
	}
	if classes >= 3 {
		return true
	}
	return len(value) >= 16 && entropy(value) >= 3.5
}

// keyLike reports long mixed-case, high-entropy values such as AWS secret
// keys, which may contain slashes without being paths.
func keyLike(value string) bool {
	var lower, upper, digit bool
	for _, r := range value {
		lower = lower || (r >= 'a' && r <= 'z')
		upper = upper || (r >= 'A' && r <= 'Z')
		digit = digit || (r >= '0' && r <= '9')
	}
	return len(value) >= 20 && lower && upper && digit && entropy(value) >= 4
}

func entropy(value string) float64 {
	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}
	total := float64(len([]rune(value)))
	sum := 0.0
	for _, count := range counts {
		p := float64(count) / total
		sum -= p * math.Log2(p)
	}
	return sum
}

// DetectPath reads path itself. A read error is not reported: the union runs
// this engine after the primary engines, which already report unreadable files.
func (c *Credentials) DetectPath(ctx context.Context, path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil
	}
	return c.DetectContent(ctx, path, data)
}

var bareValueExtensions = map[string]bool{
	".env": true, ".ini": true, ".cfg": true, ".conf": true, ".properties": true, ".yaml": true, ".yml": true, ".toml": true,
}

func (c *Credentials) DetectContent(ctx context.Context, path string, content []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return credentialMatch(path, string(content)) != "", nil
}

// credentialMatch returns the first credential found in text, or "". It
// scans with plain string search instead of regular expressions: the rules
// run on every file foco reads.
func credentialMatch(path, text string) string {
	if match := awsKeyIDIn(text); match != "" {
		return match
	}
	bare := bareValueExtensions[strings.ToLower(filepath.Ext(path))] || strings.HasPrefix(filepath.Base(path), ".env")
	if match := keyedValueIn(text, bare); match != "" {
		return match
	}
	return hostCredentialIn(text)
}

func isUpperAlnum(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') }

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// awsKeyIDIn finds an AWS access key ID (AKIA, ASIA, AIDA or AROA plus 16
// uppercase letters or digits) on word boundaries.
func awsKeyIDIn(text string) string {
	for offset := 0; ; {
		index := strings.Index(text[offset:], "A")
		if index < 0 {
			return ""
		}
		start := offset + index
		offset = start + 1
		if start+20 > len(text) || (start > 0 && isWordByte(text[start-1])) {
			continue
		}
		switch text[start : start+4] {
		case "AKIA", "ASIA", "AIDA", "AROA":
		default:
			continue
		}
		valid := true
		for _, c := range []byte(text[start+4 : start+20]) {
			if !isUpperAlnum(c) {
				valid = false
				break
			}
		}
		if valid && (start+20 == len(text) || !isWordByte(text[start+20])) {
			return text[start : start+20]
		}
	}
}

func isKeyByte(c byte) bool { return isWordByte(c) || c == '.' || c == '-' }

func asciiLower(text string) []byte {
	out := []byte(text)
	for index, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[index] = c + 32
		}
	}
	return out
}

type keyword struct {
	text   []byte
	strong bool
}

var keywords = func() []keyword {
	out := []keyword{}
	for _, word := range secretKeywords {
		out = append(out, keyword{text: []byte(word)})
	}
	for _, word := range serviceKeywords {
		out = append(out, keyword{text: []byte(word), strong: true})
	}
	return out
}()

// keyedValueIn finds key = "value" or "key": "value" where the key contains a
// secret or service keyword and the value looks like a password. With bare,
// unquoted values that end their line count too (.env, .ini, YAML).
func keyedValueIn(text string, bare bool) string {
	lower := asciiLower(text)
	seen := map[int]bool{}
	for _, hit := range keywordMatcher.MatchThreadSafe(lower) {
		word := keywords[hit]
		for offset := 0; ; {
			index := bytes.Index(lower[offset:], word.text)
			if index < 0 {
				break
			}
			start := offset + index
			offset = start + 1
			keyStart := start
			for keyStart > 0 && isKeyByte(text[keyStart-1]) {
				keyStart--
			}
			if seen[keyStart] {
				continue
			}
			seen[keyStart] = true
			if match := valueAfterKey(text, keyStart, start+len(word.text), bare, word.strong); match != "" {
				return match
			}
		}
	}
	return ""
}

// valueAfterKey reads the rest of the key from position, then a separator
// and a value, and returns the value when it looks like a secret.
func valueAfterKey(text string, keyStart, position int, bare, strong bool) string {
	cursor := position
	for cursor < len(text) && isKeyByte(text[cursor]) {
		cursor++
	}
	if cursor < len(text) && (text[cursor] == '"' || text[cursor] == '\'') {
		cursor++
	}
	cursor = skipBlanks(text, cursor)
	if cursor >= len(text) || (text[cursor] != ':' && text[cursor] != '=') {
		return ""
	}
	cursor = skipBlanks(text, cursor+1)
	if cursor >= len(text) {
		return ""
	}
	var value string
	if quote := text[cursor]; quote == '"' || quote == '\'' {
		end := strings.IndexAny(text[cursor+1:], string(quote)+"\n \t")
		if end < 0 || text[cursor+1+end] != quote {
			return ""
		}
		value = text[cursor+1 : cursor+1+end]
	} else {
		if !bare {
			return ""
		}
		lineStart := strings.LastIndexByte(text[:keyStart], '\n') + 1
		if prefix := strings.TrimSpace(text[lineStart:keyStart]); prefix != "" && prefix != "export" {
			return ""
		}
		end := strings.IndexAny(text[cursor:], " \t\r\n#;\"'")
		if end < 0 {
			end = len(text) - cursor
		}
		value = text[cursor : cursor+end]
		if rest := skipBlanks(text, cursor+end); rest < len(text) && text[rest] != '\n' && text[rest] != '\r' {
			return ""
		}
	}
	if len(value) >= 8 && secretLike(value, strong) {
		return value
	}
	return ""
}

func skipBlanks(text string, cursor int) int {
	for cursor < len(text) && (text[cursor] == ' ' || text[cursor] == '\t') {
		cursor++
	}
	return cursor
}

// hostCredentialIn finds quoted "host:password" literals and "host":
// "password" pairs, where host is a dotted hostname or IPv4 address,
// optionally after a scheme or "://".
func hostCredentialIn(text string) string {
	for offset := 0; offset < len(text); {
		index := strings.IndexAny(text[offset:], "\"'")
		if index < 0 {
			return ""
		}
		start := offset + index
		quote := text[start]
		end := strings.IndexAny(text[start+1:], string(quote)+"\n")
		if end < 0 {
			return ""
		}
		end += start + 1
		offset = end + 1
		if text[end] != quote {
			offset = end
			continue
		}
		literal := text[start+1 : end]
		if len(literal) < 4 || len(literal) > 300 {
			continue
		}
		host := stripScheme(literal)
		if colon := strings.IndexByte(host, ':'); colon > 0 {
			if hostLike(host[:colon]) {
				password := host[colon+1:]
				if len(password) >= 8 && !strings.ContainsAny(password, ":/") && secretLike(password, true) {
					return literal
				}
			}
			continue
		}
		if !hostLike(host) {
			continue
		}
		cursor := end + 1
		for cursor < len(text) && (text[cursor] == ' ' || text[cursor] == '\t') {
			cursor++
		}
		if cursor >= len(text) || text[cursor] != ':' {
			continue
		}
		cursor++
		for cursor < len(text) && (text[cursor] == ' ' || text[cursor] == '\t') {
			cursor++
		}
		if cursor >= len(text) || (text[cursor] != '"' && text[cursor] != '\'') {
			continue
		}
		close := strings.IndexAny(text[cursor+1:], string(text[cursor])+"\n \t")
		if close < 0 || text[cursor+1+close] != text[cursor] {
			continue
		}
		if value := text[cursor+1 : cursor+1+close]; len(value) >= 8 && secretLike(value, true) {
			return literal + ": " + value
		}
	}
	return ""
}

func stripScheme(literal string) string {
	if index := strings.Index(literal, "://"); index >= 0 {
		scheme := literal[:index]
		valid := true
		for _, c := range []byte(scheme) {
			if !isKeyByte(c) && c != '+' {
				valid = false
				break
			}
		}
		if valid {
			return literal[index+3:]
		}
	}
	return literal
}

// hostLike reports a dotted hostname with letters, or an IPv4 address.
func hostLike(host string) bool {
	if len(host) < 4 || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	digitsAndDots, letters := true, false
	for _, c := range []byte(host) {
		switch {
		case c >= '0' && c <= '9':
		case c == '.':
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			digitsAndDots, letters = false, true
		case c == '-':
			digitsAndDots = false
		default:
			return false
		}
	}
	if digitsAndDots {
		return strings.Count(host, ".") == 3
	}
	// A hostname ends in a letters-only top-level label; dotted settings
	// keys such as "system.base-hostname" do not.
	tld := host[strings.LastIndexByte(host, '.')+1:]
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, c := range []byte(tld) {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return letters
}

// hostPort reports values such as "my.server:9092", a host and port rather
// than a password.
func hostPort(value string) bool {
	colon := strings.LastIndexByte(value, ':')
	if colon <= 0 || colon == len(value)-1 {
		return false
	}
	for _, c := range []byte(value[colon+1:]) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (c *Credentials) Close() error { return nil }
