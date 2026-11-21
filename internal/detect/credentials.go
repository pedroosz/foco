package detect

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// secretKeyWords name values that are secrets themselves. serviceKeyWords
// name services whose values are as often a database name or file path as a
// password, so their values must look strongly like a password.
const (
	secretKeyWords  = `pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|db[_-]?pass|conn(?:ection)?[_-]?str(?:ing)?`
	serviceKeyWords = `smtp|postgres(?:ql)?|mysql|mariadb|redis|mongo(?:db)?|database`
)

var (
	// "dbPassword": "S3cr3t!x", db_password = 'S3cr3t!x'. The value must be a
	// quoted literal, so code such as token = parser.next() never matches.
	keyedSecret  = regexp.MustCompile(`(?i)["']?[a-z0-9_.-]*(?:` + secretKeyWords + `)[a-z0-9_.-]*["']?\s*[:=]\s*["']([^"'\s]{8,})["']`)
	keyedService = regexp.MustCompile(`(?i)["']?[a-z0-9_.-]*(?:` + serviceKeyWords + `)[a-z0-9_.-]*["']?\s*[:=]\s*["']([^"'\s]{8,})["']`)
	// DB_PASSWORD=S3cr3t!x in .env, .ini, .properties and similar files, where
	// values are not quoted.
	keyedBare = regexp.MustCompile(`(?im)^\s*(?:export\s+)?[a-z0-9_.-]*(?:` + secretKeyWords + `|` + serviceKeyWords + `)[a-z0-9_.-]*\s*[:=]\s*([^"'\s#;]{8,})\s*$`)
	// "db-prod-01.example.local:S3nh@Prod#2026", "10.0.0.8:Admin#2026"
	hostPassword = regexp.MustCompile(`(?i)["'\s](?:[a-z][a-z0-9+.-]*)?:?(?://)?((?:[a-z0-9-]+\.)+[a-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3}):([^"'\s:/]{8,})["']`)
	// "db-prod-01.example.local": "S3nh@Prod#2026!"
	hostKeyedValue = regexp.MustCompile(`(?i)["'](?:[a-z][a-z0-9+.-]*)?:?(?://)?((?:[a-z0-9-]+\.)+[a-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3})["']\s*:\s*["']([^"'\s]{8,})["']`)
	versionLike    = regexp.MustCompile(`^v?\d+(?:\.\d+)+`)
	pathLike       = regexp.MustCompile(`^-?[\w.-]*(?:/[\w.-]+)+$`)
	constantLike   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	awsKeyID       = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b`)
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
	if strong && (strings.Contains(value, "/") || strings.HasSuffix(lower, ".sqlite3") || strings.HasSuffix(lower, ".db")) {
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

// credentialMatch returns the first credential found in text, or "".
func credentialMatch(path, text string) string {
	if match := awsKeyID.FindString(text); match != "" {
		return match
	}
	for _, match := range keyedSecret.FindAllStringSubmatch(text, -1) {
		if secretLike(match[1], false) {
			return match[0]
		}
	}
	for _, match := range keyedService.FindAllStringSubmatch(text, -1) {
		if secretLike(match[1], true) {
			return match[0]
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	if bareValueExtensions[ext] || strings.HasPrefix(filepath.Base(path), ".env") {
		for _, match := range keyedBare.FindAllStringSubmatch(text, -1) {
			if secretLike(match[1], false) {
				return match[0]
			}
		}
	}
	for _, match := range hostPassword.FindAllStringSubmatch(text, -1) {
		if secretLike(match[2], true) {
			return match[0]
		}
	}
	for _, match := range hostKeyedValue.FindAllStringSubmatch(text, -1) {
		if secretLike(match[2], true) {
			return match[0]
		}
	}
	return ""
}

func (c *Credentials) Close() error { return nil }
