package cli

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"foco/internal/enums"
)

func TestParseTopLevel(t *testing.T) {
	cwd, err := Parse(nil)
	if err != nil || cwd.Kind != KindHelp {
		t.Fatalf("no args: got %+v, %v", cwd, err)
	}
	version, err := Parse([]string{"--version"})
	if err != nil || version.Kind != KindVersion {
		t.Fatalf("--version: got %+v, %v", version, err)
	}
	if _, err := Parse([]string{"--help", "x"}); err == nil {
		t.Fatal("--help with positional must fail")
	}
}

func TestParseSearch(t *testing.T) {
	cmd, err := Parse([]string{"which tests?", ".", "--max-output-bytes", "256", "--no-locations"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindSearch || cmd.Search.Query != "which tests?" || cmd.Search.Root != "." {
		t.Fatalf("unexpected command: %+v", cmd)
	}
	if cmd.Search.MaxOutputBytes != 256 || !cmd.Search.NoLocations {
		t.Fatalf("unexpected search options: %+v", cmd.Search)
	}
	if _, err := Parse([]string{"q", ".", "--max-output-bytes", "255"}); err == nil {
		t.Fatal("--max-output-bytes below 256 must fail")
	}
}

func TestFilesIsSearchQuery(t *testing.T) {
	cmd, err := Parse([]string{"files"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindSearch {
		t.Fatalf("files must parse as a search query, got kind %v", cmd.Kind)
	}
	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Search.Query != "files" || cmd.Search.Root != workdir {
		t.Fatalf("unexpected search: %+v", cmd.Search)
	}
}

func TestCacheIsSearchQuery(t *testing.T) {
	cmd, err := Parse([]string{"cache"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindSearch {
		t.Fatalf("cache must parse as a search query, got kind %v", cmd.Kind)
	}
	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Search.Query != "cache" || cmd.Search.Root != workdir {
		t.Fatalf("unexpected search: %+v", cmd.Search)
	}
}

func TestHelpOmitsFilesCommand(t *testing.T) {
	for _, forbidden := range []string{"foco files", "files [root]", "Eligible paths", "End files"} {
		if strings.Contains(Help, forbidden) {
			t.Fatalf("help still mentions %q:\n%s", forbidden, Help)
		}
	}
}

func TestHelpOmitsCacheCommand(t *testing.T) {
	if strings.Contains(Help, "cache clear") {
		t.Fatalf("help still mentions the removed cache command:\n%s", Help)
	}
}

func TestSearchAcceptsPolicyFlags(t *testing.T) {
	cmd, err := Parse([]string{"q", ".", "--hidden", "--no-ignore", "--include-dependencies", "--include-sensitive", "--exclude", "**/*.tmp", "--only", "code", "--exclude-types", "docs"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindSearch {
		t.Fatalf("unexpected kind: %v", cmd.Kind)
	}
	policy := cmd.Search.Policy
	if !policy.Hidden || !policy.NoIgnore || !policy.IncludeDependencies || !policy.IncludeSensitive {
		t.Fatalf("boolean policy flags not set: %+v", policy)
	}
	if len(policy.Exclude) != 1 || policy.Exclude[0] != "**/*.tmp" {
		t.Fatalf("unexpected exclude: %+v", policy.Exclude)
	}
	if len(policy.Only) != 1 || policy.Only[0] != enums.FileCategoryCode {
		t.Fatalf("unexpected only: %+v", policy.Only)
	}
	if len(policy.ExcludeTypes) != 1 || policy.ExcludeTypes[0] != enums.FileCategoryDocs {
		t.Fatalf("unexpected exclude-types: %+v", policy.ExcludeTypes)
	}
}

func TestParseAuth(t *testing.T) {
	cmd, err := Parse([]string{
		"auth", "--schema", "system-one", "--endpoint", "https://gw.example/v1/systemone", "--model", "m", "--stdin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindAuth || cmd.Auth.Schema != enums.SchemaSystemOne ||
		cmd.Auth.Endpoint != "https://gw.example/v1/systemone" || cmd.Auth.Model != "m" {
		t.Fatalf("unexpected auth: %+v", cmd.Auth)
	}
	if _, err := Parse([]string{"auth", "--schema", "system-one"}); err == nil {
		t.Fatal("schema auth without --stdin must fail")
	}
	if _, err := Parse([]string{"auth", "--schema", "system-one", "--stdin"}); err == nil {
		t.Fatal("schema auth without endpoint/model must fail")
	}
}

func TestParseAuthAcceptsSchemaEndpointAndModel(t *testing.T) {
	cmd, err := Parse([]string{
		"auth", "--schema", "openai-decisions", "--endpoint", "https://api.openai.com/v1/decisions",
		"--model", "gpt-6-luna", "--stdin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Kind != KindAuth {
		t.Fatalf("unexpected command: %+v", cmd)
	}
	if _, err := Parse([]string{"auth", "--schema", "openai-decisions", "--stdin"}); err == nil {
		t.Fatal("schema auth without endpoint/model must fail")
	}
	if _, err := Parse([]string{"auth", "--provider", "vercel", "--stdin"}); err == nil {
		t.Fatal("provider presets must not be accepted")
	}
}

func TestParseUsageErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--nope"}, "Unknown option"},
		{[]string{"cache", "clear", "x"}, "Usage: foco \"question\""},
		{[]string{"q", "a", "b"}, "Usage: foco \"question\""},
		{[]string{"--only", "nope", "files"}, "Unknown or empty file category"},
	}
	for _, tc := range cases {
		_, err := Parse(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestUsageMessagesMatchUpstream(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"q", "--concurrency", "0"}, "--concurrency must be a positive integer."},
		{[]string{"q", "--concurrency", "+1"}, "--concurrency must be a positive integer."},
		{[]string{"q", "--parallel", "-1"}, "--parallel must be an integer from 0 (all CPU cores) to 4096."},
		{[]string{"q", "--parallel", "4097"}, "--parallel must be an integer from 0 (all CPU cores) to 4096."},
		{[]string{"q", "--nav-batch-size", "0"}, "--nav-batch-size must be an integer from 1 to 100."},
		{[]string{"q", "--nav-batch-bytes", "37999"}, "--nav-batch-bytes must be an integer from 38000 to 64000."},
		{[]string{"q", "--nav-batch-size", "101"}, "--nav-batch-size must be an integer from 1 to 100."},
		{[]string{"q", "--pipeline", "fast"}, "--pipeline must be classic or outline."},
		{[]string{"q", "--max-requests", "0"}, "--max-requests must be a positive integer."},
		{[]string{"q", "--max-requests", "1e2"}, "--max-requests must be a positive integer."},
		{[]string{"q", "--max-source-bytes=-1"}, "--max-source-bytes must be a nonnegative integer (0 means unlimited)."},
		{[]string{"q", "--max-source-bytes", "1.5"}, "--max-source-bytes must be a nonnegative integer (0 means unlimited)."},
		{[]string{"q", "--max-output-bytes", "255"}, "--max-output-bytes must be 0 (unlimited) or at least 256."},
		{[]string{"q", "--max-output-bytes", "1.5"}, "--max-output-bytes must be 0 (unlimited) or at least 256."},
		{[]string{"q", "--only", "nope"}, "Unknown or empty file category. Choose from: code, config, docs, data, audio, video, archives, logs, temp, unknown."},
		{[]string{"q", "--only", "code,"}, "Unknown or empty file category. Choose from: code, config, docs, data, audio, video, archives, logs, temp, unknown."},
		{[]string{"q", "--exclude", "!keep.ts"}, "--exclude takes one gitignore pattern without a leading ! or # or a trailing unescaped \\."},
		{[]string{"q", "--exclude", "secrets\\"}, "--exclude takes one gitignore pattern without a leading ! or # or a trailing unescaped \\."},
		{[]string{"q", "--stdin"}, `Usage: foco "question" [root]. Run foco --help.`},
		{[]string{"q", "--list"}, `Usage: foco "question" [root]. Run foco --help.`},
		{[]string{"   "}, `Usage: foco "question" [root]. Run foco --help.`},
	}
	for _, tc := range cases {
		_, err := Parse(tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestParallelDefaultsToHalfTheCores(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"q"}, max(1, runtime.NumCPU()/2)},
		{[]string{"q", "--parallel", "3"}, 3},
		{[]string{"q", "--parallel=0"}, runtime.NumCPU()},
	}
	for _, tc := range cases {
		command, err := Parse(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if command.Search.Parallel != tc.want {
			t.Fatalf("%v: parallel = %d, want %d", tc.args, command.Search.Parallel, tc.want)
		}
	}
}

func TestNavigationBatchFlags(t *testing.T) {
	command, err := Parse([]string{"q", "--nav-batch-size", "64", "--nav-batch-bytes=60000"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Search.NavBatchSize != 64 || command.Search.NavBatchBytes != 60000 {
		t.Fatalf("search = %+v", command.Search)
	}
	command, err = Parse([]string{"q"})
	if err != nil || command.Search.NavBatchSize != 0 || command.Search.NavBatchBytes != 0 {
		t.Fatalf("defaults must stay unset: %+v, %v", command.Search, err)
	}
}

func TestOnlyHelpAndVersionAliases(t *testing.T) {
	for _, args := range [][]string{{"-help"}, {"--h"}, {"---help"}, {"-H"}, {"--Help"}} {
		_, err := Parse(args)
		if err == nil || err.Error() != "Unknown option or missing option value. Run foco --help." {
			t.Fatalf("%v: got %v", args, err)
		}
	}
	cases := []struct {
		args []string
		kind Kind
	}{
		{[]string{"-h"}, KindHelp},
		{[]string{"--help"}, KindHelp},
		{[]string{"-v"}, KindVersion},
		{[]string{"--version"}, KindVersion},
	}
	for _, tc := range cases {
		command, err := Parse(tc.args)
		if err != nil || command.Kind != tc.kind {
			t.Fatalf("%v: got %+v, %v", tc.args, command, err)
		}
	}
}

func TestDashPrefixedValuesAreConsumed(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"q", "--concurrency", "-1"}, "--concurrency must be a positive integer."},
		{[]string{"q", "--max-source-bytes", "-1"}, "--max-source-bytes must be a nonnegative integer (0 means unlimited)."},
		{[]string{"auth", "--schema", "--stdin"}, "Use auth --schema system-one|gemini-decisions|openai-decisions --endpoint URL --model ID --stdin for a piped key."},
		{[]string{"q", "--only", "--help"}, "Unknown or empty file category. Choose from: code, config, docs, data, audio, video, archives, logs, temp, unknown."},
	}
	for _, tc := range cases {
		_, err := Parse(tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
	command, err := Parse([]string{"q", "--exclude", "-pattern"})
	if err != nil {
		t.Fatalf("--exclude must accept a dash-prefixed value: %v", err)
	}
	if len(command.Search.Policy.Exclude) != 1 || command.Search.Policy.Exclude[0] != "-pattern" {
		t.Fatalf("unexpected exclude: %+v", command.Search.Policy.Exclude)
	}
	if _, err := Parse([]string{"q", "--exclude=-pattern"}); err != nil {
		t.Fatalf("= form must accept a dash-prefixed value: %v", err)
	}
}

func TestPositiveIntCapsAtPlatformMax(t *testing.T) {
	const value = "4294967296"
	n, err := positiveInt("concurrency", value)
	if strconv.IntSize == 32 {
		if err == nil {
			t.Fatalf("positiveInt accepted %s on a 32-bit int", value)
		}
		if err.Error() != "--concurrency must be a positive integer." {
			t.Fatalf("error %q", err)
		}
		return
	}
	if err != nil || n != 4294967296 {
		t.Fatalf("positiveInt(%q) = %d, %v", value, n, err)
	}
	if _, err := positiveInt("concurrency", "9007199254740992"); err == nil {
		t.Fatal("positiveInt accepted a value above 2^53-1")
	}
}

func TestExcludeAcceptsEvenTrailingBackslashes(t *testing.T) {
	for _, pattern := range []string{"secrets\\\\", "secrets\\\\\\\\"} {
		command, err := Parse([]string{"q", "--exclude", pattern})
		if err != nil {
			t.Fatalf("%q: %v", pattern, err)
		}
		if len(command.Search.Policy.Exclude) != 1 || command.Search.Policy.Exclude[0] != pattern {
			t.Fatalf("%q: %+v", pattern, command.Search.Policy.Exclude)
		}
	}
}

func TestSearchRootDefaultsToCwd(t *testing.T) {
	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	command, err := Parse([]string{"q"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Search.Root != workdir {
		t.Fatalf("root = %q, want %q", command.Search.Root, workdir)
	}
}
