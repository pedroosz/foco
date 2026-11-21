package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestHelpMatchesGolden(t *testing.T) {
	golden, err := os.ReadFile("testdata/help.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--help"}, {"-h"}} {
		var output, errorOutput bytes.Buffer
		if code := Run(args, &output, &errorOutput); code != 0 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if output.String() != string(golden) {
			t.Fatalf("%v: help mismatch\n--- got ---\n%s\n--- want ---\n%s", args, output.String(), string(golden))
		}
		if errorOutput.Len() != 0 {
			t.Fatalf("%v: stderr %q", args, errorOutput.String())
		}
	}
}

func TestHelpCoversPhaseFourSurface(t *testing.T) {
	for _, required := range []string{
		"auth --schema system-one|gemini-decisions|openai-decisions",
		"system-one is Jev/Clef-compatible.",
		"schema and is used as the exact POST URL; no provider presets are configured.",
		"Skill installation requires Node 22.20+ (skills@1.7.0), npm/npx, and network access.",
		"--agent NAME",
		"--global",
		"--yes",
		"--max-requests N",
		"--max-source-bytes N",
		"--max-output-bytes N",
		"--no-locations",
		"--hidden",
		"--no-ignore",
		"--include-dependencies",
		"--include-sensitive",
		"--only TYPES",
		"--exclude-types TYPES",
		"--exclude PATTERN",
		"--no-cache",
		"--concurrency N",
		"--parallel N",
		"--nav-batch-size N",
		"--nav-batch-bytes N",
		"--pipeline NAME",
		"File categories: code, config, docs, data, audio, video, archives, logs, temp, unknown.",
		"130 interrupted.",
	} {
		if !strings.Contains(Help, required) {
			t.Fatalf("help missing %q", required)
		}
	}
	for _, forbidden := range []string{"foco files", "files [root]", "Eligible paths", "End files", "cache clear"} {
		if strings.Contains(Help, forbidden) {
			t.Fatalf("help must not advertise cancelled command: %q", forbidden)
		}
	}
}
