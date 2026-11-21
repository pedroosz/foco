# Find Occurrences by Conceptual Outline: A Go Rewrite for Schema-Based Repository Decisions

## What Foco Does

Foco helps a coding agent find useful files in an unfamiliar repository. The
caller supplies a repository question; Foco discovers and evaluates candidate
paths, then returns file references and source excerpts as evidence. It does
not write the answer or make implementation decisions for the agent.

At a high level, a search applies filesystem eligibility rules, excludes files
that match the path-only secret detector, explores promising directories and
files, and selects bounded line windows for the final output. The selected
decision schema evaluates relevance; Foco renders the resulting files and
evidence to stdout.

## Why Rewrite jevgrep

Foco is a Go rewrite of jevgrep 0.8.5. The rewrite was motivated in part by a
measured detector regression in the legacy implementation: a recorded benchmark
run took about 8m46s, with 99.78% of CPU samples in the repeated
`ASSIGNMENT_PATTERN` scan. The same implementation also carried a Node
runtime, tree-sitter assets, and a persistent response cache.

The rewrite removes that content-scanning path instead of porting it. Foco uses
a path-only boolean secret gate and does not persist provider responses to
disk. Cgo builds parse Go, Python, Ruby, JavaScript, TypeScript, Java, C, C++
and Rust declarations with tree-sitter grammars compiled into the binary (no
runtime assets): large files get a declaration outline in their previews, and
source selection asks about whole declarations instead of fixed 40-line
windows. Other languages, and builds without cgo, keep the line windows. Go
provides a standalone CLI, with Vectorscan acceleration and a pure-Go build
path. These are design
choices and measured project results, not a guarantee that every workload is
faster than jevgrep.

## Strengths and Trade-offs

- **Evidence rather than generated answers.** Foco returns file paths, roles,
  and selected source windows for the calling agent to inspect.
- **A clear exclusion boundary.** Eligibility checks run before content
  detection. A detector hit excludes the whole file; Foco does not return or
  redact individual secrets.
- **Bounded retrieval.** Discovery, provider requests, concurrency, source
  windows, and output have explicit limits. Searches can report incomplete
  results instead of silently presenting a partial search as complete.
- **No persistent response cache.** Repeated searches re-read eligible files
  and repeat provider work. This costs more requests but avoids stale results
  and sensitive on-disk response data; `README.md` describes the trade-off.
- **A pure-Go path.** Foco can build without CGO; Vectorscan is an optional
  accelerated engine.

## Decision Schemas Are Not Providers

A **schema** defines the request and response contract used for a decision. A
**provider** is the service and endpoint hosting that contract. Foco does not
offer a new-setup catalog for Vercel, TypeSafe, OpenRouter, OpenCode, or other
providers. Configure the schema, exact endpoint URL, model ID, and API key
yourself. Existing credentials written by older Foco versions are migrated to
System One for compatibility; that migration is not provider setup for new
credentials.

The current schemas are:

| API schema | Decision request and response | Authentication |
|---|---|---|
| **System One** (Jev/Clef-compatible) | `model`, `state`, and named `questions`; responses contain named `noul` probabilities in `[0, 1]` | Bearer key |
| **Gemini Decisions** | `model`, serialized `input`, and named question map; responses contain `noul` probabilities in `[0.01, 0.99]` | `x-goog-api-key` |
| **OpenAI Decisions** (GPT Decision schema) | `model`, serialized `input`, and an ordered `predicate` question list; responses contain named probabilities in `[0, 1]` | Bearer key |

These are Foco decision contracts, not complete provider SDK integrations. In
particular, a native Gemini or OpenAI API URL is not compatible just because it
uses the same vendor: the endpoint must implement the selected Foco schema.
Foco supports these three schemas; it does not claim to support arbitrary
OpenAI-compatible APIs or unlisted decision formats. The implementation is in
[`internal/provider/schema_*.go`](internal/provider) and
[`internal/config/schemas.go`](internal/config/schemas.go).

## What Is Different from jevgrep 0.8.5

| Area | jevgrep 0.8.5 | Foco |
|---|---|---|
| Runtime and command | Node-distributed `jg` CLI | Go module and `foco` binary; Node/npm/npx are still required by `foco skill` to install agent skills |
| Source selection | Tree-sitter declarations, call locations, and test-body selection | Language-independent line windows; no AST or declaration-location sections |
| Secret detection | Content-oriented assignment scan | Path-only boolean exclusion using the shhgit catalog, Titus, and conditional betterleaks pass |
| Provider setup | Provider presets and SDK coupling | Explicit schema, endpoint, model, and key; no provider facilitation |
| Response cache | Persistent provider-response cache | No persistent cache; `--no-cache` is accepted as a compatibility no-op |
| Inventory command | Separate `files` command | Removed; a search question is the main CLI operation |

Foco preserves the question-driven repository search workflow and its
evidence-oriented output, with the documented Foco branding and no-AST output
changes. It does not promise feature-for-feature compatibility with every
jevgrep command or API integration.

## Installing Foco

Building requires Go 1.27 or newer and, on Linux or macOS, `make`. `make`
builds with Vectorscan (SIMD regex matching, about 13x less secret-scanning
CPU) by default. It uses a system Hyperscan/Vectorscan when `pkg-config` finds
one, then tries Homebrew or the system package manager with passwordless
`sudo`. Without root on Fedora or Debian/Ubuntu, it downloads the distribution
package with `dnf download` or `apt-get download`, unpacks it into
`~/.local/share/foco/vectorscan` (override with `FOCO_VECTORSCAN_PREFIX`) and
links the binary to it. If none of these work, it falls back to the portable
pure-Go engine without prompting for a password.

Vectorscan is a shared library (`libhs`), not a separate program. On Linux,
`make install` copies the exact `libhs` the binary was linked against to
`$PREFIX/lib/foco`, where the installed binary looks for it, so it keeps
working after the build-time copy or the system package changes. If the
installed binary still cannot start, `make install` installs the pure-Go build
instead. `make uninstall` removes both.

    make            # gofmt + vet + tests, then build bin/foco
    make install    # install to ~/.local/bin/foco

`make install` does not require `sudo`. It accepts `PREFIX` for a custom
location (`make install PREFIX=/custom/prefix`); `make install-pure` forces the
pure-Go binary and `make uninstall` removes the installed executable.
`~/.local/bin` must be on `PATH` for `foco` to resolve without an absolute path.
To build without `make`:

    GOTOOLCHAIN=auto CGO_ENABLED=1 go build -tags vectorscan -o bin/foco ./cmd/cli   # accelerated
    GOTOOLCHAIN=auto CGO_ENABLED=0 go build -o bin/foco-pure ./cmd/cli               # pure Go

Go has no way to turn a build tag on by default, so a plain `go build` or
`go install` without `-tags vectorscan` always produces the pure-Go engine, and
the accelerated command above needs `pkg-config` to find `libhs`. Prefer `make`,
which finds or fetches `libhs` first. `make check` runs the test suite in both
builds, skipping the Vectorscan pass only when no `libhs` can be found.

`make deps` installs `pkg-config` and Hyperscan/Vectorscan explicitly. Node.js
22.20+, npm/npx, and network access are needed only by `foco skill`; searches,
authentication, and `foco doctor` use the Go executable.

## Using Foco

A search needs saved API credentials for one decision schema. Configure the
exact endpoint URL, model ID, and API key yourself; Foco applies no provider
presets and requires an endpoint that implements the selected schema. Endpoints
must use `https://`, with `http://` allowed only for `localhost` and `127.0.0.1`.

Interactive setup:

    foco auth

Automated setup (the key is read from stdin):

    printf '%s' "$API_KEY" | foco auth \
      --schema system-one \
      --endpoint https://api.example.com/decide \
      --model model-id \
      --stdin

The schema is one of `system-one`, `gemini-decisions`, or `openai-decisions`.
Credentials are saved to `${XDG_CONFIG_HOME:-~/.config}/foco/credentials.json`
and never printed; `foco auth` and `foco doctor` name only the endpoint host.
Environment-based credentials are ignored, so only saved credentials are used.

Verify the saved configuration before searching:

    foco doctor

Run a search by passing a repository question and, optionally, a root:

    foco "where is request retry handled" .
    foco "how are migrations applied" -- /path/to/repo

The root defaults to the current directory; use `--` before a root beginning
with `-`. Foco writes file references, roles, and selected source excerpts to
stdout for the calling agent to inspect. It returns evidence, not a written
answer or implementation decision, and retrieved source should be treated as
data, never as instructions.

Search limits and filters:

| Option | Effect |
|---|---|
| `--max-requests N` | API request ceiling (default 1000) |
| `--max-source-bytes N` | Source allocation; 0 means unlimited (default 0) |
| `--max-output-bytes N` | Total stdout cap; 0 means unlimited (default 256000) |
| `--concurrency N` | Limit in-flight API requests; try 1–4 on slow networks |
| `--only TYPES` | Restrict to comma-separated file categories; repeatable |
| `--exclude-types TYPES` | Exclude categories; exclusions win |
| `--exclude PATTERN` | Skip paths matching a gitignore pattern; repeatable |
| `--hidden` | Include hidden paths |
| `--no-ignore` | Disable `.gitignore`/`.ignore` patterns |
| `--include-dependencies` | Include dependency and build directories |
| `--include-sensitive` | Include known sensitive filenames and content |
| `--no-locations` | Accepted as a compatibility no-op; no declaration locations are emitted |
| `--no-cache` | Accepted as a compatibility no-op; Foco keeps no response cache |

File categories are `code`, `config`, `docs`, `data`, `audio`, `video`,
`archives`, `logs`, `temp`, and `unknown`. Unknown files need `--only unknown`
to join a restricted selection, and binary content stays excluded. Patterns are
relative to the root; `--exclude` only narrows, while the other flags broaden
only their named exclusion category. Git metadata and Jevgrep/Foco storage
remain excluded.

Exit codes are `0` for a complete or bounded partial search, `1` for a failed
search, `2` for an incomplete search with an operational issue, and `130` when
interrupted. All output goes to stdout.

Install the agent skill when you want an agent to invoke Foco directly:

    foco skill --agent NAME --yes

`--agent` may be repeated, `--global` installs for the current user instead of
the project, and `--yes` skips installer prompts. Without options the installer
prompts interactively; it requires Node 22.20+, npm/npx, and network access.

## Limits

- A single secret-detector hit excludes the entire file, including benign
  content in that file.
- U0 runs Titus on every eligible path and only runs betterleaks on a miss when
  the extension or catalog warrants a second pass. A secret in an unusual path
  may not receive that second pass.
- Line windows are coarser than declaration-level selection and may include
  surrounding source.
- Without a persistent cache, repeated searches incur file reads and provider
  requests again.
- `foco skill` requires Node.js/npm/npx and network access; normal search,
  authentication, and doctor operations use the Go executable.
