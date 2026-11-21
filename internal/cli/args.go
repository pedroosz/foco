package cli

import (
	"errors"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"foco/internal/enums"
	"foco/internal/filetypes"
)

type Kind int

const (
	KindHelp Kind = iota
	KindVersion
	KindAuth
	KindDoctor
	KindSkill
	KindSearch
)

type PolicyOptions struct {
	Hidden              bool
	NoIgnore            bool
	IncludeDependencies bool
	IncludeSensitive    bool
	Exclude             []string
	Only                []enums.FileCategory
	ExcludeTypes        []enums.FileCategory
}

type AuthOptions struct {
	Schema   enums.Schema
	Endpoint string
	Model    string
	Stdin    bool
}

type SkillOptions struct {
	Agents []string
	Global bool
	Yes    bool
}

type SearchOptions struct {
	Query          string
	Root           string
	NoCache        bool
	Concurrency    int
	Parallel       int
	NavBatchSize   int
	Pipeline       string
	NavBatchBytes  int
	MaxRequests    int
	MaxSourceBytes int64
	MaxOutputBytes int64
	NoLocations    bool
	Policy         PolicyOptions
}

type Command struct {
	Kind   Kind
	Auth   AuthOptions
	Skill  SkillOptions
	Search SearchOptions
}

type rawArgs struct {
	values      map[string][]string
	positionals []string
}

func (r rawArgs) has(name string) bool { _, ok := r.values[name]; return ok }
func (r rawArgs) one(name string) string {
	v := r.values[name]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{Kind: KindHelp}, nil
	}
	if token, ok := aloneArg(args); ok {
		switch {
		case isHelpToken(token):
			return Command{Kind: KindHelp}, nil
		case isVersionToken(token):
			return Command{Kind: KindVersion}, nil
		}
	}
	if containsHelpOrVersion(args) {
		return Command{}, usageError("Use --help or --version alone.")
	}
	var command Command
	root := newRootCommand(&command)
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err != nil {
		return Command{}, err
	}
	return command, nil
}

func aloneArg(args []string) (string, bool) {
	trimmed := args
	if len(trimmed) > 0 && trimmed[len(trimmed)-1] == "--" {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if len(trimmed) != 1 {
		return "", false
	}
	return trimmed[0], true
}

func isHelpToken(arg string) bool    { return arg == "--help" || arg == "-h" }
func isVersionToken(arg string) bool { return arg == "--version" || arg == "-v" }

// valueFlagNames lets the help/version-alone check skip values that belong to
// another flag, matching the way pflag consumes a following token.
var valueFlagNames = map[string]bool{
	"schema": true, "endpoint": true, "model": true, "agent": true,
	"concurrency": true, "parallel": true, "nav-batch-size": true, "nav-batch-bytes": true, "pipeline": true, "max-requests": true, "max-source-bytes": true,
	"max-output-bytes": true, "exclude": true, "only": true, "exclude-types": true,
}

func containsHelpOrVersion(args []string) bool {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			return false
		}
		if isHelpToken(arg) || isVersionToken(arg) {
			return true
		}
		if strings.HasPrefix(arg, "--") && !strings.Contains(arg, "=") {
			if valueFlagNames[strings.TrimPrefix(arg, "--")] && index+1 < len(args) {
				index++
			}
		}
	}
	return false
}

func newRootCommand(target *Command) *cobra.Command {
	root := &cobra.Command{
		Use:                `foco "question" [root]`,
		Args:               cobra.ArbitraryArgs,
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsed, err := parseSearch(searchRaw(cmd, args))
			if err != nil {
				return err
			}
			*target = parsed
			return nil
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(*cobra.Command, error) error {
		return usageError("Unknown option or missing option value. Run foco --help.")
	})
	flags := root.Flags()
	flags.String("concurrency", "", "")
	flags.String("parallel", "", "")
	flags.String("nav-batch-size", "", "")
	flags.String("pipeline", "", "")
	flags.String("nav-batch-bytes", "", "")
	flags.String("max-requests", "", "")
	flags.String("max-source-bytes", "", "")
	flags.String("max-output-bytes", "", "")
	flags.Bool("no-cache", false, "")
	flags.Bool("no-locations", false, "")
	flags.Bool("hidden", false, "")
	flags.Bool("no-ignore", false, "")
	flags.Bool("include-dependencies", false, "")
	flags.Bool("include-sensitive", false, "")
	flags.StringArray("only", nil, "")
	flags.StringArray("exclude-types", nil, "")
	flags.StringArray("exclude", nil, "")
	flags.Bool("stdin", false, "")
	flags.Bool("list", false, "")
	_ = flags.MarkHidden("stdin")
	_ = flags.MarkHidden("list")
	root.AddCommand(newAuthCommand(target), newDoctorCommand(target), newSkillCommand(target))
	return root
}

func newAuthCommand(target *Command) *cobra.Command {
	cmd := &cobra.Command{
		Use: "auth",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageError("Usage: foco auth OR foco auth --schema NAME --endpoint URL --model ID --stdin")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			raw := rawArgs{values: map[string][]string{}, positionals: append([]string{"auth"}, args...)}
			collectString(&raw, cmd, "schema")
			collectString(&raw, cmd, "endpoint")
			collectString(&raw, cmd, "model")
			collectBool(&raw, cmd, "stdin")
			parsed, err := parseAuth(raw)
			if err != nil {
				return err
			}
			*target = parsed
			return nil
		},
	}
	cmd.Flags().String("schema", "", "")
	cmd.Flags().String("endpoint", "", "")
	cmd.Flags().String("model", "", "")
	cmd.Flags().Bool("stdin", false, "")
	return cmd
}

func newDoctorCommand(target *Command) *cobra.Command {
	return &cobra.Command{
		Use: "doctor",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageError("This command takes no arguments.")
			}
			return nil
		},
		RunE: func(*cobra.Command, []string) error {
			*target = Command{Kind: KindDoctor}
			return nil
		},
	}
}

func newSkillCommand(target *Command) *cobra.Command {
	cmd := &cobra.Command{
		Use: "skill",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageError("Usage: foco skill [--agent NAME] [--global] [--yes]")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			raw := rawArgs{values: map[string][]string{}, positionals: append([]string{"skill"}, args...)}
			collectArray(&raw, cmd, "agent")
			collectBool(&raw, cmd, "global")
			collectBool(&raw, cmd, "yes")
			parsed, err := parseSkill(raw)
			if err != nil {
				return err
			}
			*target = parsed
			return nil
		},
	}
	cmd.Flags().StringArray("agent", nil, "")
	cmd.Flags().Bool("global", false, "")
	cmd.Flags().Bool("yes", false, "")
	return cmd
}

func searchRaw(cmd *cobra.Command, positionals []string) rawArgs {
	raw := rawArgs{values: map[string][]string{}, positionals: positionals}
	for _, name := range []string{
		"no-cache", "no-locations", "hidden", "no-ignore",
		"include-dependencies", "include-sensitive", "stdin", "list",
	} {
		collectBool(&raw, cmd, name)
	}
	for _, name := range []string{"concurrency", "parallel", "nav-batch-size", "nav-batch-bytes", "pipeline", "max-requests", "max-source-bytes", "max-output-bytes"} {
		collectString(&raw, cmd, name)
	}
	for _, name := range []string{"exclude", "only", "exclude-types"} {
		collectArray(&raw, cmd, name)
	}
	return raw
}

func collectString(raw *rawArgs, cmd *cobra.Command, name string) {
	if !cmd.Flags().Changed(name) {
		return
	}
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		return
	}
	raw.values[name] = append(raw.values[name], value)
}

func collectBool(raw *rawArgs, cmd *cobra.Command, name string) {
	if !cmd.Flags().Changed(name) {
		return
	}
	value, err := cmd.Flags().GetBool(name)
	if err != nil || !value {
		return
	}
	raw.values[name] = append(raw.values[name], "true")
}

func collectArray(raw *rawArgs, cmd *cobra.Command, name string) {
	if !cmd.Flags().Changed(name) {
		return
	}
	values, err := cmd.Flags().GetStringArray(name)
	if err != nil {
		return
	}
	raw.values[name] = append(raw.values[name], values...)
}

func parseAuth(raw rawArgs) (Command, error) {
	if len(raw.positionals) != 1 {
		return Command{}, usageError("Usage: foco auth OR foco auth --schema NAME --endpoint URL --model ID --stdin")
	}
	for key := range raw.values {
		if key != "stdin" && key != "schema" && key != "endpoint" && key != "model" {
			return Command{}, usageError("Usage: foco auth OR foco auth --schema NAME --endpoint URL --model ID --stdin")
		}
	}
	if len(raw.values) == 0 {
		return Command{Kind: KindAuth}, nil
	}
	schema, validSchema := enums.NewSchema(raw.one("schema"))
	if !raw.has("stdin") || !validSchema {
		return Command{}, usageError("Use auth --schema system-one|gemini-decisions|openai-decisions --endpoint URL --model ID --stdin for a piped key.")
	}
	endpoint, model := raw.one("endpoint"), raw.one("model")
	if endpoint == "" || model == "" {
		return Command{}, usageError("All schemas need --endpoint URL and --model ID with --stdin.")
	}
	return Command{Kind: KindAuth, Auth: AuthOptions{Schema: schema, Endpoint: endpoint, Model: model, Stdin: true}}, nil
}

func parseSkill(raw rawArgs) (Command, error) {
	if len(raw.positionals) != 1 {
		return Command{}, usageError("Usage: foco skill [--agent NAME] [--global] [--yes]")
	}
	for key := range raw.values {
		if key != "agent" && key != "global" && key != "yes" {
			return Command{}, usageError("Usage: foco skill [--agent NAME] [--global] [--yes]")
		}
	}
	agents := raw.values["agent"]
	for _, a := range agents {
		if a == "" || a[0] < 'a' || a[0] > 'z' {
			return Command{}, usageError("Usage: foco skill [--agent NAME] [--global] [--yes]")
		}
		for _, r := range a[1:] {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return Command{}, usageError("Usage: foco skill [--agent NAME] [--global] [--yes]")
			}
		}
	}
	return Command{Kind: KindSkill, Skill: SkillOptions{Agents: agents, Global: raw.has("global"), Yes: raw.has("yes")}}, nil
}

func parseSearch(raw rawArgs) (Command, error) {
	if len(raw.positionals) == 0 || strings.TrimSpace(raw.positionals[0]) == "" {
		return Command{}, usageError(`Usage: foco "question" [root]. Run foco --help.`)
	}
	if len(raw.positionals) > 2 {
		return Command{}, usageError(`Usage: foco "question" [root]. Run foco --help.`)
	}
	if raw.has("stdin") || raw.has("list") {
		return Command{}, usageError(`Usage: foco "question" [root]. Run foco --help.`)
	}
	for key := range raw.values {
		if !isPolicyFlag(key) && key != "no-cache" && key != "concurrency" && key != "parallel" && key != "nav-batch-size" && key != "nav-batch-bytes" && key != "pipeline" && key != "max-requests" &&
			key != "max-source-bytes" && key != "max-output-bytes" && key != "no-locations" {
			return Command{}, usageError(`Usage: foco "question" [root]. Run foco --help.`)
		}
	}
	root := cwd()
	if len(raw.positionals) == 2 {
		root = raw.positionals[1]
	}
	search := SearchOptions{
		Query: raw.positionals[0], Root: root, NoCache: raw.has("no-cache"),
		Concurrency: 32, Parallel: DefaultParallel(), MaxRequests: 1000, MaxOutputBytes: 256000,
		NoLocations: raw.has("no-locations"),
	}
	var err error
	if raw.has("concurrency") {
		search.Concurrency, err = positiveInt("concurrency", raw.one("concurrency"))
		if err != nil {
			return Command{}, err
		}
	}
	if raw.has("parallel") {
		value, parseErr := digits(raw.one("parallel"))
		if parseErr != nil || value > 4096 {
			return Command{}, usageError("--parallel must be an integer from 0 (all CPU cores) to 4096.")
		}
		search.Parallel = int(value)
		if search.Parallel == 0 {
			search.Parallel = runtime.NumCPU()
		}
	}
	search.Pipeline = "classic"
	if raw.has("pipeline") {
		switch value := raw.one("pipeline"); value {
		case "classic", "outline":
			search.Pipeline = value
		default:
			return Command{}, usageError("--pipeline must be classic or outline.")
		}
	}
	if raw.has("nav-batch-size") {
		value, parseErr := digits(raw.one("nav-batch-size"))
		if parseErr != nil || value < 1 || value > maxNavBatchSize {
			return Command{}, usageError("--nav-batch-size must be an integer from 1 to 100.")
		}
		search.NavBatchSize = int(value)
	}
	if raw.has("nav-batch-bytes") {
		value, parseErr := digits(raw.one("nav-batch-bytes"))
		if parseErr != nil || value < minNavBatchBytes || value > maxNavBatchBytes {
			return Command{}, usageError("--nav-batch-bytes must be an integer from 38000 to 64000.")
		}
		search.NavBatchBytes = int(value)
	}
	if raw.has("max-requests") {
		search.MaxRequests, err = positiveInt("max-requests", raw.one("max-requests"))
		if err != nil {
			return Command{}, err
		}
	}
	if raw.has("max-source-bytes") {
		search.MaxSourceBytes, err = nonNegativeInt64("max-source-bytes", raw.one("max-source-bytes"))
		if err != nil {
			return Command{}, err
		}
	}
	if raw.has("max-output-bytes") {
		search.MaxOutputBytes, err = outputBytes(raw.one("max-output-bytes"))
		if err != nil {
			return Command{}, err
		}
	}
	policy, err := policyFrom(raw)
	if err != nil {
		return Command{}, err
	}
	search.Policy = policy
	return Command{Kind: KindSearch, Search: search}, nil
}

// Navigation batch limits. Below the default byte limit, single file previews
// no longer fit one request and would be chunked or dropped. The maximums keep
// a request within Jev's 100 questions and 32K-token context.
const (
	maxNavBatchSize  = 100
	minNavBatchBytes = 38_000
	maxNavBatchBytes = 64_000
)

// DefaultParallel is the CPU cores a search uses by default: half of them, so
// a search never saturates the machine it runs on.
func DefaultParallel() int {
	return max(1, runtime.NumCPU()/2)
}

func isPolicyFlag(key string) bool {
	switch key {
	case "hidden", "no-ignore", "include-dependencies", "include-sensitive", "exclude", "only", "exclude-types":
		return true
	}
	return false
}

func policyFrom(raw rawArgs) (PolicyOptions, error) {
	patterns := append([]string{}, raw.values["exclude"]...)
	for _, pattern := range patterns {
		if invalidExcludePattern(pattern) {
			return PolicyOptions{}, usageError(`--exclude takes one gitignore pattern without a leading ! or # or a trailing unescaped \.`)
		}
	}
	only, err := parseTypes(raw.values["only"])
	if err != nil {
		return PolicyOptions{}, err
	}
	excluded, err := parseTypes(raw.values["exclude-types"])
	if err != nil {
		return PolicyOptions{}, err
	}
	slices.Sort(patterns)
	patterns = slices.Compact(patterns)
	return PolicyOptions{
		Hidden: raw.has("hidden"), NoIgnore: raw.has("no-ignore"),
		IncludeDependencies: raw.has("include-dependencies"), IncludeSensitive: raw.has("include-sensitive"),
		Exclude: patterns, Only: only, ExcludeTypes: excluded,
	}, nil
}

func invalidExcludePattern(pattern string) bool {
	if strings.TrimSpace(pattern) == "" {
		return true
	}
	if strings.HasPrefix(pattern, "!") || strings.HasPrefix(pattern, "#") {
		return true
	}
	if strings.ContainsAny(pattern, "\r\n") {
		return true
	}
	count := 0
	for index := len(pattern) - 1; index >= 0 && pattern[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func parseTypes(values []string) ([]enums.FileCategory, error) {
	var out []enums.FileCategory
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			category, ok := enums.NewFileCategory(part)
			if !ok {
				allowed := filetypes.All()
				names := make([]string, len(allowed))
				for index, category := range allowed {
					names[index] = category.String()
				}
				return nil, usageError("Unknown or empty file category. Choose from: " + strings.Join(names, ", ") + ".")
			}
			out = append(out, category)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

const (
	maxSafeInteger = int64(1<<53 - 1)
	maxInt         = int(^uint(0) >> 1)
)

func digits(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("empty")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("not digits")
		}
	}
	return strconv.ParseInt(value, 10, 64)
}

func positiveInt(flag, value string) (int, error) {
	n, err := digits(value)
	if err != nil || n < 1 || n > maxSafeInteger || n > int64(maxInt) {
		return 0, usageError("--" + flag + " must be a positive integer.")
	}
	return int(n), nil
}

func nonNegativeInt64(flag, value string) (int64, error) {
	n, err := digits(value)
	if err != nil || n > maxSafeInteger {
		return 0, usageError("--" + flag + " must be a nonnegative integer (0 means unlimited).")
	}
	return n, nil
}

func outputBytes(value string) (int64, error) {
	n, err := digits(value)
	if err != nil || n > maxSafeInteger || (n != 0 && n < 256) {
		return 0, usageError("--max-output-bytes must be 0 (unlimited) or at least 256.")
	}
	return n, nil
}

func cwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}
