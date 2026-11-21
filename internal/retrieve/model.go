package retrieve

import (
	"context"
	"path/filepath"
	"sync"

	"foco/internal/enums"
	"foco/internal/files"
	"foco/internal/provider"
)

const (
	StageWorkers          = 32
	RelevanceBoundary     = 0.5
	WeakScoreCeiling      = 0.6
	MinimumPositiveScores = 32
	NavigationByteBudget  = 8_000_000
	SourceInspectionLimit = 1_000_000
	PreviewBytes          = 16_384
	// OutlineOpeningBytes is how much opening source an outlined preview keeps.
	OutlineOpeningBytes    = 4_096
	PreviewJSONBytes       = 24_000
	PreviewSampleJSONBytes = 28_000
	NavigationBatchSize    = 100
	NavigationBatchBytes   = 38_000
	SelectionBatchSize     = 128
	// MaxQuestionsPerRequest is the most questions one request may carry.
	// Command Code's Jev endpoint rejects larger requests with HTTP 400, and
	// navigation requests are not split on a 400, so their items were lost.
	MaxQuestionsPerRequest = 100
	// SelectionGroupSourceBytes caps the source one selection request carries,
	// and SelectionStateBytes its whole serialized state. Jev's context is 32K
	// tokens for the state plus the longest question; indented code measured
	// close to one token per byte, and a 42 KB group was rejected.
	SelectionGroupSourceBytes = 30_000
	SelectionStateBytes       = 40_000
	EvidenceBytes             = 64_000
	SourceConfidenceBoundary  = 0.7
	DiscoveryLimit            = 100_000
	WholeFileContextBytes     = 16_000
	WindowLines               = 40
	WindowOverlap             = 10
	WindowMaxBytes            = 24_000
)

type Issue struct {
	Kind  enums.RetrievalIssueCode
	Count int
}

type Counts struct {
	Requests       int
	CacheHits      int
	InspectedFiles int
}

type RepositoryContext struct {
	InstructionFiles            []string
	InstructionLookupIncomplete bool
}

type Range struct {
	StartLine int
	EndLine   int
}

type EvidenceRange struct {
	StartLine       int
	EndLine         int
	SourceByteStart *int
	SourceByteEnd   *int
}

type Excerpt struct {
	Range           EvidenceRange
	Source          string
	SourceByteStart *int
	SourceByteEnd   *int
	Partial         bool
}

type SourceDecision struct {
	Range EvidenceRange
	Score float64
}

type FileEvidence struct {
	Path                 string
	ContentHash          string
	Score                float64
	Priority             *float64
	Roles                []enums.AssessmentRole
	Selected             []EvidenceRange
	Rendered             []EvidenceRange
	Excerpts             []Excerpt
	PresentationExcerpts []Excerpt
	PresentationSelected []EvidenceRange
	SourceDecisions      []SourceDecision
	SourceOmitted        bool
}

type RetrievalResult struct {
	Root              string
	Query             string
	Status            enums.RetrievalStatus
	Files             []FileEvidence
	Issues            []Issue
	ProviderFailure   string
	Warnings          []Issue
	RepositoryContext RepositoryContext
	Counts            Counts
}

type ProgressSnapshot struct {
	Files int
	Bytes int
}

type Donor struct {
	Path        string
	ContentHash string
}

type Evaluator interface {
	Requests() int
	Evaluate(ctx context.Context, request provider.Request, options provider.EvalOptions) (map[string]float64, error)
}

type Reader interface {
	Root() string
	ListPage(ctx context.Context, path string, offset int) (files.Page, error)
	ReadSnapshotReuse(ctx context.Context, path string) files.SnapshotResult
	LookupFile(ctx context.Context, path string) (files.LookupResult, error)
}

type issueSet struct {
	mu              sync.Mutex
	order           []enums.RetrievalIssueCode
	counts          map[enums.RetrievalIssueCode]int
	providerFailure string
}

func (s *issueSet) add(kind enums.RetrievalIssueCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(kind)
}

func (s *issueSet) addLocked(kind enums.RetrievalIssueCode) {
	if !kind.IsValid() {
		return
	}
	if s.counts == nil {
		s.counts = make(map[enums.RetrievalIssueCode]int)
	}
	if _, ok := s.counts[kind]; !ok {
		s.order = append(s.order, kind)
	}
	s.counts[kind]++
}

func (s *issueSet) addProvider(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.providerFailure == "" {
		s.providerFailure = message
	}
	s.addLocked(enums.IssueCodeProvider)
}

func (s *issueSet) list() []Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Issue, 0, len(s.order))
	for _, kind := range s.order {
		out = append(out, Issue{Kind: kind, Count: s.counts[kind]})
	}
	return out
}

func (s *issueSet) has(kind enums.RetrievalIssueCode) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.counts[kind]
	return ok
}

func (s *issueSet) fatal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kind := range s.order {
		if fatalIssue(kind) {
			return true
		}
	}
	return false
}

func (s *issueSet) failureMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.providerFailure
}

func fatalIssue(kind enums.RetrievalIssueCode) bool {
	switch kind {
	case enums.IssueCodeAuthentication, enums.IssueCodeRequestLimit, enums.IssueCodeCancelled, enums.IssueCodeInterrupted:
		return true
	}
	return false
}

func retrievalIssueForFileIssue(kind enums.FileIssueKind) enums.RetrievalIssueCode {
	switch kind {
	case enums.FileIssueUnreadable:
		return enums.IssueCodeUnreadable
	case enums.FileIssueChanged:
		return enums.IssueCodeChanged
	case enums.FileIssueResourceLimit:
		return enums.IssueCodeResourceLimit
	case enums.FileIssueInterrupted:
		return enums.IssueCodeInterrupted
	case enums.FileIssueDetector:
		return enums.IssueCodeDetector
	default:
		return enums.UnknownRetrievalIssueCode
	}
}

func retrievalIssueForProviderFailure(kind enums.ProviderFailureKind) enums.RetrievalIssueCode {
	switch kind {
	case enums.FailureAuthentication:
		return enums.IssueCodeAuthentication
	case enums.FailureRequestLimit:
		return enums.IssueCodeRequestLimit
	case enums.FailureProvider:
		return enums.IssueCodeProvider
	case enums.FailureCancelled:
		return enums.IssueCodeCancelled
	default:
		return enums.UnknownRetrievalIssueCode
	}
}

type candidate struct {
	Path        string
	ContentHash string
	Score       float64
}

func absPath(root, relative string) string {
	if relative == "" || relative == "." {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

func relPath(root, absolute string) string {
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == "" {
		return "."
	}
	return filepath.ToSlash(relative)
}
