package ai

import (
	"context"
	"errors"
	"strings"
	"time"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

// BridgeClient is the slice of the scanner-bridge gRPC API the drafter uses.
// Defined as an interface so tests can plug in a fake without spinning up gRPC.
type BridgeClient interface {
	DraftIgnoreReason(ctx context.Context, in *pb.DraftIgnoreReasonRequest, opts ...any) (*pb.DraftIgnoreReasonResponse, error)
}

// IgnoreReasonDrafter is a thin client for the scanner-bridge gRPC RPC
// DraftIgnoreReason. When `bridge` is nil — the typical case while the Python
// sidecar is starting up or absent — Draft returns ErrDrafterDisabled so the
// UI panel hides cleanly via the 503 path. Set the bridge with WithBridge to
// activate the live LLM round-trip.
type IgnoreReasonDrafter struct {
	enabled bool
	budget  *TokenBudget
	bridge  bridgeAdapter
}

// bridgeAdapter wraps the generated grpc client to satisfy the variadic-options
// quirk: the generated client returns `(*Resp, error)` with `...grpc.CallOption`,
// which doesn't fit the `...any` we use for the test-friendly interface.
type bridgeAdapter func(context.Context, *pb.DraftIgnoreReasonRequest) (*pb.DraftIgnoreReasonResponse, error)

// NewIgnoreReasonDrafter constructs a drafter. enabled=false (default) makes Draft
// always return ErrDrafterDisabled.
func NewIgnoreReasonDrafter(enabled bool) *IgnoreReasonDrafter {
	return &IgnoreReasonDrafter{enabled: enabled}
}

// WithTokenBudget wires a daily token-budget counter. nil disables enforcement.
func (d *IgnoreReasonDrafter) WithTokenBudget(b *TokenBudget) *IgnoreReasonDrafter {
	d.budget = b
	return d
}

// WithBridge wires the scanner-bridge gRPC client. Pass the adapter produced
// by NewBridgeAdapter so the generated client's variadic CallOption signature
// is hidden behind a uniform 2-arg call.
func (d *IgnoreReasonDrafter) WithBridge(call bridgeAdapter) *IgnoreReasonDrafter {
	d.bridge = call
	return d
}

// NewBridgeAdapter wraps a generated pb.ScannerBridgeClient so its variadic
// CallOption tail is hidden behind a 2-arg signature. Returns a closure
// suitable for WithBridge. Pass nil to keep the drafter in disabled mode.
func NewBridgeAdapter(client pb.ScannerBridgeClient) bridgeAdapter {
	if client == nil {
		return nil
	}
	return func(ctx context.Context, req *pb.DraftIgnoreReasonRequest) (*pb.DraftIgnoreReasonResponse, error) {
		return client.DraftIgnoreReason(ctx, req)
	}
}

// ErrDrafterDisabled is returned when ai_features.enabled is false or the
// scanner-bridge sidecar is not reachable.
var ErrDrafterDisabled = errors.New("ai: drafter disabled")

// ErrTokenBudgetExceeded is returned when the daily Draft-call budget is spent.
// Callers should surface 429 to clients and retry against the new window the
// next UTC day.
var ErrTokenBudgetExceeded = errors.New("ai: token budget exceeded")

// DraftRequest is the input shape for Draft.
type DraftRequest struct {
	ComponentID    int64
	CVEID          string
	PackageName    string
	PackageVersion string
	Ecosystem      string
	CVESummary     string
	RepoURL        string
	OperatorEmail  string
}

// DraftResponse holds the LLM-produced draft text.
type DraftResponse struct {
	Reason     string
	ModelUsed  string
	TokensUsed int32
	FromCache  bool
}

// Draft returns a 1-2 sentence justification for ignoring the CVE. The Go side
// performs the pre-flight gating (enabled flag, daily budget); the LLM call
// lives in scanner-bridge. When the bridge is absent or returns an empty
// reason, ErrDrafterDisabled propagates so the UI hides the panel via 503.
func (d *IgnoreReasonDrafter) Draft(ctx context.Context, req DraftRequest) (*DraftResponse, error) {
	start := time.Now()
	if d == nil || !d.enabled {
		recordDraftOutcome("disabled", time.Since(start))
		return nil, ErrDrafterDisabled
	}
	if d.budget != nil && !d.budget.Allow() {
		recordDraftOutcome("budget_exceeded", time.Since(start))
		return nil, ErrTokenBudgetExceeded
	}
	if d.bridge == nil {
		// AI feature flagged on but no scanner-bridge wired (sidecar starting
		// up, missing OPENAI key, etc). 503 keeps the UI panel hidden.
		recordDraftOutcome("disabled", time.Since(start))
		return nil, ErrDrafterDisabled
	}
	// Apply a request-level timeout so a stuck bridge doesn't pin the handler
	// goroutine longer than the rate-limiter / UI expects.
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := d.bridge(callCtx, &pb.DraftIgnoreReasonRequest{
		ComponentId:    req.ComponentID,
		CveId:          req.CVEID,
		PackageName:    req.PackageName,
		PackageVersion: req.PackageVersion,
		Ecosystem:      req.Ecosystem,
		CveSummary:     req.CVESummary,
		RepoUrl:        req.RepoURL,
		OperatorEmail:  req.OperatorEmail,
	})
	if err != nil {
		recordDraftOutcome("error", time.Since(start))
		return nil, err
	}
	reason := strings.TrimSpace(resp.GetReason())
	if reason == "" {
		recordDraftOutcome("disabled", time.Since(start))
		return nil, ErrDrafterDisabled
	}
	recordDraftOutcome("ok", time.Since(start))
	return &DraftResponse{
		Reason:     reason,
		ModelUsed:  resp.GetModelUsed(),
		TokensUsed: resp.GetTokensUsed(),
		FromCache:  resp.GetFromCache(),
	}, nil
}
