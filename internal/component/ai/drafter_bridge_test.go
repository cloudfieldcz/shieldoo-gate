package ai_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDraft_BridgeWired_HappyPath: a wired bridge returning a non-empty reason
// produces a DraftResponse populated from the proto reply.
func TestDraft_BridgeWired_HappyPath(t *testing.T) {
	called := false
	bridge := func(_ context.Context, req *pb.DraftIgnoreReasonRequest) (*pb.DraftIgnoreReasonResponse, error) {
		called = true
		assert.Equal(t, "CVE-2024-1", req.CveId)
		assert.Equal(t, "requests", req.PackageName)
		return &pb.DraftIgnoreReasonResponse{
			Reason:     "Not exploitable in our usage — vulnerable function never called.",
			ModelUsed:  "gpt-5",
			TokensUsed: 42,
			FromCache:  false,
		}, nil
	}
	d := ai.NewIgnoreReasonDrafter(true).WithBridge(bridge)
	resp, err := d.Draft(context.Background(), ai.DraftRequest{
		CVEID:          "CVE-2024-1",
		PackageName:    "requests",
		PackageVersion: "2.31.0",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Not exploitable in our usage — vulnerable function never called.", resp.Reason)
	assert.Equal(t, "gpt-5", resp.ModelUsed)
	assert.Equal(t, int32(42), resp.TokensUsed)
	assert.True(t, called, "bridge must be invoked when wired")
}

// TestDraft_BridgeReturnsEmpty_FallsBackToDisabled covers the case where the
// scanner-bridge sidecar returned a 200 with reason="" (e.g. AI not configured
// inside the sidecar). The Go side must surface ErrDrafterDisabled so the UI
// hides the panel via 503 — never propagating an empty draft to the operator.
func TestDraft_BridgeReturnsEmpty_FallsBackToDisabled(t *testing.T) {
	bridge := func(_ context.Context, _ *pb.DraftIgnoreReasonRequest) (*pb.DraftIgnoreReasonResponse, error) {
		return &pb.DraftIgnoreReasonResponse{Reason: "", ModelUsed: "none", TokensUsed: 0}, nil
	}
	d := ai.NewIgnoreReasonDrafter(true).WithBridge(bridge)
	_, err := d.Draft(context.Background(), ai.DraftRequest{})
	assert.ErrorIs(t, err, ai.ErrDrafterDisabled)
}

// TestDraft_BridgeError_PropagatesError: gRPC transport / sidecar errors must
// reach the caller verbatim so the API handler can surface 5xx and the rate
// limiter can refund the call.
func TestDraft_BridgeError_PropagatesError(t *testing.T) {
	wantErr := errors.New("simulated transport failure")
	bridge := func(_ context.Context, _ *pb.DraftIgnoreReasonRequest) (*pb.DraftIgnoreReasonResponse, error) {
		return nil, wantErr
	}
	d := ai.NewIgnoreReasonDrafter(true).WithBridge(bridge)
	_, err := d.Draft(context.Background(), ai.DraftRequest{})
	assert.ErrorIs(t, err, wantErr)
}

// TestDraft_BridgeNotWired_ReturnsDisabled keeps the fallback path tested even
// after the bridge field was added. Without a wired bridge, every call returns
// ErrDrafterDisabled regardless of feature flag.
func TestDraft_BridgeNotWired_ReturnsDisabled(t *testing.T) {
	d := ai.NewIgnoreReasonDrafter(true) // enabled but no bridge
	_, err := d.Draft(context.Background(), ai.DraftRequest{})
	assert.ErrorIs(t, err, ai.ErrDrafterDisabled)
}
