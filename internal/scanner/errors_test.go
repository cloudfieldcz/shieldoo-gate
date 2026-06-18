package scanner

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestScanError_Retryable_ReturnsTrueForRetryableAndOverload(t *testing.T) {
	assert.True(t, NewScanError(ErrKindRetryable, errors.New("down")).Retryable())
	assert.True(t, NewScanError(ErrKindOverload, errors.New("busy")).Retryable())
	assert.False(t, NewScanError(ErrKindTerminal, errors.New("bad input")).Retryable())
	// Throttled is local backpressure, not a transient backend failure — the
	// engine must not retry it (the quota will not have reset 200ms later).
	assert.False(t, NewScanError(ErrKindThrottled, errors.New("quota")).Retryable())
}

func TestScanError_Throttled_StringIsThrottled(t *testing.T) {
	assert.Equal(t, "throttled", ErrKindThrottled.String())
}

func TestScanError_CountsTowardBreaker_OnlyHealthSignals(t *testing.T) {
	// Retryable transients and backend overload indicate scanner ill-health and
	// must open the per-scanner circuit breaker.
	assert.True(t, NewScanError(ErrKindRetryable, errors.New("down")).CountsTowardBreaker())
	assert.True(t, NewScanError(ErrKindOverload, errors.New("busy")).CountsTowardBreaker())
	// Terminal per-artifact conditions and local throttles say nothing about
	// scanner health — a burst of them must not open the breaker and fail
	// unrelated, healthy traffic.
	assert.False(t, NewScanError(ErrKindTerminal, errors.New("too big")).CountsTowardBreaker())
	assert.False(t, NewScanError(ErrKindThrottled, errors.New("quota")).CountsTowardBreaker())
	// A nil error never counts.
	var nilErr *ScanError
	assert.False(t, nilErr.CountsTowardBreaker())
}

func TestClassifyScanError_ContextDeadlineIsRetryable(t *testing.T) {
	err := ClassifyScanError(context.DeadlineExceeded)
	require.NotNil(t, err)
	assert.Equal(t, ErrKindRetryable, err.Kind)
}

func TestClassifyScanError_NetTimeoutIsRetryable(t *testing.T) {
	err := ClassifyScanError(timeoutErr{})
	require.NotNil(t, err)
	assert.Equal(t, ErrKindRetryable, err.Kind)
}

func TestClassifyScanError_GRPCResourceExhaustedIsOverload(t *testing.T) {
	err := ClassifyScanError(status.Error(codes.ResourceExhausted, "busy"))
	require.NotNil(t, err)
	assert.Equal(t, ErrKindOverload, err.Kind)
}

func TestClassifyScanError_GRPCInvalidArgumentIsTerminal(t *testing.T) {
	err := ClassifyScanError(status.Error(codes.InvalidArgument, "bad artifact"))
	require.NotNil(t, err)
	assert.Equal(t, ErrKindTerminal, err.Kind)
}

func TestClassifyScanError_PreservesExistingScanError(t *testing.T) {
	original := NewScanError(ErrKindOverload, errors.New("scanner overloaded"))
	classified := ClassifyScanError(original)
	require.NotNil(t, classified)
	assert.Same(t, original, classified)
}
