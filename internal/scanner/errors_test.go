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
