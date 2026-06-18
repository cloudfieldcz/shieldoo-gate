package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ScanErrorKind classifies why a scanner failed to produce a verdict. The kind
// drives retry behaviour (retryable/overload are retried, terminal is not) and
// is surfaced in audit metadata.
type ScanErrorKind int

const (
	ErrKindNone ScanErrorKind = iota
	ErrKindRetryable
	ErrKindTerminal
	ErrKindOverload
)

func (k ScanErrorKind) String() string {
	switch k {
	case ErrKindRetryable:
		return "retryable"
	case ErrKindTerminal:
		return "terminal"
	case ErrKindOverload:
		return "overload"
	default:
		return "none"
	}
}

// ScanError wraps an underlying scanner failure with a classification kind.
type ScanError struct {
	Kind ScanErrorKind
	Err  error
}

func NewScanError(kind ScanErrorKind, err error) *ScanError {
	if err == nil {
		err = errors.New("scanner error")
	}
	if kind == ErrKindNone {
		kind = ErrKindRetryable
	}
	return &ScanError{Kind: kind, Err: err}
}

func (e *ScanError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s scanner error: %v", e.Kind.String(), e.Err)
}

func (e *ScanError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ScanError) Retryable() bool {
	return e != nil && (e.Kind == ErrKindRetryable || e.Kind == ErrKindOverload)
}

// Terminal reports whether the error is a permanent, per-artifact failure that
// retrying cannot fix (e.g. an artifact too large to scan, or an unsupported
// archive format). Terminal errors still fail closed for required scanners, but
// — unlike retryable/overload errors — they say nothing about scanner health,
// so the engine must not count them against a scanner's circuit breaker.
func (e *ScanError) Terminal() bool {
	return e != nil && e.Kind == ErrKindTerminal
}

// ClassifyScanError maps an arbitrary error to a *ScanError. An existing
// *ScanError is returned unchanged. gRPC status codes, context deadlines, and
// net timeouts are mapped to their natural kinds; everything else defaults to
// retryable so transient failures are retried rather than treated as terminal.
func ClassifyScanError(err error) *ScanError {
	if err == nil {
		return nil
	}
	var scanErr *ScanError
	if errors.As(err, &scanErr) {
		return scanErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return NewScanError(ErrKindRetryable, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return NewScanError(ErrKindRetryable, err)
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.ResourceExhausted:
			return NewScanError(ErrKindOverload, err)
		case codes.Unavailable, codes.DeadlineExceeded:
			return NewScanError(ErrKindRetryable, err)
		case codes.InvalidArgument, codes.NotFound, codes.Unimplemented:
			return NewScanError(ErrKindTerminal, err)
		}
	}
	return NewScanError(ErrKindRetryable, err)
}
