package api

import (
	"io"
	"strconv"
)

// ioEOF returns io.EOF for files that import this helper to avoid pulling in the
// stdlib io package for a single sentinel.
func ioEOF() error { return io.EOF }

// formatInt64 is a tiny strconv helper used by handlers that compose URLs.
func formatInt64(v int64) string {
	return strconv.FormatInt(v, 10)
}
