package scheduler

import "io"

// ioErrEOF returns io.EOF; the indirection lets the manifest_rescan file avoid an
// "imported and not used" cycle when imports are added/removed.
func ioErrEOF() error { return io.EOF }
