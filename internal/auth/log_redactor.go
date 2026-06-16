package auth

import (
	"regexp"
)

// RedactBytes/RedactString mask secret-bearing header values in free text. They are
// applied at known leak points (e.g. panic-recovery stack dumps in recoverer.go).
//
// Note: a zerolog Hook cannot rewrite an event's message, only discard it — so there
// is intentionally NO global redaction hook here. A hook that silently dropped whole
// log lines on a regex match would be both lossy and a false sense of security. The
// real defense is not logging secrets in the first place; these helpers are the
// belt-and-suspenders for the few places that dump untrusted text.

// authPatterns lists regex patterns to scrub in panic-stack and free-text logs.
var authPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization|x-api-key|proxy-authorization)\s*[:=]\s*[^\s,]+`),
	regexp.MustCompile(`(?i)(cookie|set-cookie)\s*[:=]\s*[^\n]+`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+=/]+`),
	regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/=]+`),
}

// RedactBytes returns a copy of b with sensitive header values masked.
func RedactBytes(b []byte) []byte {
	out := b
	for _, re := range authPatterns {
		out = re.ReplaceAll(out, []byte("[REDACTED]"))
	}
	return out
}

// RedactString returns the redacted form of s.
func RedactString(s string) string {
	return string(RedactBytes([]byte(s)))
}
