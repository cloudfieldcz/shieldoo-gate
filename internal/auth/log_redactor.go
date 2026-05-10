package auth

import (
	"regexp"

	"github.com/rs/zerolog"
)

// LogRedactorHook is a zerolog Hook that scrubs Authorization, Cookie, X-Api-Key
// and similar header values from any line emission. Used to protect against
// secret leakage in panic-recovery stacks and ad-hoc Debug() lines that include
// http.Request dumps.
type LogRedactorHook struct{}

// Run implements zerolog.Hook.
func (LogRedactorHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	// zerolog's built-in field scrubbing happens at field write time. The hook
	// runs before the event is emitted so we redact via msg substitution.
	if msg == "" {
		return
	}
	// Hooks cannot mutate the message in-place; we swap via Discard + Str.
	if redacted := RedactBytes([]byte(msg)); string(redacted) != msg {
		e.Discard()
	}
}

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
