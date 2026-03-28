package sandbox

import (
	"regexp"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// BehaviorRule defines a pattern-matching rule applied to gVisor syscall log lines.
type BehaviorRule struct {
	Name        string
	Severity    scanner.Severity
	Pattern     *regexp.Regexp
	Description string
}

// defaultRules returns the built-in behavioral detection rules.
// Each rule matches against individual lines from the gVisor strace log.
func defaultRules() []BehaviorRule {
	return []BehaviorRule{
		{
			Name:        "dns-non-registry",
			Severity:    scanner.SeverityHigh,
			Pattern:     regexp.MustCompile(`connect\(.*:53\)`),
			Description: "DNS query to non-registry domain during install",
		},
		{
			Name:        "http-post-external",
			Severity:    scanner.SeverityCritical,
			Pattern:     regexp.MustCompile(`connect\(.*:443\).*write\(.*POST`),
			Description: "HTTP POST to external host — potential data exfiltration",
		},
		{
			Name:        "ssh-config-write",
			Severity:    scanner.SeverityCritical,
			Pattern:     regexp.MustCompile(`openat\(.*(?:\.ssh|\.config).*O_WRONLY`),
			Description: "Write to .ssh or .config directory — potential credential theft",
		},
		{
			Name:        "shell-execution",
			Severity:    scanner.SeverityHigh,
			Pattern:     regexp.MustCompile(`execve\(.*(?:sh|-c)\b`),
			Description: "Shell execution during package install",
		},
		{
			Name:        "pth-file-creation",
			Severity:    scanner.SeverityCritical,
			Pattern:     regexp.MustCompile(`openat\(.*\.pth.*O_CREAT`),
			Description: "Creation of .pth file — Python auto-execute vector",
		},
		{
			Name:        "cron-job-creation",
			Severity:    scanner.SeverityCritical,
			Pattern:     regexp.MustCompile(`openat\(.*(?:crontab|/etc/cron).*O_CREAT`),
			Description: "Cron job creation — persistence mechanism",
		},
		{
			Name:        "excessive-forking",
			Severity:    scanner.SeverityHigh,
			Pattern:     regexp.MustCompile(`clone\(`),
			Description: "Process spawning (fork) — excessive forking indicates suspicious behavior",
		},
	}
}

// analyzeLog applies all behavioral rules to the gVisor strace log and returns
// scanner.Finding entries for each match. The forkThreshold parameter controls
// how many clone() syscalls are needed before the "excessive-forking" rule fires.
func analyzeLog(log string, rules []BehaviorRule, forkThreshold int) []scanner.Finding {
	lines := strings.Split(log, "\n")

	var findings []scanner.Finding
	forkCount := 0

	for _, line := range lines {
		for _, rule := range rules {
			if !rule.Pattern.MatchString(line) {
				continue
			}

			// Special handling for fork counting: only report once when threshold exceeded.
			if rule.Name == "excessive-forking" {
				forkCount++
				if forkCount == forkThreshold+1 {
					findings = append(findings, scanner.Finding{
						Severity:    rule.Severity,
						Category:    "sandbox:" + rule.Name,
						Description: rule.Description,
						Location:    "sandbox-strace",
						IoCs:        []string{line},
					})
				}
				continue
			}

			findings = append(findings, scanner.Finding{
				Severity:    rule.Severity,
				Category:    "sandbox:" + rule.Name,
				Description: rule.Description,
				Location:    "sandbox-strace",
				IoCs:        []string{line},
			})
		}
	}

	return findings
}

// findingsToVerdict converts behavioral findings into a scanner verdict.
// At least one CRITICAL or HIGH finding is needed for VerdictMalicious.
// MEDIUM findings alone produce VerdictSuspicious.
// No findings produce VerdictClean.
func findingsToVerdict(findings []scanner.Finding) (scanner.Verdict, float32) {
	if len(findings) == 0 {
		return scanner.VerdictClean, 1.0
	}

	hasCritical := false
	hasHigh := false
	for _, f := range findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			hasCritical = true
		case scanner.SeverityHigh:
			hasHigh = true
		}
	}

	if hasCritical {
		return scanner.VerdictMalicious, 0.9
	}
	if hasHigh {
		return scanner.VerdictMalicious, 0.8
	}

	// MEDIUM / LOW findings only
	return scanner.VerdictSuspicious, 0.7
}
