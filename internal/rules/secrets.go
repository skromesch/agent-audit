package rules

import (
	"fmt"
	"regexp"

	"github.com/skromesch/agent-audit/internal/model"
)

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"OpenAI API Key", regexp.MustCompile(`(?i)"?(OPENAI_API_KEY)"?\s*[=:]\s*"?(sk-[a-zA-Z0-9\-_]{20,})`)},
	{"Anthropic API Key", regexp.MustCompile(`(?i)"?(ANTHROPIC_API_KEY)"?\s*[=:]\s*"?(sk-ant-[a-zA-Z0-9\-_]{20,})`)},
	{"GitHub Token", regexp.MustCompile(`(?i)"?(GITHUB_TOKEN)"?\s*[=:]\s*"?(gh[ps]_[a-zA-Z0-9]{36,})`)},
	{"Generic API Key", regexp.MustCompile(`(?i)"?([a-zA-Z_]{3,}_(?:API_KEY|TOKEN|SECRET|PASSWORD))"?\s*[=:]\s*"?([a-zA-Z0-9\-_]{16,})`)},
}

// ScanForSecrets scans content for secret patterns and returns findings.
// Each unique (name, value) pair produces at most one finding.
func ScanForSecrets(path, content string) []model.Finding {
	seen := map[string]bool{}
	var findings []model.Finding
	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 3 {
				continue
			}
			// Deduplicate by secret value across all patterns.
			if seen[m[2]] {
				continue
			}
			seen[m[2]] = true
			masked := MaskSecret(m[2])
			findings = append(findings, model.Finding{
				Tool:        "security",
				Category:    "secrets",
				Scope:       "project",
				Path:        path,
				Severity:    model.SeverityCritical,
				Description: fmt.Sprintf("%s detected in config file", sp.name),
				Details:     map[string]string{"masked_value": masked},
			})
		}
	}
	return findings
}

// MaskSecret masks a secret value, always returning a different string.
// For values with 7+ chars: keeps first 3 and last 4 chars.
// For shorter values: keeps up to first 4 and last 4 chars.
func MaskSecret(value string) string {
	n := len(value)
	if n == 0 {
		return "************"
	}
	if n >= 7 {
		return value[:3] + "************" + value[n-4:]
	}
	// Short values: use up to 4 chars for both prefix and suffix.
	prefixLen := n
	if prefixLen > 4 {
		prefixLen = 4
	}
	suffixLen := n
	if suffixLen > 4 {
		suffixLen = 4
	}
	return value[:prefixLen] + "************" + value[n-suffixLen:]
}
