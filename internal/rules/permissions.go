package rules

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

type permCheck struct {
	keyword  string
	desc     string
	severity model.Severity
}

var permChecks = []permCheck{
	{`"allow": ["*"]`, "Wildcard allow permission — unrestricted tool access", model.SeverityCritical},
	{`"allow":["*"]`, "Wildcard allow permission — unrestricted tool access", model.SeverityCritical},
	{"approval_mode: none", "Approval mode disabled — all actions auto-approved", model.SeverityCritical},
	{`approval = "none"`, "Approval mode disabled — all actions auto-approved", model.SeverityCritical},
	{"sandbox = false", "Sandbox disabled in agent config", model.SeverityWarning},
	{"sandbox: false", "Sandbox disabled in agent config", model.SeverityWarning},
	{"allow_all: true", "allow_all flag set to true", model.SeverityWarning},
	{"allow_all=true", "allow_all flag set to true", model.SeverityWarning},
	{"shell: unrestricted", "Unrestricted shell execution enabled", model.SeverityCritical},
}

// CheckPermissions scans file content for dangerous permission configurations.
func CheckPermissions(tool, path, content string) []model.Finding {
	var findings []model.Finding
	seen := map[string]bool{}
	lower := strings.ToLower(content)
	for _, pc := range permChecks {
		if strings.Contains(lower, strings.ToLower(pc.keyword)) {
			if seen[pc.desc] {
				continue
			}
			seen[pc.desc] = true
			findings = append(findings, model.Finding{
				Tool:        tool,
				Category:    "permissions",
				Scope:       "project",
				Path:        path,
				Severity:    pc.severity,
				Description: fmt.Sprintf("[%s] %s", tool, pc.desc),
				Details:     map[string]string{"file": path},
			})
		}
	}
	return findings
}
