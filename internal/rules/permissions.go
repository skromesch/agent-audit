package rules

import (
	"encoding/json"
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
	{"approval_mode: none", "Approval mode disabled — all actions auto-approved", model.SeverityCritical},
	{`approval = "none"`, "Approval mode disabled — all actions auto-approved", model.SeverityCritical},
	{"sandbox = false", "Sandbox disabled in agent config", model.SeverityWarning},
	{"sandbox: false", "Sandbox disabled in agent config", model.SeverityWarning},
	{"allow_all: true", "allow_all flag set to true", model.SeverityWarning},
	{"allow_all=true", "allow_all flag set to true", model.SeverityWarning},
	{"shell: unrestricted", "Unrestricted shell execution enabled", model.SeverityCritical},
	// Codex config.toml (current key names).
	{`sandbox_mode = "danger-full-access"`, "Codex sandbox disabled (danger-full-access)", model.SeverityCritical},
	{`approval_policy = "never"`, "Codex approval prompts disabled (approval_policy = never)", model.SeverityWarning},
}

// CheckPermissions scans file content for dangerous permission configurations.
func CheckPermissions(tool, path, content string) []model.Finding {
	var findings []model.Finding
	seen := map[string]bool{}

	addFinding := func(desc string, severity model.Severity) {
		if seen[desc] {
			return
		}
		seen[desc] = true
		findings = append(findings, model.Finding{
			Tool:        tool,
			Category:    "permissions",
			Scope:       "project",
			Path:        path,
			Severity:    severity,
			Description: fmt.Sprintf("[%s] %s", tool, desc),
			Details:     map[string]string{"file": path},
		})
	}

	if v, ok := parseJSON(content); ok {
		if findWildcardAllow(v) {
			addFinding("Wildcard allow permission — unrestricted tool access", model.SeverityCritical)
		}
		// Claude Code settings.json.
		if findJSONValue(v, "defaultMode", "bypassPermissions") {
			addFinding("Permission prompts bypassed (defaultMode = bypassPermissions)", model.SeverityCritical)
		}
		if findJSONValue(v, "enableAllProjectMcpServers", true) {
			addFinding("All project MCP servers auto-approved (enableAllProjectMcpServers)", model.SeverityWarning)
		}
	}

	lower := strings.ToLower(content)
	for _, pc := range permChecks {
		if strings.Contains(lower, strings.ToLower(pc.keyword)) {
			addFinding(pc.desc, pc.severity)
		}
	}
	return findings
}

// parseJSON parses content as generic JSON. Using a real JSON parse instead of
// substring matching means pretty-printed or reordered settings files are
// still detected.
func parseJSON(content string) (interface{}, bool) {
	var v interface{}
	if err := json.Unmarshal([]byte(content), &v); err != nil {
		return nil, false
	}
	return v, true
}

// findJSONValue reports whether key is set to want at any nesting depth.
func findJSONValue(v interface{}, key string, want interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		if got, ok := val[key]; ok && got == want {
			return true
		}
		for _, child := range val {
			if findJSONValue(child, key, want) {
				return true
			}
		}
	case []interface{}:
		for _, item := range val {
			if findJSONValue(item, key, want) {
				return true
			}
		}
	}
	return false
}

// findWildcardAllow looks for any "allow" array (at any nesting depth, e.g.
// top-level or under "permissions") containing a literal "*" entry.
func findWildcardAllow(v interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		if arr, ok := val["allow"].([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok && s == "*" {
					return true
				}
			}
		}
		for _, child := range val {
			if findWildcardAllow(child) {
				return true
			}
		}
	case []interface{}:
		for _, item := range val {
			if findWildcardAllow(item) {
				return true
			}
		}
	}
	return false
}
