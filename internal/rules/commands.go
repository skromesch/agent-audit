package rules

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

var dangerousPatterns = []struct {
	pattern string
	reason  string
}{
	{"rm ", "destructive file removal"},
	{"sudo", "privilege escalation"},
	{"curl | sh", "remote code execution via pipe"},
	{"curl|sh", "remote code execution via pipe"},
	{"wget | sh", "remote code execution via pipe"},
	{"wget|sh", "remote code execution via pipe"},
	{"chmod 777", "world-writable permissions"},
	{"eval $(", "arbitrary code execution"},
	{"|bash", "piped shell execution"},
	{"| bash", "piped shell execution"},
	{"|sh", "piped shell execution"},
	{"| sh", "piped shell execution"},
}

// CheckMCPCommands inspects the command and args of an MCP server for dangerous patterns.
func CheckMCPCommands(server model.MCPServer) []model.Finding {
	combined := server.Command + " " + strings.Join(server.Args, " ")
	var findings []model.Finding
	for _, dp := range matchDangerousPatterns(combined) {
		findings = append(findings, model.Finding{
			Tool:        "security",
			Category:    "dangerous-commands",
			Scope:       "project",
			Path:        server.Source,
			Severity:    model.SeverityWarning,
			Description: fmt.Sprintf("MCP server %q uses %s (%s)", server.Name, dp.pattern, dp.reason),
			Details:     map[string]string{"command": combined, "server": server.Name},
		})
	}
	return findings
}

// CheckHookCommands inspects a Claude Code hook's shell command for dangerous patterns.
func CheckHookCommands(hookName, command, source string) []model.Finding {
	var findings []model.Finding
	for _, dp := range matchDangerousPatterns(command) {
		findings = append(findings, model.Finding{
			Tool:        "security",
			Category:    "dangerous-commands",
			Scope:       "project",
			Path:        source,
			Severity:    model.SeverityWarning,
			Description: fmt.Sprintf("Hook %q uses %s (%s)", hookName, dp.pattern, dp.reason),
			Details:     map[string]string{"command": command, "hook": hookName},
		})
	}
	return findings
}

// matchDangerousPatterns returns the set of dangerousPatterns entries found in
// combined, deduplicated by reason so equivalent patterns produce one hit.
func matchDangerousPatterns(combined string) []struct {
	pattern string
	reason  string
} {
	var matches []struct {
		pattern string
		reason  string
	}
	seen := map[string]bool{}
	for _, dp := range dangerousPatterns {
		if strings.Contains(combined, dp.pattern) {
			if seen[dp.reason] {
				continue
			}
			seen[dp.reason] = true
			matches = append(matches, dp)
		}
	}
	return matches
}
