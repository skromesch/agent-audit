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
	{"|sh", "piped shell execution"},
}

// CheckMCPCommands inspects the command and args of an MCP server for dangerous patterns.
func CheckMCPCommands(server model.MCPServer) []model.Finding {
	var findings []model.Finding
	combined := server.Command + " " + strings.Join(server.Args, " ")
	seen := map[string]bool{}
	for _, dp := range dangerousPatterns {
		if strings.Contains(combined, dp.pattern) {
			// Deduplicate by reason to avoid multiple hits for equivalent patterns.
			if seen[dp.reason] {
				continue
			}
			seen[dp.reason] = true
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
	}
	return findings
}
