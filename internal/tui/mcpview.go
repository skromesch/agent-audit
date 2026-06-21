package tui

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func renderMCP(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.MCPServers) == 0 {
		return StyleMuted.Render("No MCP servers detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("MCP Servers (%d)", len(result.MCPServers))) + "\n\n")

	for _, s := range result.MCPServers {
		sb.WriteString(StyleTitle.Render(s.Name) + "\n")
		sb.WriteString(fmt.Sprintf("  Command:  %s %s\n", s.Command, strings.Join(s.Args, " ")))
		sb.WriteString(fmt.Sprintf("  Source:   %s\n", s.Source))
		if len(s.Env) > 0 {
			sb.WriteString(StyleMuted.Render("  Env vars:") + "\n")
			for k, v := range s.Env {
				sb.WriteString(fmt.Sprintf("    %s = %s\n", k, v))
			}
		}
		sb.WriteString("\n")
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
