package tui

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func renderAgents(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Agents) == 0 {
		return StyleMuted.Render("No agents detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render("Detected Agents") + "\n\n")

	for _, a := range result.Agents {
		sb.WriteString(StyleTitle.Render(a.Tool) + "\n")
		if len(a.ConfigFiles) > 0 {
			sb.WriteString(StyleMuted.Render("  Config files:") + "\n")
			for _, f := range a.ConfigFiles {
				sb.WriteString(fmt.Sprintf("    %s\n", f))
			}
		}
		if len(a.Settings) > 0 {
			sb.WriteString(StyleMuted.Render("  Settings:") + "\n")
			for k, v := range a.Settings {
				sb.WriteString(fmt.Sprintf("    %s = %s\n", k, v))
			}
		}
		sb.WriteString("\n")
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
