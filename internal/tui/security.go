package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderSecurity(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Findings) == 0 {
		return StyleOK.Render("✓ No security findings.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Security Findings (%d)", len(result.Findings))) + "\n\n")

	for _, f := range result.Findings {
		var severityStyle lipgloss.Style
		icon := "ℹ"
		switch f.Severity {
		case model.SeverityCritical:
			severityStyle = StyleCritical
			icon = "✗"
		case model.SeverityWarning:
			severityStyle = StyleWarning
			icon = "!"
		default:
			severityStyle = StyleMuted
		}

		fmt.Fprintf(&sb, "%s [%s] %s\n",
			severityStyle.Render(icon),
			severityStyle.Render(string(f.Severity)),
			f.Description,
		)
		fmt.Fprintf(&sb, "  %s\n\n", StyleMuted.Render(f.Path))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
