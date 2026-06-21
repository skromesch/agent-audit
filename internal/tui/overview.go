package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderOverview(result *model.ScanResult, width, _ int) string {
	if result == nil {
		return StyleMuted.Render("Scanning...")
	}

	critStr := fmt.Sprintf("%d", result.CriticalCount())
	warnStr := fmt.Sprintf("%d", result.WarningCount())
	if result.CriticalCount() > 0 {
		critStr = StyleCritical.Render(critStr)
	}
	if result.WarningCount() > 0 {
		warnStr = StyleWarning.Render(warnStr)
	}

	summary := lipgloss.JoinVertical(lipgloss.Left,
		StyleTitle.Render("agent-audit"),
		StyleMuted.Render("Root: "+result.Root),
		"",
		StyleHeader.Render("Detected Tools"),
	)

	for _, a := range result.Agents {
		summary += "\n  " + StyleOK.Render("✓") + "  " + a.Tool
	}
	if len(result.Agents) == 0 {
		summary += "\n  " + StyleMuted.Render("none detected")
	}

	stats := lipgloss.JoinVertical(lipgloss.Left,
		"",
		StyleHeader.Render("Statistics"),
		fmt.Sprintf("  MCP Servers   %s", StyleOK.Render(fmt.Sprintf("%d", len(result.MCPServers)))),
		fmt.Sprintf("  Skills        %s", StyleOK.Render(fmt.Sprintf("%d", len(result.Skills)))),
		fmt.Sprintf("  Config Files  %s", StyleMuted.Render(fmt.Sprintf("%d", len(result.ConfigFiles)))),
		fmt.Sprintf("  Critical      %s", critStr),
		fmt.Sprintf("  Warnings      %s", warnStr),
	)

	content := lipgloss.JoinVertical(lipgloss.Left, summary, stats)
	return StyleBox.Width(width - 4).Render(content)
}
