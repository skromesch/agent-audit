package tui

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func renderOverview(result *model.ScanResult, width, _ int) string {
	if result == nil {
		return StyleMuted.Render("Scanning...")
	}

	inner := width - 6
	var sb strings.Builder

	sb.WriteString(StyleTitle.Render("agent-audit") + "\n")
	sb.WriteString(StyleMuted.Render("Root: "+result.Root) + "\n\n")

	if len(result.Agents) == 0 {
		sb.WriteString(StyleMuted.Render("No agents detected.") + "\n")
		return StyleBox.Width(width - 4).Render(strings.TrimRight(sb.String(), "\n"))
	}

	// Build a set of config files per agent for MCP matching
	agentFiles := map[string]map[string]bool{}
	for _, a := range result.Agents {
		set := map[string]bool{}
		for _, f := range a.ConfigFiles {
			set[f] = true
		}
		agentFiles[a.Tool] = set
	}

	for _, a := range result.Agents {
		sb.WriteString(divider(a.Tool, inner) + "\n\n")

		// Skills
		skillCount, projectSkills, globalSkills := 0, 0, 0
		for _, sk := range result.Skills {
			if sk.Agent == a.Tool {
				skillCount++
				if sk.Scope == "project" {
					projectSkills++
				} else {
					globalSkills++
				}
			}
		}

		// MCP servers whose source file belongs to this agent
		mcpCount := 0
		for _, m := range result.MCPServers {
			if agentFiles[a.Tool][m.Source] {
				mcpCount++
			}
		}

		// Findings
		critCount, warnCount := 0, 0
		for _, f := range result.Findings {
			if f.Tool == a.Tool {
				if f.Severity == model.SeverityCritical {
					critCount++
				} else if f.Severity == model.SeverityWarning {
					warnCount++
				}
			}
		}

		// Stats block
		detail := fmt.Sprintf("(%d project, %d global)", projectSkills, globalSkills)
		sb.WriteString(fmt.Sprintf("  %-16s %s  %s\n",
			"Skills",
			StyleOK.Render(fmt.Sprintf("%d", skillCount)),
			StyleMuted.Render(detail),
		))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "MCP Servers", StyleOK.Render(fmt.Sprintf("%d", mcpCount))))
		for k, v := range a.Settings {
			sb.WriteString(fmt.Sprintf("  %-16s %s\n", k, StyleMuted.Render(v)))
		}
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Critical", StyleCritical.Render(fmt.Sprintf("%d", critCount))))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Warnings", StyleWarning.Render(fmt.Sprintf("%d", warnCount))))

		// Config files
		if len(a.ConfigFiles) > 0 {
			sb.WriteString("\n  " + StyleMuted.Render("Config files:") + "\n")
			for _, f := range a.ConfigFiles {
				sb.WriteString(fmt.Sprintf("    %s\n", f))
			}
		}
		sb.WriteString("\n")
	}

	return StyleBox.Width(width - 4).Render(strings.TrimRight(sb.String(), "\n"))
}

func divider(label string, width int) string {
	prefix := "── " + label + " "
	dashes := width - len(prefix)
	if dashes < 2 {
		dashes = 2
	}
	return StyleHeader.Render(prefix + strings.Repeat("─", dashes))
}
