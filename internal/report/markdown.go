package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func WriteMarkdown(result *model.ScanResult, w io.Writer) error {
	fmt.Fprintf(w, "# agent-audit Report\n\n")
	fmt.Fprintf(w, "**Root:** `%s`  \n", result.Root)
	fmt.Fprintf(w, "**Scanned:** %s  \n\n", result.ScannedAt.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n|--------|-------|\n")
	fmt.Fprintf(w, "| Agents detected | %d |\n", len(result.Agents))
	fmt.Fprintf(w, "| MCP servers | %d |\n", len(result.MCPServers))
	fmt.Fprintf(w, "| Skills | %d |\n", len(result.Skills))
	fmt.Fprintf(w, "| Critical findings | %d |\n", result.CriticalCount())
	fmt.Fprintf(w, "| Warning findings | %d |\n\n", result.WarningCount())

	fmt.Fprintf(w, "## Agents\n\n")
	for _, a := range result.Agents {
		fmt.Fprintf(w, "### %s\n\n", a.Tool)
		fmt.Fprintf(w, "**Config files:**\n")
		for _, f := range a.ConfigFiles {
			fmt.Fprintf(w, "- `%s`\n", f)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## MCP Servers\n\n")
	for _, s := range result.MCPServers {
		fmt.Fprintf(w, "### %s\n\n", s.Name)
		if s.URL != "" {
			fmt.Fprintf(w, "- **URL:** `%s`\n", s.URL)
		} else {
			fmt.Fprintf(w, "- **Command:** `%s %s`\n", s.Command, strings.Join(s.Args, " "))
		}
		fmt.Fprintf(w, "- **Source:** `%s`\n\n", s.Source)
	}

	fmt.Fprintf(w, "## Security Findings\n\n")
	for _, f := range result.Findings {
		icon := "ℹ️"
		if f.Severity == model.SeverityWarning {
			icon = "⚠️"
		} else if f.Severity == model.SeverityCritical {
			icon = "🚨"
		}
		fmt.Fprintf(w, "- %s **[%s]** `%s`: %s\n", icon, f.Severity, f.Path, f.Description)
	}
	fmt.Fprintln(w)
	return nil
}
