package tui

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func renderSkills(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.Skills) == 0 {
		return StyleMuted.Render("No skills detected.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Skills (%d)", len(result.Skills))) + "\n\n")

	for _, sk := range result.Skills {
		status := StyleOK.Render("✓ valid")
		if !sk.Valid {
			status = StyleCritical.Render("✗ invalid")
		}
		sb.WriteString(fmt.Sprintf("%s  %s\n", status, StyleTitle.Render(sk.Name)))
		if sk.Description != "" {
			sb.WriteString(fmt.Sprintf("   %s\n", StyleMuted.Render(sk.Description)))
		}
		if len(sk.Issues) > 0 {
			for _, issue := range sk.Issues {
				sb.WriteString(fmt.Sprintf("   %s %s\n", StyleWarning.Render("!"), issue))
			}
		}
		sb.WriteString(fmt.Sprintf("   %s\n\n", StyleMuted.Render(sk.Path)))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
