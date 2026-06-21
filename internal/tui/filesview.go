package tui

import (
	"fmt"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

func renderFiles(result *model.ScanResult, width, _ int) string {
	if result == nil || len(result.ConfigFiles) == 0 {
		return StyleMuted.Render("No configuration files found.")
	}

	var sb strings.Builder
	sb.WriteString(StyleHeader.Render(fmt.Sprintf("Config Files (%d)", len(result.ConfigFiles))) + "\n\n")

	for _, f := range result.ConfigFiles {
		sb.WriteString(fmt.Sprintf("  %s\n", f))
	}
	return StyleBox.Width(width - 4).Render(sb.String())
}
