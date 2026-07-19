package tui

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Version is set at build time via -ldflags "-X .../internal/tui.Version=...".
// When empty (e.g. a plain `go build`), renderAbout falls back to the Go
// module version (populated by `go install pkg@version`), then "(dev)".
var Version = ""

func renderAbout(width, height int) string {
	version := Version
	if version == "" {
		version = "(dev)"
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}

	toolInfo := StyleBox.Width(width - 4).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			StyleHeader.Render("agent-audit"),
			StyleMuted.Render("Scan and audit AI agent configurations across tools"),
			"",
			fmt.Sprintf("%-12s %s", "Version:", version),
			fmt.Sprintf("%-12s %s", "Module:", "github.com/skromesch/agent-audit"),
		),
	)

	keybindings := []struct{ key, desc string }{
		{"tab / shift+tab", "next / previous tab"},
		{"q,  ctrl+c", "quit"},
		{"e", "export report.json"},
	}

	var kb strings.Builder
	kb.WriteString(StyleHeader.Render("Keybindings") + "\n")
	for _, b := range keybindings {
		kb.WriteString(fmt.Sprintf("  %-20s %s\n",
			StyleMuted.Render(b.key),
			b.desc,
		))
	}

	keybindBox := StyleBox.Width(width - 4).Render(strings.TrimRight(kb.String(), "\n"))

	return lipgloss.JoinVertical(lipgloss.Left, toolInfo, "", keybindBox)
}
