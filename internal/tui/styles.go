package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorBase    = lipgloss.AdaptiveColor{Light: "#1a1a2e", Dark: "#e2e8f0"}
	colorMuted   = lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#94a3b8"}
	colorAccent  = lipgloss.AdaptiveColor{Light: "#3b82f6", Dark: "#60a5fa"}
	colorCrit    = lipgloss.AdaptiveColor{Light: "#dc2626", Dark: "#f87171"}
	colorWarn    = lipgloss.AdaptiveColor{Light: "#d97706", Dark: "#fbbf24"}
	colorOK      = lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34d399"}
	colorTab     = lipgloss.AdaptiveColor{Light: "#374151", Dark: "#cbd5e1"}
	colorTabSel  = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#93c5fd"}
	colorBorder  = lipgloss.AdaptiveColor{Light: "#d1d5db", Dark: "#334155"}

	StyleBase = lipgloss.NewStyle().Foreground(colorBase)

	StyleTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorAccent).
		MarginBottom(1)

	StyleTab = lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(colorTab)

	StyleTabActive = lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(colorTabSel).
		Bold(true).
		Underline(true)

	StyleTabBar = lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(colorBorder).
		MarginBottom(1)

	StyleCritical = lipgloss.NewStyle().Foreground(colorCrit).Bold(true)
	StyleWarning  = lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	StyleOK       = lipgloss.NewStyle().Foreground(colorOK)
	StyleMuted    = lipgloss.NewStyle().Foreground(colorMuted)

	StyleBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1)

	StyleHeader = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorAccent).
		PaddingBottom(1)

	StyleStatusBar = lipgloss.NewStyle().
		Foreground(colorMuted).
		PaddingTop(1)
)
