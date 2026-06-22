package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/report"
)

var tabs = []string{"Agents Overview", "MCP", "Skills", "Security", "About"}

type App struct {
	activeTab         int
	width             int
	height            int
	overviewScroll    int
	skillsCursor      int
	skillsFocus       int // 0=left list, 1=right detail
	skillsRightScroll int
	mcpCursor         int
	mcpFocus          int // 0=left list, 1=right detail
	mcpRightScroll    int
	result            *model.ScanResult
}

func NewApp(result *model.ScanResult) *App {
	return &App{result: result}
}

func (a App) Init() tea.Cmd { return nil }

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "tab":
			switch {
			case a.activeTab == 2 && a.skillsFocus == 0:
				a.skillsFocus = 1
			case a.activeTab == 1 && a.mcpFocus == 0:
				a.mcpFocus = 1
			default:
				a.activeTab = (a.activeTab + 1) % len(tabs)
				a.overviewScroll = 0
				a.skillsCursor, a.skillsFocus, a.skillsRightScroll = 0, 0, 0
				a.mcpCursor, a.mcpFocus, a.mcpRightScroll = 0, 0, 0
			}
		case "shift+tab":
			switch {
			case a.activeTab == 2 && a.skillsFocus == 1:
				a.skillsFocus = 0
			case a.activeTab == 1 && a.mcpFocus == 1:
				a.mcpFocus = 0
			default:
				a.activeTab = (a.activeTab - 1 + len(tabs)) % len(tabs)
				a.overviewScroll = 0
				a.skillsCursor, a.skillsFocus, a.skillsRightScroll = 0, 0, 0
				a.mcpCursor, a.mcpFocus, a.mcpRightScroll = 0, 0, 0
			}
		case "enter", "right", "l":
			if a.activeTab == 2 && a.skillsFocus == 0 {
				a.skillsFocus = 1
				a.skillsRightScroll = 0
			} else if a.activeTab == 1 && a.mcpFocus == 0 {
				a.mcpFocus = 1
				a.mcpRightScroll = 0
			}
		case "escape", "left", "h":
			if a.activeTab == 2 && a.skillsFocus == 1 {
				a.skillsFocus = 0
			} else if a.activeTab == 1 && a.mcpFocus == 1 {
				a.mcpFocus = 0
			}
		case "up", "k":
			switch a.activeTab {
			case 0:
				if a.overviewScroll > 0 {
					a.overviewScroll--
				}
			case 2:
				if a.skillsFocus == 1 {
					if a.skillsRightScroll > 0 {
						a.skillsRightScroll--
					}
				} else if a.skillsCursor > 0 {
					a.skillsCursor--
					a.skillsRightScroll = 0
				}
			case 1:
				if a.mcpFocus == 1 {
					if a.mcpRightScroll > 0 {
						a.mcpRightScroll--
					}
				} else if a.mcpCursor > 0 {
					a.mcpCursor--
					a.mcpRightScroll = 0
				}
			}
		case "down", "j":
			switch a.activeTab {
			case 0:
				a.overviewScroll++
			case 2:
				if a.skillsFocus == 1 {
					a.skillsRightScroll++
				} else if n := len(a.result.Skills); n > 0 && a.skillsCursor < n-1 {
					a.skillsCursor++
					a.skillsRightScroll = 0
				}
			case 1:
				if a.mcpFocus == 1 {
					a.mcpRightScroll++
				} else if n := len(a.result.MCPServers); n > 0 && a.mcpCursor < n-1 {
					a.mcpCursor++
					a.mcpRightScroll = 0
				}
			}
		case "e":
			go func() {
				f, _ := os.Create("report.json")
				defer f.Close()
				report.WriteJSON(a.result, f)
			}()
		case "r":
			// no-op: rescan requires plumbing not yet available
		}
	}
	return a, nil
}

func (a App) View() string {
	if a.width == 0 {
		return "Loading..."
	}

	tabBar := renderTabBar(a.activeTab, a.width)

	contentHeight := a.height - 5
	content := a.renderActiveTab(a.width, contentHeight)

	navHint := ""
	switch a.activeTab {
	case 0:
		navHint = "  ↑↓:scroll"
	case 2:
		if a.skillsFocus == 0 {
			navHint = "  ↑↓:select  →/enter:detail"
		} else {
			navHint = "  ↑↓:scroll  ←/esc:back"
		}
	case 1:
		if a.mcpFocus == 0 {
			navHint = "  ↑↓:select  →/enter:detail"
		} else {
			navHint = "  ↑↓:scroll  ←/esc:back"
		}
	}
	status := StyleStatusBar.Render(
		fmt.Sprintf("  %s  q:quit  tab:next  shift+tab:prev  e:export%s",
			StyleMuted.Render(a.result.Root), navHint),
	)

	return lipgloss.JoinVertical(lipgloss.Left, tabBar, content, status)
}

func (a App) renderActiveTab(width, height int) string {
	switch a.activeTab {
	case 0:
		return renderOverview(a.result, width, height, a.overviewScroll)
	case 1:
		return renderMCP(a.result, width, height, a.mcpCursor, a.mcpFocus, a.mcpRightScroll)
	case 2:
		return renderSkills(a.result, width, height, a.skillsCursor, a.skillsFocus, a.skillsRightScroll)
	case 3:
		return renderSecurity(a.result, width, height)
	case 4:
		return renderAbout(width, height)
	default:
		return ""
	}
}

func renderTabBar(active, width int) string {
	var parts []string
	for i, t := range tabs {
		if i == active {
			parts = append(parts, StyleTabActive.Render(t))
		} else {
			parts = append(parts, StyleTab.Render(t))
		}
	}
	return StyleTabBar.Width(width).Render(strings.Join(parts, " "))
}

// Run starts the Bubble Tea TUI with the given scan result.
// Falls back to stdout JSON if stdin is not a TTY (e.g. pipes, CI).
func Run(result *model.ScanResult) error {
	if !term.IsTerminal(os.Stdin.Fd()) {
		return report.WriteJSON(result, os.Stdout)
	}
	app := NewApp(result)
	p := tea.NewProgram(app, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
