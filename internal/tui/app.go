package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/report"
)

var tabs = []string{"Overview", "Agents", "MCP", "Skills", "Security", "Files"}

type App struct {
	activeTab int
	width     int
	height    int
	result    *model.ScanResult
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
			a.activeTab = (a.activeTab + 1) % len(tabs)
		case "shift+tab":
			a.activeTab = (a.activeTab - 1 + len(tabs)) % len(tabs)
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

	contentHeight := a.height - 4
	content := a.renderActiveTab(a.width, contentHeight)

	status := StyleStatusBar.Render(
		fmt.Sprintf("  %s  q:quit  tab:next  shift+tab:prev  e:export",
			StyleMuted.Render(a.result.Root)),
	)

	return lipgloss.JoinVertical(lipgloss.Left, tabBar, content, status)
}

func (a App) renderActiveTab(width, height int) string {
	switch a.activeTab {
	case 0:
		return renderOverview(a.result, width, height)
	case 1:
		return renderAgents(a.result, width, height)
	case 2:
		return renderMCP(a.result, width, height)
	case 3:
		return renderSkills(a.result, width, height)
	case 4:
		return renderSecurity(a.result, width, height)
	case 5:
		return renderFiles(a.result, width, height)
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
func Run(result *model.ScanResult) error {
	app := NewApp(result)
	p := tea.NewProgram(app, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
