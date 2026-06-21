package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/skromesch/agent-audit/internal/model"
)

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		Root:      "/test/project",
		ScannedAt: time.Now(),
		Agents: []model.AgentConfig{
			{Tool: "Claude Code", ConfigFiles: []string{"/test/.claude/settings.json"}, Settings: map[string]string{"model": "claude-opus-4-5"}},
		},
		MCPServers: []model.MCPServer{
			{Name: "filesystem", Command: "node", Args: []string{"server.js"}, Source: "/test/.mcp.json"},
		},
		Skills: []model.Skill{
			{Name: "my-skill", Description: "Does something", Valid: true, Path: "/test/skills/my-skill"},
			{Name: "broken", Valid: false, Issues: []string{"missing skill.md"}, Path: "/test/skills/broken"},
		},
		Findings: []model.Finding{
			{Tool: "security", Category: "secrets", Severity: model.SeverityCritical, Description: "API key found", Path: "/test/.claude/settings.json"},
			{Tool: "security", Category: "dangerous-commands", Severity: model.SeverityWarning, Description: "curl|sh detected", Path: "/test/.mcp.json"},
		},
		ConfigFiles: []string{"/test/.claude/settings.json", "/test/.mcp.json"},
	}
}

func TestRenderOverview(t *testing.T) {
	out := renderOverview(sampleResult(), 80, 24)
	if !strings.Contains(out, "Claude Code") {
		t.Error("overview should contain agent name")
	}
}

func TestRenderOverviewNil(t *testing.T) {
	out := renderOverview(nil, 80, 24)
	if out == "" {
		t.Error("nil result should return non-empty string")
	}
}

func TestRenderAgents(t *testing.T) {
	out := renderAgents(sampleResult(), 80, 24)
	if !strings.Contains(out, "Claude Code") {
		t.Error("agents view should contain agent name")
	}
}

func TestRenderAgentsEmpty(t *testing.T) {
	r := &model.ScanResult{}
	out := renderAgents(r, 80, 24)
	if out == "" {
		t.Error("empty agents should return non-empty string")
	}
}

func TestRenderMCP(t *testing.T) {
	out := renderMCP(sampleResult(), 80, 24)
	if !strings.Contains(out, "filesystem") {
		t.Error("mcp view should contain server name")
	}
}

func TestRenderMCPEmpty(t *testing.T) {
	out := renderMCP(&model.ScanResult{}, 80, 24)
	if out == "" {
		t.Error("empty mcp should return non-empty string")
	}
}

func TestRenderSkills(t *testing.T) {
	out := renderSkills(sampleResult(), 80, 24)
	if !strings.Contains(out, "my-skill") {
		t.Error("skills view should contain skill name")
	}
	if !strings.Contains(out, "broken") {
		t.Error("skills view should contain invalid skill")
	}
}

func TestRenderSkillsEmpty(t *testing.T) {
	out := renderSkills(&model.ScanResult{}, 80, 24)
	if out == "" {
		t.Error("empty skills should return non-empty string")
	}
}

func TestRenderSecurity(t *testing.T) {
	out := renderSecurity(sampleResult(), 80, 24)
	if !strings.Contains(out, "CRITICAL") {
		t.Error("security view should contain CRITICAL")
	}
	if !strings.Contains(out, "WARNING") {
		t.Error("security view should contain WARNING")
	}
}

func TestRenderSecurityEmpty(t *testing.T) {
	out := renderSecurity(&model.ScanResult{}, 80, 24)
	if out == "" {
		t.Error("empty security should return non-empty string")
	}
}

func TestRenderFiles(t *testing.T) {
	out := renderFiles(sampleResult(), 80, 24)
	if !strings.Contains(out, "/test/.claude/settings.json") {
		t.Error("files view should contain config file path")
	}
}

func TestRenderFilesEmpty(t *testing.T) {
	out := renderFiles(&model.ScanResult{}, 80, 24)
	if out == "" {
		t.Error("empty files should return non-empty string")
	}
}

func TestRenderTabBar(t *testing.T) {
	bar := renderTabBar(0, 120)
	if !strings.Contains(bar, "Overview") {
		t.Error("tab bar should contain Overview")
	}
}

func TestNewApp(t *testing.T) {
	app := NewApp(sampleResult())
	if app == nil {
		t.Fatal("NewApp should return non-nil")
	}
}

func TestAppInit(t *testing.T) {
	app := NewApp(sampleResult())
	cmd := app.Init()
	if cmd != nil {
		t.Error("Init should return nil cmd")
	}
}

func TestAppUpdateWindowSize(t *testing.T) {
	app := *NewApp(sampleResult())
	m, _ := app.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	a := m.(App)
	if a.width != 120 || a.height != 40 {
		t.Errorf("width=%d height=%d, want 120x40", a.width, a.height)
	}
}

func TestAppUpdateTabNavigation(t *testing.T) {
	app := *NewApp(sampleResult())
	m, _ := app.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	app = m.(App)

	m, _ = app.Update(tea.KeyMsg{Type: tea.KeyTab})
	app = m.(App)
	if app.activeTab != 1 {
		t.Errorf("activeTab = %d, want 1 after tab", app.activeTab)
	}

	m, _ = app.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	app = m.(App)
	if app.activeTab != 0 {
		t.Errorf("activeTab = %d, want 0 after shift+tab", app.activeTab)
	}
}

func TestAppUpdateQuit(t *testing.T) {
	app := *NewApp(sampleResult())
	_, cmd := app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Error("q key should return a quit cmd")
	}
}

func TestAppViewLoading(t *testing.T) {
	app := *NewApp(sampleResult())
	out := app.View()
	if out != "Loading..." {
		t.Errorf("View with zero width should return 'Loading...', got %q", out)
	}
}

func TestAppViewWithSize(t *testing.T) {
	app := *NewApp(sampleResult())
	m, _ := app.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	app = m.(App)
	out := app.View()
	if !strings.Contains(out, "Overview") {
		t.Error("View should contain tab names")
	}
}

func TestRenderActiveTabAllTabs(t *testing.T) {
	app := *NewApp(sampleResult())
	for i := 0; i < 6; i++ {
		app.activeTab = i
		out := app.renderActiveTab(80, 24)
		if out == "" {
			t.Errorf("tab %d returned empty string", i)
		}
	}
	app.activeTab = 99
	out := app.renderActiveTab(80, 24)
	if out != "" {
		t.Errorf("unknown tab should return empty string, got %q", out)
	}
}

func TestAppUpdateExportKey(t *testing.T) {
	app := *NewApp(sampleResult())
	_, cmd := app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	if cmd != nil {
		t.Error("e key should return nil cmd")
	}
}

func TestAppUpdateRescanKey(t *testing.T) {
	app := *NewApp(sampleResult())
	_, cmd := app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd != nil {
		t.Error("r key should return nil cmd")
	}
}
