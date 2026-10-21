package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

func renderMCP(result *model.ScanResult, width, height, cursor, focus, rightScroll int) string {
	if result == nil || len(result.MCPServers) == 0 {
		return StyleMuted.Render("No MCP servers detected.")
	}

	servers := result.MCPServers
	if cursor >= len(servers) {
		cursor = len(servers) - 1
	}

	// source path → agent name
	agentForSource := map[string]string{}
	for _, a := range result.Agents {
		for _, f := range a.ConfigFiles {
			agentForSource[f] = a.Tool
		}
	}

	leftWidth := width / 3
	if leftWidth < 24 {
		leftWidth = 24
	}
	if leftWidth > 44 {
		leftWidth = 44
	}
	rightWidth := width - leftWidth - 2
	innerHeight := height - 2

	leftContent, selected := buildMCPLeftPane(servers, result.Agents, agentForSource, cursor, innerHeight)
	rightContent := buildMCPRightPane(servers[selected], rightWidth-4, innerHeight, rightScroll)

	leftBorder := StyleBox
	rightBorder := StyleBox
	if focus == 0 {
		leftBorder = StyleBox.BorderForeground(colorAccent)
	} else {
		rightBorder = StyleBox.BorderForeground(colorAccent)
	}

	left := leftBorder.Width(leftWidth).Height(innerHeight).Render(leftContent)
	right := rightBorder.Width(rightWidth).Height(innerHeight).Render(rightContent)

	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// buildMCPLeftPane renders the agent-grouped server list. cursor is a position
// in the displayed order (not an index into servers); the index of the server
// at that position is returned so the detail pane shows the same entry.
func buildMCPLeftPane(servers []model.MCPServer, agents []model.AgentConfig, agentForSource map[string]string, cursor, visibleHeight int) (string, int) {
	type agentGroup struct {
		project []int
		global  []int
	}

	groupMap := map[string]*agentGroup{}
	agentOrder := []string{}

	for _, a := range agents {
		groupMap[a.Tool] = &agentGroup{}
		agentOrder = append(agentOrder, a.Tool)
	}

	for i, s := range servers {
		name := agentForSource[s.Source]
		if name == "" {
			name = "Other"
		}
		if groupMap[name] == nil {
			groupMap[name] = &agentGroup{}
			agentOrder = append(agentOrder, name)
		}
		if s.Scope == "global" {
			groupMap[name].global = append(groupMap[name].global, i)
		} else {
			groupMap[name].project = append(groupMap[name].project, i)
		}
	}

	type lineItem struct {
		text      string
		serverIdx int
	}
	var lines []lineItem
	pos, selected := 0, 0

	for _, agentName := range agentOrder {
		g := groupMap[agentName]
		if len(g.project) == 0 && len(g.global) == 0 {
			continue
		}
		lines = append(lines, lineItem{StyleMuted.Render("── " + agentName), -1})

		addScope := func(indices []int, label string) {
			if len(indices) == 0 {
				return
			}
			if len(g.project) > 0 && len(g.global) > 0 {
				lines = append(lines, lineItem{StyleMuted.Render("   " + label), -1})
			}
			for _, idx := range indices {
				s := servers[idx]
				marker := "  "
				displayName := s.Name
				if pos == cursor {
					selected = idx
					marker = "▶ "
					displayName = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(displayName)
				}
				pos++
				lines = append(lines, lineItem{fmt.Sprintf("%s%s", marker, displayName), idx})
			}
		}

		addScope(g.project, "project")
		addScope(g.global, "global")
	}

	// auto-scroll to keep cursor visible
	cursorLine := 0
	for i, l := range lines {
		if l.serverIdx == selected {
			cursorLine = i
			break
		}
	}
	offset := 0
	if cursorLine >= visibleHeight {
		offset = cursorLine - visibleHeight/2
	}
	if offset+visibleHeight > len(lines) {
		offset = len(lines) - visibleHeight
	}
	if offset < 0 {
		offset = 0
	}
	end := offset + visibleHeight
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	for _, l := range lines[offset:end] {
		sb.WriteString(l.text + "\n")
	}
	return strings.TrimRight(sb.String(), "\n"), selected
}

func buildMCPRightPane(s model.MCPServer, width, height, scroll int) string {
	var sb strings.Builder

	sb.WriteString(StyleHeader.Render(s.Name) + "\n\n")

	scope := s.Scope
	if scope == "" {
		scope = "project"
	}
	sb.WriteString(fmt.Sprintf("%-10s %s\n", StyleMuted.Render("Scope:"), scope))
	sb.WriteString(fmt.Sprintf("%-10s %s\n", StyleMuted.Render("Source:"), s.Source))
	sb.WriteString("\n")

	cmd := s.Command
	if len(s.Args) > 0 {
		cmd += " " + strings.Join(s.Args, " ")
	}
	if s.URL != "" {
		sb.WriteString(StyleMuted.Render("URL:") + "\n")
		sb.WriteString(fmt.Sprintf("  %s\n", s.URL))
	} else {
		sb.WriteString(StyleMuted.Render("Command:") + "\n")
		sb.WriteString(fmt.Sprintf("  %s\n", cmd))
	}

	if len(s.Headers) > 0 {
		sb.WriteString("\n" + StyleMuted.Render("Headers:") + "\n")
		for k, v := range s.Headers {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	if len(s.Env) > 0 {
		sb.WriteString("\n" + StyleMuted.Render("Environment:") + "\n")
		for k, v := range s.Env {
			sb.WriteString(fmt.Sprintf("  %s = %s\n", k, v))
		}
	}

	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")

	var wrapped []string
	for _, line := range lines {
		if len(line) <= width {
			wrapped = append(wrapped, line)
			continue
		}
		for len(line) > width {
			wrapped = append(wrapped, line[:width])
			line = line[width:]
		}
		wrapped = append(wrapped, line)
	}

	maxScroll := len(wrapped) - height
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scroll > maxScroll {
		scroll = maxScroll
	}
	end := scroll + height
	if end > len(wrapped) {
		end = len(wrapped)
	}
	visible := wrapped[scroll:end]

	if scroll > 0 && len(visible) > 0 {
		visible[0] = StyleMuted.Render("↑ more above")
	}
	if scroll < maxScroll && len(visible) > 0 {
		visible[len(visible)-1] = StyleMuted.Render("↓ more below")
	}

	return strings.Join(visible, "\n")
}
