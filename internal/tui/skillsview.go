package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/skromesch/agent-audit/internal/model"
)

// orderedSkills returns skills in the same order they appear in the left panel:
// sorted agents (named first, Generic last), then project→global per agent.
func orderedSkills(result *model.ScanResult) []model.Skill {
	type agentGroup struct {
		name   string
		scopes map[string][]model.Skill
	}

	index := map[string]*agentGroup{}
	order := []string{}

	for _, sk := range result.Skills {
		agent := sk.Agent
		if agent == "" {
			agent = "Generic"
		}
		if index[agent] == nil {
			index[agent] = &agentGroup{name: agent, scopes: map[string][]model.Skill{}}
			order = append(order, agent)
		}
		index[agent].scopes[sk.Scope] = append(index[agent].scopes[sk.Scope], sk)
	}

	named := []string{}
	for _, a := range order {
		if a != "Generic" {
			named = append(named, a)
		}
	}
	sort.Strings(named)
	if _, ok := index["Generic"]; ok {
		named = append(named, "Generic")
	}

	out := []model.Skill{}
	for _, agent := range named {
		g := index[agent]
		for _, scope := range []string{"project", "global", ""} {
			out = append(out, g.scopes[scope]...)
		}
	}
	return out
}

func renderSkills(result *model.ScanResult, width, height, cursor, focus, rightScroll int) string {
	if result == nil || len(result.Skills) == 0 {
		return StyleMuted.Render("No skills detected.")
	}

	ordered := orderedSkills(result)
	if cursor >= len(ordered) {
		cursor = len(ordered) - 1
	}
	selected := ordered[cursor]

	leftWidth := width / 3
	if leftWidth < 24 {
		leftWidth = 24
	}
	if leftWidth > 44 {
		leftWidth = 44
	}
	rightWidth := width - leftWidth - 2

	innerHeight := height - 2

	leftContent := buildLeftPane(result, ordered, cursor, innerHeight)
	rightContent := buildRightPane(selected, rightWidth-4, innerHeight, rightScroll)

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

func buildLeftPane(result *model.ScanResult, ordered []model.Skill, cursor, visibleHeight int) string {
	type lineItem struct {
		text       string
		skillIndex int // -1 for headers
	}

	index := map[string]map[string][]model.Skill{}
	for _, sk := range result.Skills {
		agent := sk.Agent
		if agent == "" {
			agent = "Generic"
		}
		if index[agent] == nil {
			index[agent] = map[string][]model.Skill{}
		}
		index[agent][sk.Scope] = append(index[agent][sk.Scope], sk)
	}

	named := []string{}
	for a := range index {
		if a != "Generic" {
			named = append(named, a)
		}
	}
	sort.Strings(named)
	if _, ok := index["Generic"]; ok {
		named = append(named, "Generic")
	}

	// build flat list of display lines + which orderedSkills index each skill is at
	lines := []lineItem{}
	skillLineIndex := map[int]int{} // orderedSkills index → line index

	// map skill path → orderedSkills index for lookup
	pathToIdx := map[string]int{}
	for i, sk := range ordered {
		pathToIdx[sk.Path] = i
	}

	agentHeader := lipgloss.NewStyle().Bold(true).Foreground(colorAccent)

	for _, agent := range named {
		scopes := index[agent]
		agentTotal := 0
		for _, ss := range scopes {
			agentTotal += len(ss)
		}
		lines = append(lines, lineItem{
			text:       agentHeader.Render(fmt.Sprintf("%s (%d)", agent, agentTotal)),
			skillIndex: -1,
		})

		for _, scope := range []string{"project", "global", ""} {
			skills, ok := scopes[scope]
			if !ok {
				continue
			}
			label := scope
			if label == "" {
				label = "unknown"
			}
			lines = append(lines, lineItem{
				text:       StyleMuted.Render("  ── " + label),
				skillIndex: -1,
			})
			for _, sk := range skills {
				idx := pathToIdx[sk.Path]
				skillLineIndex[idx] = len(lines)
				status := StyleOK.Render("✓")
				if !sk.Valid {
					status = StyleCritical.Render("✗")
				}
				name := sk.Name
				if idx == cursor {
					name = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("▶ " + name)
				} else {
					name = "  " + name
				}
				lines = append(lines, lineItem{
					text:       fmt.Sprintf("%s %s", status, name),
					skillIndex: idx,
				})
			}
		}
		lines = append(lines, lineItem{text: "", skillIndex: -1})
	}

	// auto-scroll so cursor line is visible
	cursorLine := skillLineIndex[cursor]
	scrollOffset := 0
	if cursorLine >= visibleHeight {
		scrollOffset = cursorLine - visibleHeight/2
	}
	if scrollOffset+visibleHeight > len(lines) {
		scrollOffset = len(lines) - visibleHeight
	}
	if scrollOffset < 0 {
		scrollOffset = 0
	}

	end := scrollOffset + visibleHeight
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	for _, item := range lines[scrollOffset:end] {
		sb.WriteString(item.text + "\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func buildRightPane(sk model.Skill, width, height, scroll int) string {
	content := ""
	if sk.EntryPoint != "" {
		data, err := os.ReadFile(sk.EntryPoint)
		if err == nil {
			content = stripFrontmatter(string(data))
		}
	}

	if content == "" {
		if !sk.Valid {
			content = StyleWarning.Render("Invalid skill: " + strings.Join(sk.Issues, ", "))
		} else {
			content = StyleMuted.Render("No content.")
		}
	}

	// soft-wrap long lines at width
	lines := strings.Split(content, "\n")
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

	// apply scroll offset
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

	// scroll indicators on first/last visible line
	if scroll > 0 && len(visible) > 0 {
		visible[0] = StyleMuted.Render("↑ more above")
	}
	if scroll < maxScroll && len(visible) > 0 {
		visible[len(visible)-1] = StyleMuted.Render("↓ more below")
	}

	return strings.Join(visible, "\n")
}

func stripFrontmatter(content string) string {
	if !strings.HasPrefix(strings.TrimSpace(content), "---") {
		return content
	}
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	return strings.TrimLeft(parts[2], "\n")
}
