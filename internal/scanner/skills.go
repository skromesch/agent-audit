package scanner

import (
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
)

func scanSkillDir(path, name string) model.Skill {
	skill := model.Skill{Name: name, Path: path, Valid: false}
	mdPath := filepath.Join(path, "skill.md")
	if data, err := os.ReadFile(mdPath); err == nil {
		skill.Valid = true
		skill.EntryPoint = mdPath
		skill.Description = extractFirstLine(string(data))
	} else {
		skill.Issues = append(skill.Issues, "missing skill.md")
	}
	return skill
}

func extractFirstLine(content string) string {
	for _, line := range splitLines(content) {
		if len(line) >= 3 && line[:3] != "---" {
			return line
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
