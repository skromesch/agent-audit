package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

type SkillsScanner struct{}

func NewSkillsScanner() *SkillsScanner { return &SkillsScanner{} }

func (s *SkillsScanner) Name() string { return "Skills" }

func (s *SkillsScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	skillRoots := []string{
		filepath.Join(root, "skills"),
		filepath.Join(root, ".claude", "skills"),
	}

	for _, skillRoot := range skillRoots {
		entries, err := os.ReadDir(skillRoot)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			skillPath := filepath.Join(skillRoot, e.Name())
			skill := scanSkillDir(skillPath, e.Name())
			result.Skills = append(result.Skills, skill)
			result.Files = append(result.Files, skillPath)
		}
	}

	return result, nil
}

func scanSkillDir(path, name string) model.Skill {
	skill := model.Skill{Name: name, Path: path}
	mdPath := filepath.Join(path, "skill.md")
	data, err := os.ReadFile(mdPath)
	if err != nil {
		skill.Valid = false
		skill.Issues = append(skill.Issues, "missing skill.md")
		return skill
	}
	skill.Valid = true
	skill.EntryPoint = mdPath
	skill.Description = extractSkillDescription(string(data))
	return skill
}

func extractSkillDescription(content string) string {
	// Try to extract from YAML frontmatter: description: ...
	if strings.Contains(content, "---") {
		parts := strings.SplitN(content, "---", 3)
		if len(parts) >= 2 {
			for _, line := range splitLines(parts[1]) {
				if strings.HasPrefix(strings.TrimSpace(line), "description:") {
					return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "description:"))
				}
			}
		}
	}
	// Fall back to first non-empty, non-header line
	for _, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && trimmed != "---" {
			return trimmed
		}
	}
	return ""
}

func extractFirstLine(content string) string {
	return extractSkillDescription(content)
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
