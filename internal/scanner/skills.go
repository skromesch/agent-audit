package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
)

type SkillsScanner struct{}

func NewSkillsScanner() *SkillsScanner { return &SkillsScanner{} }

func (s *SkillsScanner) Name() string { return "Skills" }

type skillRootMeta struct {
	path  string
	agent string
	scope string
}

func (s *SkillsScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	home, _ := os.UserHomeDir()

	roots := []skillRootMeta{
		{filepath.Join(root, "skills"), "", "project"},
		{filepath.Join(root, ".claude", "skills"), "Claude Code", "project"},
	}
	if home != "" {
		roots = append(roots, skillRootMeta{filepath.Join(home, ".claude", "skills"), "Claude Code", "global"})
		for _, p := range pluginSkillRoots(home) {
			roots = append(roots, skillRootMeta{p, "Claude Code", "global"})
		}
		roots = append(roots, skillRootMeta{filepath.Join(home, ".codex", "skills"), "Codex", "global"})
		roots = append(roots, skillRootMeta{filepath.Join(home, ".codex", "skills", ".system"), "Codex", "global"})
		for _, p := range codexPluginSkillRoots(home) {
			roots = append(roots, skillRootMeta{p, "Codex", "global"})
		}
	}

	seen := map[string]bool{}
	for _, r := range roots {
		entries, err := os.ReadDir(r.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			skillPath := filepath.Join(r.path, e.Name())
			if seen[skillPath] {
				continue
			}
			seen[skillPath] = true
			skill := scanSkillDir(skillPath, e.Name())
			skill.Agent = r.agent
			skill.Scope = r.scope
			result.Skills = append(result.Skills, skill)
		}
	}

	return result, nil
}

// pluginSkillRoots reads ~/.claude/plugins/installed_plugins.json and returns
// the skills/ subdirectory of each installed plugin's latest installPath.
func pluginSkillRoots(home string) []string {
	registryPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(registryPath)
	if err != nil {
		return nil
	}

	var registry struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil
	}

	var roots []string
	for _, installs := range registry.Plugins {
		if len(installs) == 0 {
			continue
		}
		// last entry is the most recently installed version
		latest := installs[len(installs)-1]
		skillsDir := filepath.Join(latest.InstallPath, "skills")
		roots = append(roots, skillsDir)
	}
	return roots
}

// codexPluginSkillRoots scans ~/.codex/plugins/cache/<marketplace>/<plugin>/<version>/skills/
func codexPluginSkillRoots(home string) []string {
	cacheDir := filepath.Join(home, ".codex", "plugins", "cache")
	marketplaces, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil
	}
	var roots []string
	for _, marketplace := range marketplaces {
		if !marketplace.IsDir() {
			continue
		}
		pluginsDir := filepath.Join(cacheDir, marketplace.Name())
		plugins, err := os.ReadDir(pluginsDir)
		if err != nil {
			continue
		}
		for _, plugin := range plugins {
			if !plugin.IsDir() {
				continue
			}
			versionsDir := filepath.Join(pluginsDir, plugin.Name())
			versions, err := os.ReadDir(versionsDir)
			if err != nil {
				continue
			}
			for _, version := range versions {
				if !version.IsDir() {
					continue
				}
				skillsDir := filepath.Join(versionsDir, version.Name(), "skills")
				if _, err := os.Stat(skillsDir); err == nil {
					roots = append(roots, skillsDir)
				}
			}
		}
	}
	return roots
}

func scanSkillDir(path, name string) model.Skill {
	skill := model.Skill{Name: name, Path: path}

	// Accept both SKILL.md (plugin convention) and skill.md (project convention)
	mdPath := ""
	for _, candidate := range []string{"SKILL.md", "skill.md"} {
		p := filepath.Join(path, candidate)
		if _, err := os.Stat(p); err == nil {
			mdPath = p
			break
		}
	}
	if mdPath == "" {
		skill.Valid = false
		skill.Issues = append(skill.Issues, "missing skill.md")
		return skill
	}

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
