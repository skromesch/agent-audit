package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type CodexScanner struct{}

func NewCodexScanner() *CodexScanner { return &CodexScanner{} }

func (s *CodexScanner) Name() string { return "Codex" }

// parseCodexTOML extracts model, approval_policy and sandbox_mode from a
// Codex config.toml. Top-level keys win; otherwise the first value found in a
// [profiles.<name>] table (or the legacy [profile.<name>]) is used. The legacy
// "approval" key is still accepted as approval_policy.
func parseCodexTOML(content string) map[string]string {
	top := map[string]string{}
	prof := map[string]string{}
	section := "" // "" = top level, "profile" = inside a profile table, "other"
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			if strings.HasPrefix(line, "[profiles.") || strings.HasPrefix(line, "[profile.") {
				section = "profile"
			} else {
				section = "other"
			}
			continue
		}
		key, val, ok := parseTOMLKeyVal(line)
		if !ok {
			continue
		}
		if key == "approval" {
			key = "approval_policy"
		}
		if key != "model" && key != "approval_policy" && key != "sandbox_mode" {
			continue
		}
		switch section {
		case "":
			top[key] = val
		case "profile":
			if _, seen := prof[key]; !seen {
				prof[key] = val
			}
		}
	}
	for k, v := range prof {
		if _, ok := top[k]; !ok {
			top[k] = v
		}
	}
	return top
}

// parseTOMLKeyVal parses a line like: key = "value" or key = value
func parseTOMLKeyVal(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	// Strip surrounding quotes (and any trailing inline comment) if present.
	// Both basic ("...") and literal ('...') TOML strings.
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			value = value[1 : end+1]
		}
	}
	key = strings.Trim(key, `"`)
	return key, value, true
}

func (s *CodexScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "AGENTS.md"),
		filepath.Join(root, ".codex", "config.toml"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(home, ".codex", "auth.json"),
			filepath.Join("/etc", "codex", "config.toml"),
		)
		// Per-profile overrides: $CODEX_HOME/<profile>.config.toml
		if matches, err := filepath.Glob(filepath.Join(home, ".codex", "*.config.toml")); err == nil {
			candidates = append(candidates, matches...)
		}
	} else {
		candidates = append(candidates, filepath.Join("/etc", "codex", "config.toml"))
	}

	cfg := &model.AgentConfig{Tool: "Codex", Settings: map[string]string{}}
	found := false

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)

		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
		result.Findings = append(result.Findings, rules.CheckPermissions("Codex", path, content)...)

		if filepath.Ext(path) == ".toml" {
			for k, v := range parseCodexTOML(content) {
				cfg.Settings[k] = v
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
