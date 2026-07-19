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

// parseCodexTOML extracts model and approval values from a simple
// [profile.<name>] TOML structure. Returns (model, approval) from the
// first profile encountered.
func parseCodexTOML(content string) (model string, approval string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	inProfile := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[profile.") {
			inProfile = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inProfile = false
			continue
		}
		if !inProfile {
			continue
		}
		key, val, ok := parseTOMLKeyVal(line)
		if !ok {
			continue
		}
		switch key {
		case "model":
			if model == "" {
				model = val
			}
		case "approval":
			if approval == "" {
				approval = val
			}
		}
	}
	return model, approval
}

// parseTOMLKeyVal parses a line like: key = "value" or key = value
func parseTOMLKeyVal(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	// Strip surrounding quotes if present.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
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
			modelVal, approvalVal := parseCodexTOML(content)
			if modelVal != "" {
				cfg.Settings["model"] = modelVal
			}
			if approvalVal != "" {
				cfg.Settings["approval"] = approvalVal
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
