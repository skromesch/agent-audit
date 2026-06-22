package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type ClaudeScanner struct{}

func NewClaudeScanner() *ClaudeScanner { return &ClaudeScanner{} }

func (s *ClaudeScanner) Name() string { return "Claude Code" }

func (s *ClaudeScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "CLAUDE.md"),
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(root, ".mcp.json"),
	}

	// Also check user-level settings
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".claude", "settings.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "Claude Code", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Claude Code", path, content)...)

		if filepath.Base(path) == "settings.json" {
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				if m, ok := raw["model"]; ok {
					var modelVal string
					if json.Unmarshal(m, &modelVal) == nil {
						cfg.Settings["model"] = modelVal
					}
				}
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
