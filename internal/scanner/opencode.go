package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type OpenCodeScanner struct{}

func NewOpenCodeScanner() *OpenCodeScanner { return &OpenCodeScanner{} }

func (s *OpenCodeScanner) Name() string { return "OpenCode" }

func (s *OpenCodeScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "opencode.json"),
		filepath.Join(root, "opencode.jsonc"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".config", "opencode", "opencode.json"),
			filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
			filepath.Join(home, ".local", "share", "opencode", "auth.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "OpenCode", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("OpenCode", path, content)...)

		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) == nil {
			if m, ok := raw["model"]; ok {
				var modelVal string
				if json.Unmarshal(m, &modelVal) == nil {
					if _, exists := cfg.Settings["model"]; !exists {
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
