package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type GeminiScanner struct{}

func NewGeminiScanner() *GeminiScanner { return &GeminiScanner{} }

func (s *GeminiScanner) Name() string { return "Gemini CLI" }

func (s *GeminiScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "GEMINI.md"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".gemini", "settings.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "Gemini CLI", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Gemini CLI", path, content)...)

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
