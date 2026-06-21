package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type ContinueScanner struct{}

func NewContinueScanner() *ContinueScanner { return &ContinueScanner{} }

func (s *ContinueScanner) Name() string { return "Continue.dev" }

func (s *ContinueScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, ".continue", "config.yaml"),
		filepath.Join(root, ".continue", "continue.yaml"),
		filepath.Join(root, "continue.yaml"),
		filepath.Join(root, "config.yaml"),
	}

	cfg := &model.AgentConfig{Tool: "Continue.dev", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Continue.dev", path, content)...)
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
