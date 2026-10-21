package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type CursorScanner struct{}

func NewCursorScanner() *CursorScanner { return &CursorScanner{} }

func (s *CursorScanner) Name() string { return "Cursor" }

func (s *CursorScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}
	cursorDir := filepath.Join(root, ".cursor")
	cfg := &model.AgentConfig{Tool: "Cursor", Settings: map[string]string{}}

	if _, err := os.Stat(cursorDir); err == nil {
		// The callback swallows per-entry errors, so WalkDir itself can't fail meaningfully.
		_ = filepath.WalkDir(cursorDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			result.Files = append(result.Files, path)
			cfg.ConfigFiles = append(cfg.ConfigFiles, path)
			content := string(data)
			result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
			result.Findings = append(result.Findings, rules.CheckPermissions("Cursor", path, content)...)
			return nil
		})
	}

	// Legacy root-level rules file, still honored by Cursor for backward compatibility.
	legacyPath := filepath.Join(root, ".cursorrules")
	if data, err := os.ReadFile(legacyPath); err == nil {
		result.Files = append(result.Files, legacyPath)
		cfg.ConfigFiles = append(cfg.ConfigFiles, legacyPath)
		content := string(data)
		result.Findings = append(result.Findings, rules.ScanForSecrets(legacyPath, content)...)
		result.Findings = append(result.Findings, rules.CheckPermissions("Cursor", legacyPath, content)...)
	}

	if len(result.Files) > 0 {
		result.Agent = cfg
	}
	return result, nil
}
