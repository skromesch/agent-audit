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

	if _, err := os.Stat(cursorDir); os.IsNotExist(err) {
		return result, nil
	}

	cfg := &model.AgentConfig{Tool: "Cursor", Settings: map[string]string{}}

	filepath.WalkDir(cursorDir, func(path string, d os.DirEntry, err error) error {
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

	if len(result.Files) > 0 {
		result.Agent = cfg
	}
	return result, nil
}
