package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestContinueScannerDetectsConfig(t *testing.T) {
	dir := t.TempDir()
	continueDir := filepath.Join(dir, ".continue")
	os.MkdirAll(continueDir, 0755)
	os.WriteFile(filepath.Join(continueDir, "config.yaml"), []byte(`
models:
  - name: claude-3-5-sonnet
    provider: anthropic
`), 0644)

	s := scanner.NewContinueScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent")
	}
}

func TestContinueScannerIgnoresUnrelatedRootConfigYAML(t *testing.T) {
	dir := t.TempDir()
	setHome(t, t.TempDir())
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("server:\n  port: 8080\n"), 0644)

	result, err := scanner.NewContinueScanner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent != nil {
		t.Errorf("root config.yaml must not trigger Continue.dev detection, got files %v", result.Agent.ConfigFiles)
	}
}

func TestContinueScannerDetectsBlockFolder(t *testing.T) {
	dir := t.TempDir()
	setHome(t, t.TempDir())
	os.MkdirAll(filepath.Join(dir, ".continue", "mcpServers"), 0755)
	os.WriteFile(filepath.Join(dir, ".continue", "mcpServers", "db.yaml"), []byte("name: db\nmcpServers: []\n"), 0644)

	result, err := scanner.NewContinueScanner().Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent from .continue/mcpServers block")
	}
}
