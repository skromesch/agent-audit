package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type MCPScanner struct{}

func NewMCPScanner() *MCPScanner { return &MCPScanner{} }

func (s *MCPScanner) Name() string { return "MCP" }

type mcpFile struct {
	MCPServers map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
}

func (s *MCPScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	locations := []string{
		filepath.Join(root, ".mcp.json"),
		filepath.Join(root, "mcp.json"),
		filepath.Join(root, ".claude", "mcp.json"),
		filepath.Join(root, ".codex", "mcp.json"),
		filepath.Join(root, ".cursor", "mcp.json"),
		filepath.Join(root, ".continue", "mcp.json"),
	}

	for _, path := range locations {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result.Files = append(result.Files, path)

		// Scan raw content for secrets
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, string(data))...)

		var mf mcpFile
		if err := json.Unmarshal(data, &mf); err != nil {
			result.Findings = append(result.Findings, model.Finding{
				Tool:        "MCP",
				Category:    "config",
				Scope:       "project",
				Path:        path,
				Severity:    model.SeverityWarning,
				Description: "Malformed MCP JSON: " + err.Error(),
			})
			continue
		}

		for name, srv := range mf.MCPServers {
			// Mask env secrets before storing
			maskedEnv := make(map[string]string, len(srv.Env))
			for k, v := range srv.Env {
				if looksLikeSecret(k) {
					maskedEnv[k] = rules.MaskSecret(v)
				} else {
					maskedEnv[k] = v
				}
			}

			server := model.MCPServer{
				Name:    name,
				Command: srv.Command,
				Args:    srv.Args,
				Env:     maskedEnv,
				Source:  path,
			}
			result.MCPServers = append(result.MCPServers, server)
			result.Findings = append(result.Findings, rules.CheckMCPCommands(server)...)
		}
	}

	return result, nil
}

func looksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range []string{"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL"} {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}
