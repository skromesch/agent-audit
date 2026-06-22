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

type mcpEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

type mcpFile struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
}

// claudeJSON is the structure of ~/.claude.json relevant to MCP.
type claudeJSON struct {
	MCPServers map[string]mcpEntry            `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]mcpEntry `json:"mcpServers"`
	} `json:"projects"`
}

func scopeForPath(path, home string) string {
	if home != "" && strings.HasPrefix(path, home) {
		return "global"
	}
	return "project"
}

func (s *MCPScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}
	home, _ := os.UserHomeDir()

	locations := []string{
		filepath.Join(root, ".mcp.json"),
		filepath.Join(root, "mcp.json"),
		filepath.Join(root, ".claude", "mcp.json"),
		filepath.Join(root, ".codex", "mcp.json"),
		filepath.Join(root, ".codex", "config.toml"),
		filepath.Join(root, ".cursor", "mcp.json"),
		filepath.Join(root, ".continue", "mcp.json"),
	}

	if home != "" {
		locations = append(locations,
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".claude", "mcp.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".codex", "mcp.json"),
			filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(home, ".gemini", "settings.json"),
		)
	}

	for _, path := range locations {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result.Files = append(result.Files, path)
		content := string(data)

		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)

		// TOML files (Codex config) need a different parser
		var servers map[string]mcpEntry
		if strings.HasSuffix(path, ".toml") {
			servers = parseCodexMCPTOML(content)
		} else {
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
			servers = mf.MCPServers
		}

		for name, srv := range servers {
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
				Scope:   scopeForPath(path, home),
			}
			result.MCPServers = append(result.MCPServers, server)
			result.Findings = append(result.Findings, rules.CheckMCPCommands(server)...)
		}
	}

	// ~/.claude.json — Claude Code's main user config
	if home != "" {
		result.MCPServers = append(result.MCPServers,
			s.scanClaudeJSON(filepath.Join(home, ".claude.json"), root, home, result)...)
	}

	return result, nil
}

func (s *MCPScanner) scanClaudeJSON(path, root, home string, result *ScannerResult) []model.MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var cj claudeJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil
	}

	var servers []model.MCPServer

	addServers := func(m map[string]mcpEntry, scope, source string) {
		for name, srv := range m {
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
				Source:  source,
				Scope:   scope,
			}
			servers = append(servers, server)
			result.Findings = append(result.Findings, rules.CheckMCPCommands(server)...)
			result.Findings = append(result.Findings, rules.ScanForSecrets(source, srv.Command)...)
		}
	}

	// Global MCP servers (top-level)
	if len(cj.MCPServers) > 0 {
		result.Files = append(result.Files, path)
		addServers(cj.MCPServers, "global", path)
	}

	// Project-specific MCP servers registered for the current root
	absRoot, _ := filepath.Abs(root)
	if proj, ok := cj.Projects[absRoot]; ok && len(proj.MCPServers) > 0 {
		if len(cj.MCPServers) == 0 {
			result.Files = append(result.Files, path)
		}
		addServers(proj.MCPServers, "project", path)
	}

	return servers
}

// parseCodexMCPTOML extracts [mcp_servers.*] entries from a Codex TOML config.
func parseCodexMCPTOML(content string) map[string]mcpEntry {
	servers := map[string]mcpEntry{}
	var currentServer string
	inEnv := false

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)

		// Section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := line[1 : len(line)-1]
			if strings.HasPrefix(inner, "mcp_servers.") {
				rest := strings.TrimPrefix(inner, "mcp_servers.")
				if strings.Contains(rest, ".env") {
					// [mcp_servers.NAME.env]
					currentServer = strings.TrimSuffix(rest, ".env")
					inEnv = true
				} else {
					currentServer = rest
					inEnv = false
					if _, ok := servers[currentServer]; !ok {
						servers[currentServer] = mcpEntry{}
					}
				}
			} else {
				currentServer = ""
				inEnv = false
			}
			continue
		}

		if currentServer == "" {
			continue
		}

		key, val, ok := parseTOMLKeyVal(line)
		if !ok {
			continue
		}

		entry := servers[currentServer]
		if inEnv {
			if entry.Env == nil {
				entry.Env = map[string]string{}
			}
			entry.Env[key] = val
		} else {
			switch key {
			case "command":
				entry.Command = val
			case "args":
				entry.Args = parseTOMLStringArray(val)
			}
		}
		servers[currentServer] = entry
	}
	return servers
}

// parseTOMLStringArray parses a TOML inline array like ["a", "b", "c"]
func parseTOMLStringArray(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil
	}
	s = s[1 : len(s)-1]
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
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
