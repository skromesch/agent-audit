package scanner

import (
	"context"
	"encoding/json"
	"fmt"
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
	URL     string            `json:"url"`
	HTTPURL string            `json:"httpUrl"` // Gemini CLI streamable HTTP
	Headers map[string]string `json:"headers"`
	Trust   bool              `json:"trust"` // Gemini CLI: skip tool confirmations
}

// openCodeFile is the MCP-relevant part of opencode.json(c): servers live
// under "mcp", local commands are a single argv array.
type openCodeFile struct {
	MCP map[string]struct {
		Type        string            `json:"type"`
		Command     []string          `json:"command"`
		Environment map[string]string `json:"environment"`
		URL         string            `json:"url"`
		Headers     map[string]string `json:"headers"`
	} `json:"mcp"`
}

type mcpFile struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
}

// claudeJSON is the structure of ~/.claude.json relevant to MCP.
type claudeJSON struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
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
		filepath.Join(root, ".continue", "config.yaml"),
		filepath.Join(root, ".gemini", "settings.json"),
		filepath.Join(root, "opencode.json"),
		filepath.Join(root, "opencode.jsonc"),
	}
	// Continue.dev standalone MCP blocks.
	if matches, err := filepath.Glob(filepath.Join(root, ".continue", "mcpServers", "*.yaml")); err == nil {
		locations = append(locations, matches...)
	}

	if home != "" {
		locations = append(locations,
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".claude", "mcp.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".codex", "mcp.json"),
			filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(home, ".gemini", "settings.json"),
			filepath.Join(home, ".continue", "config.yaml"),
			filepath.Join(home, ".config", "opencode", "opencode.json"),
			filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
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

		// TOML (Codex) and YAML (Continue.dev) configs need dedicated parsers.
		var servers map[string]mcpEntry
		switch {
		case strings.HasSuffix(path, ".toml"):
			servers = parseCodexMCPTOML(content)
		case strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml"):
			servers = parseContinueMCPYAML(content)
		case strings.HasPrefix(filepath.Base(path), "opencode."):
			// JSONC with comments won't parse; skip silently rather than
			// reporting a valid config as malformed.
			servers = parseOpenCodeMCP(data)
		default:
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
			server, findings := buildMCPServer(name, srv, path, scopeForPath(path, home))
			result.MCPServers = append(result.MCPServers, server)
			result.Findings = append(result.Findings, findings...)
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
			server, findings := buildMCPServer(name, srv, source, scope)
			servers = append(servers, server)
			result.Findings = append(result.Findings, findings...)
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

// buildMCPServer converts a parsed entry into a model.MCPServer with secret
// env and header values masked, and returns the security findings for it.
func buildMCPServer(name string, srv mcpEntry, source, scope string) (model.MCPServer, []model.Finding) {
	maskedEnv := make(map[string]string, len(srv.Env))
	for k, v := range srv.Env {
		if looksLikeSecret(k) {
			maskedEnv[k] = rules.MaskSecret(v)
		} else {
			maskedEnv[k] = v
		}
	}
	var maskedHeaders map[string]string
	if len(srv.Headers) > 0 {
		maskedHeaders = make(map[string]string, len(srv.Headers))
		for k, v := range srv.Headers {
			if looksLikeSecretHeader(k) {
				maskedHeaders[k] = rules.MaskSecret(v)
			} else {
				maskedHeaders[k] = v
			}
		}
	}
	url := srv.URL
	if url == "" {
		url = srv.HTTPURL
	}
	server := model.MCPServer{
		Name:    name,
		Command: srv.Command,
		Args:    srv.Args,
		Env:     maskedEnv,
		URL:     url,
		Headers: maskedHeaders,
		Source:  source,
		Scope:   scope,
	}
	findings := rules.CheckMCPCommands(server)
	for k, v := range srv.Headers {
		if looksLikeSecretHeader(k) && v != "" && !strings.Contains(v, "${") && !strings.HasPrefix(v, "$") {
			findings = append(findings, model.Finding{
				Tool:        "security",
				Category:    "secrets",
				Scope:       scope,
				Path:        source,
				Severity:    model.SeverityCritical,
				Description: fmt.Sprintf("MCP server %q has a hardcoded %s header", name, k),
				Details:     map[string]string{"masked_value": rules.MaskSecret(v), "server": name},
			})
		}
	}
	if srv.Trust {
		findings = append(findings, model.Finding{
			Tool:        "security",
			Category:    "permissions",
			Scope:       scope,
			Path:        source,
			Severity:    model.SeverityWarning,
			Description: fmt.Sprintf("MCP server %q is trusted — tool call confirmations are bypassed", name),
			Details:     map[string]string{"server": name},
		})
	}
	return server, findings
}

// parseOpenCodeMCP extracts the "mcp" block of an opencode.json(c) file.
func parseOpenCodeMCP(data []byte) map[string]mcpEntry {
	var f openCodeFile
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	servers := make(map[string]mcpEntry, len(f.MCP))
	for name, srv := range f.MCP {
		e := mcpEntry{Env: srv.Environment, URL: srv.URL, Headers: srv.Headers}
		if len(srv.Command) > 0 {
			e.Command = srv.Command[0]
			e.Args = srv.Command[1:]
		}
		servers[name] = e
	}
	return servers
}

// parseCodexMCPTOML extracts [mcp_servers.*] entries from a Codex TOML config.
func parseCodexMCPTOML(content string) map[string]mcpEntry {
	servers := map[string]mcpEntry{}
	var currentServer string
	inEnv, inHeaders := false, false

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)

		// Section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := line[1 : len(line)-1]
			if strings.HasPrefix(inner, "mcp_servers.") {
				rest := strings.TrimPrefix(inner, "mcp_servers.")
				if strings.HasSuffix(rest, ".env") {
					// [mcp_servers.NAME.env]
					currentServer = strings.TrimSuffix(rest, ".env")
					inEnv, inHeaders = true, false
				} else if strings.HasSuffix(rest, ".http_headers") {
					// [mcp_servers.NAME.http_headers]
					currentServer = strings.TrimSuffix(rest, ".http_headers")
					inEnv, inHeaders = false, true
				} else {
					currentServer = rest
					inEnv, inHeaders = false, false
					if _, ok := servers[currentServer]; !ok {
						servers[currentServer] = mcpEntry{}
					}
				}
			} else {
				currentServer = ""
				inEnv, inHeaders = false, false
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
		switch {
		case inEnv:
			if entry.Env == nil {
				entry.Env = map[string]string{}
			}
			entry.Env[key] = val
		case inHeaders:
			if entry.Headers == nil {
				entry.Headers = map[string]string{}
			}
			entry.Headers[key] = val
		default:
			switch key {
			case "command":
				entry.Command = val
			case "args":
				entry.Args = parseTOMLStringArray(val)
			case "url":
				entry.URL = val
			case "env":
				entry.Env = parseTOMLInlineTable(val)
			case "http_headers":
				entry.Headers = parseTOMLInlineTable(val)
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

// parseContinueMCPYAML extracts the mcpServers list from a Continue.dev
// config.yaml, e.g.:
//
//	mcpServers:
//	  - name: sqlite
//	    command: uvx
//	    args: [mcp-server-sqlite]
//	    env:
//	      NODE_ENV: production
func parseContinueMCPYAML(content string) map[string]mcpEntry {
	servers := map[string]mcpEntry{}
	lines := strings.Split(content, "\n")

	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "mcpServers:" && indentOf(line) == 0 {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return servers
	}

	var current *mcpEntry
	currentName := ""
	itemIndent := -1
	inArgsBlock, inEnvBlock := false, false

	flush := func() {
		if current != nil && currentName != "" {
			servers[currentName] = *current
		}
	}

	for i := start; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := indentOf(line)
		if indent == 0 {
			break // left the mcpServers block
		}
		if itemIndent == -1 {
			itemIndent = indent
		}

		if strings.HasPrefix(trimmed, "- ") {
			if indent == itemIndent {
				// New mcpServers list entry.
				flush()
				current = &mcpEntry{Env: map[string]string{}}
				currentName = ""
				inArgsBlock, inEnvBlock = false, false
				if key, val, ok := parseYAMLKeyVal(strings.TrimPrefix(trimmed, "- ")); ok && key == "name" {
					currentName = val
				}
				continue
			}
			// Nested list item, e.g. under args:.
			if current != nil && inArgsBlock {
				current.Args = append(current.Args, strings.Trim(strings.TrimPrefix(trimmed, "- "), `"'`))
			}
			continue
		}

		if current == nil {
			continue
		}

		key, val, ok := parseYAMLKeyVal(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "name":
			currentName = val
			inArgsBlock, inEnvBlock = false, false
		case "command":
			current.Command = val
			inArgsBlock, inEnvBlock = false, false
		case "args":
			inEnvBlock = false
			if val != "" {
				current.Args = parseTOMLStringArray(val)
				inArgsBlock = false
			} else {
				inArgsBlock = true
			}
		case "env":
			inArgsBlock = false
			inEnvBlock = val == ""
		default:
			inArgsBlock = false
			if inEnvBlock {
				current.Env[key] = val
			} else {
				inEnvBlock = false
			}
		}
	}
	flush()
	return servers
}

// parseTOMLInlineTable parses a flat TOML inline table like
// { "Authorization" = "Bearer x", X_ID = "y" }.
func parseTOMLInlineTable(s string) map[string]string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil
	}
	m := map[string]string{}
	for _, part := range strings.Split(s[1:len(s)-1], ",") {
		if k, v, ok := parseTOMLKeyVal(strings.TrimSpace(part)); ok && k != "" {
			m[k] = v
		}
	}
	return m
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func looksLikeSecretHeader(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range []string{"auth", "key", "token", "secret"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
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
