package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type ClaudeScanner struct{}

func NewClaudeScanner() *ClaudeScanner { return &ClaudeScanner{} }

func (s *ClaudeScanner) Name() string { return "Claude Code" }

func (s *ClaudeScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	candidates := []string{
		filepath.Join(root, "CLAUDE.md"),
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(root, ".claude", "settings.local.json"),
		filepath.Join(root, ".mcp.json"),
	}

	// Also check user-level settings
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		candidates = append(candidates,
			filepath.Join(home, ".claude", "settings.json"),
		)
	}

	cfg := &model.AgentConfig{Tool: "Claude Code", Settings: map[string]string{}}
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
		result.Findings = append(result.Findings, rules.CheckPermissions("Claude Code", path, content)...)

		base := filepath.Base(path)
		if base == "settings.json" || base == "settings.local.json" {
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				if m, ok := raw["model"]; ok {
					var modelVal string
					if json.Unmarshal(m, &modelVal) == nil {
						cfg.Settings["model"] = modelVal
					}
				}
				result.Findings = append(result.Findings, checkClaudeHooks(raw, path)...)
			}
		}
	}

	// Subagents can define their own tool permissions and occasionally leak
	// secrets pasted into their instructions; scan them like any other config file.
	found = scanClaudeAgentsDir(filepath.Join(root, ".claude", "agents"), result, cfg) || found
	if homeErr == nil {
		found = scanClaudeAgentsDir(filepath.Join(home, ".claude", "agents"), result, cfg) || found
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}

// checkClaudeHooks extracts hook commands from a settings.json "hooks" block
// and checks them for dangerous patterns, the same way MCP server commands are checked.
func checkClaudeHooks(raw map[string]json.RawMessage, path string) []model.Finding {
	hooksRaw, ok := raw["hooks"]
	if !ok {
		return nil
	}
	// hooks: { "<EventName>": [ { "matcher": "...", "hooks": [ {"type": "command", "command": "..."} ] } ] }
	var events map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(hooksRaw, &events) != nil {
		return nil
	}
	var findings []model.Finding
	for event, matchers := range events {
		for _, matcher := range matchers {
			for _, h := range matcher.Hooks {
				if h.Type != "command" || h.Command == "" {
					continue
				}
				findings = append(findings, rules.CheckHookCommands(event, h.Command, path)...)
			}
		}
	}
	return findings
}

// scanClaudeAgentsDir scans a .claude/agents directory of subagent markdown
// files for secrets and dangerous permissions. Returns true if any file was found.
func scanClaudeAgentsDir(dir string, result *ScannerResult, cfg *model.AgentConfig) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	found := false
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)
		result.Findings = append(result.Findings, rules.CheckPermissions("Claude Code", path, content)...)
	}
	return found
}
