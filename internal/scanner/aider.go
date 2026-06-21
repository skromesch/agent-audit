package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type AiderScanner struct{}

func NewAiderScanner() *AiderScanner { return &AiderScanner{} }

func (s *AiderScanner) Name() string { return "Aider" }

// parseYAMLKeyVal parses a line like: key: value or key: "value"
func parseYAMLKeyVal(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	// Strip surrounding quotes if present.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// parseAiderYAML extracts top-level scalar key: value pairs from YAML content.
func parseAiderYAML(content string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments, blank lines, and indented lines (nested structures).
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line != trimmed {
			// Indented line — part of a nested structure, skip.
			continue
		}
		key, val, ok := parseYAMLKeyVal(trimmed)
		if !ok || val == "" {
			continue
		}
		result[key] = val
	}
	return result
}

func (s *AiderScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}
	cfg := &model.AgentConfig{Tool: "Aider", Settings: map[string]string{}}
	found := false

	entries, err := os.ReadDir(root)
	if err != nil {
		return result, nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, ".aider") {
			continue
		}
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)
		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)

		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			kv := parseAiderYAML(content)
			if m, ok := kv["model"]; ok {
				cfg.Settings["model"] = m
			}
		}
	}

	if found {
		result.Agent = cfg
	}
	return result, nil
}
