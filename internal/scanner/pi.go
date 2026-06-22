package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

type PiScanner struct{}

func NewPiScanner() *PiScanner { return &PiScanner{} }

func (s *PiScanner) Name() string { return "Pi" }

func (s *PiScanner) Scan(ctx context.Context, root string) (*ScannerResult, error) {
	result := &ScannerResult{}

	// Pi-specific files — presence of any one confirms this is a Pi project.
	piSpecific := []string{
		filepath.Join(root, "SYSTEM.md"),
		filepath.Join(root, "models.json"),
	}

	// AGENTS.md is shared with Codex; include it but don't use it for detection.
	agentsMd := filepath.Join(root, "AGENTS.md")

	// Global Pi directory also counts as a Pi-specific marker.
	globalPiDir := ""
	if home, err := os.UserHomeDir(); err == nil {
		globalPiDir = filepath.Join(home, ".pi", "agent")
	}

	cfg := &model.AgentConfig{Tool: "Pi", Settings: map[string]string{}}
	piDetected := false

	// Check Pi-specific project files.
	for _, path := range piSpecific {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		piDetected = true
		result.Files = append(result.Files, path)
		cfg.ConfigFiles = append(cfg.ConfigFiles, path)
		content := string(data)

		result.Findings = append(result.Findings, rules.ScanForSecrets(path, content)...)

		if filepath.Base(path) == "models.json" {
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				for k, v := range raw {
					var strVal string
					if json.Unmarshal(v, &strVal) == nil {
						cfg.Settings[k] = strVal
					}
				}
			}
		}
	}

	// Check global ~/.pi/agent/ directory.
	if globalPiDir != "" {
		if info, err := os.Stat(globalPiDir); err == nil && info.IsDir() {
			piDetected = true
		}
	}

	if !piDetected {
		return result, nil
	}

	// Include AGENTS.md in config files if present.
	if data, err := os.ReadFile(agentsMd); err == nil {
		result.Files = append(result.Files, agentsMd)
		cfg.ConfigFiles = append(cfg.ConfigFiles, agentsMd)
		result.Findings = append(result.Findings, rules.ScanForSecrets(agentsMd, string(data))...)
	}

	result.Agent = cfg
	return result, nil
}
