package model

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	Tool        string            `json:"tool"`
	Category    string            `json:"category"`
	Scope       string            `json:"scope"`
	Path        string            `json:"path"`
	Severity    Severity          `json:"severity"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}

type MCPServer struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url,omitempty"`     // remote (HTTP/SSE) servers
	Headers map[string]string `json:"headers,omitempty"` // sensitive values masked
	Source  string            `json:"source"`
	Scope   string            `json:"scope"` // "project" or "global"
}

type Skill struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	EntryPoint  string   `json:"entry_point"`
	Valid       bool     `json:"valid"`
	Issues      []string `json:"issues,omitempty"`
	Agent       string   `json:"agent"` // e.g. "Claude Code"
	Scope       string   `json:"scope"` // "project" or "global"
}

type AgentConfig struct {
	Tool        string            `json:"tool"`
	ConfigFiles []string          `json:"config_files"`
	Settings    map[string]string `json:"settings"`
}

type ScanResult struct {
	Root        string        `json:"root"`
	ScannedAt   time.Time     `json:"scanned_at"`
	Agents      []AgentConfig `json:"agents"`
	MCPServers  []MCPServer   `json:"mcp_servers"`
	Skills      []Skill       `json:"skills"`
	Findings    []Finding     `json:"findings"`
	ConfigFiles []string      `json:"config_files"`
}

func (r *ScanResult) CriticalCount() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			n++
		}
	}
	return n
}

func (r *ScanResult) WarningCount() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			n++
		}
	}
	return n
}
