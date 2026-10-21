package rules_test

import (
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

func TestCheckPermissions(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantHits int
		wantSev  model.Severity
	}{
		{
			name:     "wildcard allow",
			content:  `{"allow": ["*"]}`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name: "wildcard allow pretty-printed",
			content: `{
  "permissions": {
    "allow": [
      "Bash(*)",
      "*"
    ],
    "deny": []
  }
}`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name: "allow without wildcard",
			content: `{
  "permissions": {
    "allow": [
      "Bash(ls)"
    ]
  }
}`,
			wantHits: 0,
		},
		{
			name:     "sandbox disabled",
			content:  `sandbox = false`,
			wantHits: 1,
			wantSev:  model.SeverityWarning,
		},
		{
			name:     "claude bypass permissions",
			content:  `{"permissions": {"defaultMode": "bypassPermissions"}}`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "claude auto-approve project mcp",
			content:  `{"enableAllProjectMcpServers": true}`,
			wantHits: 1,
			wantSev:  model.SeverityWarning,
		},
		{
			name:     "codex danger-full-access",
			content:  `sandbox_mode = "danger-full-access"`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "codex approval never",
			content:  `approval_policy = "never"`,
			wantHits: 1,
			wantSev:  model.SeverityWarning,
		},
		{
			name:     "safe config",
			content:  `{"model": "claude-opus-4-5"}`,
			wantHits: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.CheckPermissions("test", "config.json", tt.content)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
			if tt.wantHits > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tt.wantSev)
			}
		})
	}
}
