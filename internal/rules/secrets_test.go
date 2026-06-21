package rules_test

import (
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

func TestScanForSecrets(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantHits int
		wantSev  model.Severity
	}{
		{
			name:     "openai key",
			content:  `OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "anthropic key",
			content:  `ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "github token",
			content:  `GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456`,
			wantHits: 1,
			wantSev:  model.SeverityCritical,
		},
		{
			name:     "no secrets",
			content:  `model = "gpt-4"`,
			wantHits: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.ScanForSecrets("config.json", tt.content)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
			if tt.wantHits > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"sk-proj-abc123def456", "sk-************f456"},
		{"short", "shor************hort"},
		{"ab", "ab************ab"},
	}
	for _, c := range cases {
		got := rules.MaskSecret(c.in)
		if got == c.in {
			t.Errorf("MaskSecret(%q) returned unmasked value", c.in)
		}
	}
}
