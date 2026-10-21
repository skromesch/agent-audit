package tui

import (
	"strings"
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
)

// The list groups servers by agent, so its display order differs from
// result.MCPServers; the cursor must follow the displayed order.
func TestRenderMCPCursorFollowsDisplayOrder(t *testing.T) {
	result := &model.ScanResult{
		Agents: []model.AgentConfig{
			{Tool: "Alpha", ConfigFiles: []string{"/a.json"}},
			{Tool: "Beta", ConfigFiles: []string{"/b.json"}},
		},
		MCPServers: []model.MCPServer{
			{Name: "beta-one", Command: "cmd-beta-one", Source: "/b.json"},
			{Name: "alpha-one", Command: "cmd-alpha-one", Source: "/a.json"},
			{Name: "beta-two", Command: "cmd-beta-two", Source: "/b.json"},
		},
	}
	// Displayed: Alpha → alpha-one, Beta → beta-one, beta-two.
	want := []string{"cmd-alpha-one", "cmd-beta-one", "cmd-beta-two"}
	for cursor, cmd := range want {
		out := renderMCP(result, 120, 24, cursor, 0, 0)
		if !strings.Contains(out, cmd) {
			t.Errorf("cursor %d: detail pane should show %q", cursor, cmd)
		}
		for _, other := range want {
			if other != cmd && strings.Contains(out, other) {
				t.Errorf("cursor %d: detail pane shows %q, want %q", cursor, other, cmd)
			}
		}
	}
}
