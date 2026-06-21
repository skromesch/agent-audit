package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/report"
)

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		Root:      "/test/project",
		ScannedAt: time.Now(),
		Agents:    []model.AgentConfig{{Tool: "Claude Code"}},
		Findings: []model.Finding{
			{Tool: "security", Category: "secrets", Severity: model.SeverityCritical, Description: "API key found"},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteJSON(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var out model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Root != "/test/project" {
		t.Errorf("root = %q", out.Root)
	}
}
