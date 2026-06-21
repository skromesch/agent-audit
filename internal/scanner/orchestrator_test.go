package scanner_test

import (
	"context"
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/scanner"
)

type stubScanner struct {
	name     string
	findings []model.Finding
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Scan(_ context.Context, _ string) (*scanner.ScannerResult, error) {
	return &scanner.ScannerResult{Findings: s.findings}, nil
}

func TestOrchestratorMergesResults(t *testing.T) {
	scanners := []scanner.Scanner{
		&stubScanner{name: "a", findings: []model.Finding{{Tool: "a", Severity: model.SeverityInfo}}},
		&stubScanner{name: "b", findings: []model.Finding{{Tool: "b", Severity: model.SeverityWarning}}},
	}
	orch := scanner.NewOrchestrator(scanners)
	result, err := orch.Run(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(result.Findings))
	}
}
