package model_test

import (
	"testing"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
)

func TestCriticalCount(t *testing.T) {
	r := model.ScanResult{
		Root:      "/test",
		ScannedAt: time.Now(),
		Findings: []model.Finding{
			{Severity: model.SeverityCritical},
			{Severity: model.SeverityWarning},
			{Severity: model.SeverityCritical},
			{Severity: model.SeverityInfo},
		},
	}
	if got := r.CriticalCount(); got != 2 {
		t.Errorf("CriticalCount() = %d, want 2", got)
	}
}

func TestWarningCount(t *testing.T) {
	r := model.ScanResult{
		Root:      "/test",
		ScannedAt: time.Now(),
		Findings: []model.Finding{
			{Severity: model.SeverityCritical},
			{Severity: model.SeverityWarning},
			{Severity: model.SeverityWarning},
		},
	}
	if got := r.WarningCount(); got != 2 {
		t.Errorf("WarningCount() = %d, want 2", got)
	}
}

func TestSeverityConstants(t *testing.T) {
	if model.SeverityInfo != "INFO" {
		t.Errorf("SeverityInfo = %q, want %q", model.SeverityInfo, "INFO")
	}
	if model.SeverityWarning != "WARNING" {
		t.Errorf("SeverityWarning = %q, want %q", model.SeverityWarning, "WARNING")
	}
	if model.SeverityCritical != "CRITICAL" {
		t.Errorf("SeverityCritical = %q, want %q", model.SeverityCritical, "CRITICAL")
	}
}

func TestEmptyScanResult(t *testing.T) {
	r := model.ScanResult{}
	if r.CriticalCount() != 0 {
		t.Error("empty result should have 0 critical findings")
	}
	if r.WarningCount() != 0 {
		t.Error("empty result should have 0 warning findings")
	}
}
