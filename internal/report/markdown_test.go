package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skromesch/agent-audit/internal/report"
)

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteMarkdown(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "# agent-audit Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "Claude Code") {
		t.Error("missing agent name")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("missing critical finding")
	}
}
