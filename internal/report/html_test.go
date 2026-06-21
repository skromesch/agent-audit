package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skromesch/agent-audit/internal/report"
)

func TestWriteHTML(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteHTML(sampleResult(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("missing doctype")
	}
	if !strings.Contains(out, "agent-audit Report") {
		t.Error("missing report title")
	}
}
