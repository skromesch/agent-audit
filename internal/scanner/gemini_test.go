package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestGeminiScannerDetectsGeminiMd(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "GEMINI.md"), []byte("# Gemini instructions"), 0644)

	s := scanner.NewGeminiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent == nil {
		t.Fatal("expected agent config, got nil")
	}
	if result.Agent.Tool != "Gemini CLI" {
		t.Errorf("tool = %q, want %q", result.Agent.Tool, "Gemini CLI")
	}
	var found bool
	for _, f := range result.Files {
		if filepath.Base(f) == "GEMINI.md" {
			found = true
		}
	}
	if !found {
		t.Error("GEMINI.md not listed in config files")
	}
}

func TestGeminiScannerDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "GEMINI.md"), []byte(
		"GOOGLE_API_KEY=AIzaSyAbc123RealKeyHere456789abcdefghijk",
	), 0644)

	s := scanner.NewGeminiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var secretFindings int
	for _, f := range result.Findings {
		if f.Category == "secrets" {
			secretFindings++
		}
	}
	if secretFindings == 0 {
		t.Error("expected secret finding, got none")
	}
}

func TestGeminiScannerNoDetectionWithoutFiles(t *testing.T) {
	dir := t.TempDir()

	// Override HOME so the scanner can't pick up real ~/.gemini/settings.json.
	t.Setenv("HOME", dir)

	s := scanner.NewGeminiScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Agent != nil {
		t.Error("expected no agent config when no Gemini files exist, got one")
	}
}
