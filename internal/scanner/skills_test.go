package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func TestSkillsScannerValidSkill(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skills", "my-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "skill.md"), []byte(`---
name: my-skill
description: Does something useful
---
# My Skill
Instructions here.
`), 0644)

	s := scanner.NewSkillsScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skills) != 1 {
		t.Fatalf("got %d skills, want 1", len(result.Skills))
	}
	if !result.Skills[0].Valid {
		t.Error("expected valid skill")
	}
}

func TestSkillsScannerInvalidSkill(t *testing.T) {
	dir := t.TempDir()
	// Skill dir without skill.md
	skillDir := filepath.Join(dir, "skills", "broken-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "README.md"), []byte("no skill.md here"), 0644)

	s := scanner.NewSkillsScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skills) != 1 {
		t.Fatalf("got %d skills, want 1", len(result.Skills))
	}
	if result.Skills[0].Valid {
		t.Error("expected invalid skill")
	}
	if len(result.Skills[0].Issues) == 0 {
		t.Error("expected issues on invalid skill")
	}
}
