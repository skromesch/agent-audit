package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skromesch/agent-audit/internal/model"
	"github.com/skromesch/agent-audit/internal/scanner"
)

func findSkill(skills []model.Skill, name string) *model.Skill {
	for i := range skills {
		if skills[i].Name == name {
			return &skills[i]
		}
	}
	return nil
}

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

	found := findSkill(result.Skills, "my-skill")
	if found == nil {
		t.Fatalf("skill 'my-skill' not found in %d skills", len(result.Skills))
	}
	if !found.Valid {
		t.Error("expected valid skill")
	}
}

func TestSkillsScannerInvalidSkill(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skills", "broken-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "README.md"), []byte("no skill.md here"), 0644)

	s := scanner.NewSkillsScanner()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	found := findSkill(result.Skills, "broken-skill")
	if found == nil {
		t.Fatalf("skill 'broken-skill' not found in %d skills", len(result.Skills))
	}
	if found.Valid {
		t.Error("expected invalid skill")
	}
	if len(found.Issues) == 0 {
		t.Error("expected issues on invalid skill")
	}
}
