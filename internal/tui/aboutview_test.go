package tui

import (
	"strings"
	"testing"
)

func TestRenderAboutUsesInjectedVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "1.2.0"
	out := renderAbout(80, 24)
	if !strings.Contains(out, "1.2.0") {
		t.Errorf("expected rendered About tab to contain injected version %q, got:\n%s", "1.2.0", out)
	}
}

func TestRenderAboutFallsBackWithoutInjectedVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = ""
	out := renderAbout(80, 24)
	if !strings.Contains(out, "(dev)") {
		t.Errorf("expected rendered About tab to fall back to \"(dev)\", got:\n%s", out)
	}
}
