package scanner_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skromesch/agent-audit/internal/scanner"
)

func benchFixtureDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "fixtures", "sample-project")
}

func BenchmarkOrchestratorFixture(b *testing.B) {
	orch := buildOrchestrator()
	root := benchFixtureDir()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		orch.Run(ctx, root) //nolint:errcheck
	}
}

func BenchmarkMCPScanner(b *testing.B) {
	s := scanner.NewMCPScanner()
	root := benchFixtureDir()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(ctx, root) //nolint:errcheck
	}
}
