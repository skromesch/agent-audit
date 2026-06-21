package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
)

// Scanner discovers agent configuration in a directory tree.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, root string) (*ScannerResult, error)
}

// ScannerResult is the output of a single scanner run.
type ScannerResult struct {
	Agent      *model.AgentConfig
	MCPServers []model.MCPServer
	Skills     []model.Skill
	Findings   []model.Finding
	Files      []string
}

// Orchestrator runs multiple scanners concurrently.
type Orchestrator struct {
	scanners []Scanner
}

func NewOrchestrator(scanners []Scanner) *Orchestrator {
	return &Orchestrator{scanners: scanners}
}

func (o *Orchestrator) Run(ctx context.Context, root string) (*model.ScanResult, error) {
	result := &model.ScanResult{
		Root:      root,
		ScannedAt: time.Now(),
	}

	type outcome struct {
		r   *ScannerResult
		err error
	}

	ch := make(chan outcome, len(o.scanners))
	var wg sync.WaitGroup

	for _, s := range o.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			r, err := s.Scan(ctx, root)
			ch <- outcome{r, err}
		}(s)
	}

	wg.Wait()
	close(ch)

	for out := range ch {
		if out.err != nil {
			continue // non-fatal: one scanner failure doesn't abort the scan
		}
		r := out.r
		if r.Agent != nil {
			result.Agents = append(result.Agents, *r.Agent)
		}
		result.MCPServers = append(result.MCPServers, r.MCPServers...)
		result.Skills = append(result.Skills, r.Skills...)
		result.Findings = append(result.Findings, r.Findings...)
		result.ConfigFiles = append(result.ConfigFiles, r.Files...)
	}

	return result, nil
}
