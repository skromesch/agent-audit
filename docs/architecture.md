# Architecture

## Overview

agent-audit follows a pipeline architecture:

```
root directory
      │
      ▼
 Orchestrator (concurrent)
      │
  ┌───┴────────────────────────────────────┐
  │  ClaudeScanner  CodexScanner  ...      │
  └───────────────────────────────────────┘
      │
      ▼
  ScanResult (merged)
      │
  ┌───┴──────────────────┐
  │   TUI   │  Reports   │
  └─────────────────────┘
```

## Scanner Interface

Every ecosystem scanner implements:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, root string) (*ScannerResult, error)
}
```

## Adding a New Scanner

1. Create `internal/scanner/myecosystem.go`
2. Implement `Scanner` interface
3. Add to the orchestrator slice in `cmd/agent-audit/main.go`
4. Add fixtures under `internal/fixtures/sample-project/`
5. Write tests in `internal/scanner/myecosystem_test.go`

## Security Rules

Rules live in `internal/rules/` and are called by scanners:

- `ScanForSecrets(path, content)` — regex-based secret detection
- `CheckMCPCommands(server)` — dangerous command patterns
- `CheckPermissions(tool, path, content)` — permission misconfigurations
