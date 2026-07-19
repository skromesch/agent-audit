package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/skromesch/agent-audit/internal/report"
	"github.com/skromesch/agent-audit/internal/scanner"
	"github.com/skromesch/agent-audit/internal/tui"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		versionFlag = flag.Bool("version", false, "print version and exit")
		jsonOut     = flag.Bool("json", false, "write report.json and exit")
		markdownOut = flag.Bool("markdown", false, "write report.md and exit")
		htmlOut     = flag.Bool("html", false, "write report.html and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: agent-audit [flags] [path]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println("agent-audit " + version)
		return
	}

	tui.Version = version

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %q is not a directory\n", root)
		os.Exit(1)
	}

	orch := scanner.NewOrchestrator([]scanner.Scanner{
		scanner.NewClaudeScanner(),
		scanner.NewCodexScanner(),
		scanner.NewCursorScanner(),
		scanner.NewContinueScanner(),
		scanner.NewAiderScanner(),
		scanner.NewMCPScanner(),
		scanner.NewSkillsScanner(),
		scanner.NewOpenCodeScanner(),
		scanner.NewPiScanner(),
		scanner.NewGeminiScanner(),
	})

	result, err := orch.Run(context.Background(), root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		f, err := os.Create("report.json")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteJSON(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.json written")
		return
	}

	if *markdownOut {
		f, err := os.Create("report.md")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteMarkdown(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.md written")
		return
	}

	if *htmlOut {
		f, err := os.Create("report.html")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteHTML(result, f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("report.html written")
		return
	}

	// Default: TUI mode
	if err := tui.Run(result); err != nil {
		fmt.Fprintf(os.Stderr, "tui error: %v\n", err)
		os.Exit(1)
	}
}
