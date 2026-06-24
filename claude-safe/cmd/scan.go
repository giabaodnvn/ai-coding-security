package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/git"
	"github.com/claude-safe/claude-safe/internal/policy"
	"github.com/claude-safe/claude-safe/internal/risk"
	"github.com/claude-safe/claude-safe/internal/secrets"
)

var (
	scanFile    string
	scanGitDiff bool
	scanStaged  bool
	scanText    string
	jsonOutput  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan code, files, or git diff for security issues",
	Long: `Scan for secrets, dangerous patterns, and security vulnerabilities.

Examples:
  claude-safe scan --file main.go
  claude-safe scan --git-diff
  claude-safe scan --staged
  echo "password=secret123" | claude-safe scan
  claude-safe scan --text "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pol, err := loadPolicy()
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
		logger := newLogger(pol)

		var content string

		switch {
		case scanGitDiff || scanStaged:
			return runGitScan(pol, logger, scanStaged)

		case scanFile != "":
			data, err := os.ReadFile(scanFile)
			if err != nil {
				return fmt.Errorf("reading file %s: %w", scanFile, err)
			}
			content = string(data)

		case scanText != "":
			content = scanText

		default:
			// Read from stdin
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				return fmt.Errorf("provide --file, --git-diff, --staged, --text, or pipe input via stdin")
			}
			data, err := io.ReadAll(bufio.NewReader(os.Stdin))
			if err != nil {
				return err
			}
			content = string(data)
		}

		return runTextScan(content, pol, logger, "stdin/text")
	},
}

func runTextScan(content string, pol *policy.Policy, logger *audit.Logger, source string) error {
	detector := secrets.New()
	validator := command.New().WithAllowList(pol.AllowList)

	secretFindings := detector.ScanText(content)

	// Also validate each line as a potential command
	var cmdRisks []command.CommandRisk
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r := validator.Validate(line)
		if r.RiskLevel != command.RiskLow {
			cmdRisks = append(cmdRisks, r)
		}
	}

	report := risk.Score(secretFindings, cmdRisks)
	printScanReport(source, report)

	blocked, reason := pol.IsBlocked(report)
	logger.LogScan(source, report, blocked, reason)

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[BLOCKED]\033[0m %s\n", reason)
		os.Exit(1)
	}

	return nil
}

func runGitScan(pol *policy.Policy, logger *audit.Logger, staged bool) error {
	scanner := git.New()

	var findings []git.DiffFinding
	var err error

	if staged {
		findings, err = scanner.ScanStagedDiff()
	} else {
		findings, err = scanner.ScanWorkingDiff()
	}

	if err != nil {
		return fmt.Errorf("git diff failed (are you in a git repo?): %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("\033[32m[SAFE]\033[0m No secrets detected in git diff")
		return nil
	}

	fmt.Printf("\n\033[1m[claude-safe git scan]\033[0m Found %d issue(s):\n\n", len(findings))
	for _, f := range findings {
		color := severityColor(string(f.Secret.Severity))
		fmt.Printf("  %s%s\033[0m  %s:%d\n", color, f.Secret.Severity, f.File, f.Line)
		fmt.Printf("    Rule  : %s\n", f.Secret.Rule)
		fmt.Printf("    Match : %s\n\n", f.Secret.Match)
	}

	// Build a quick risk report for logging
	var secretFindings []secrets.Finding
	for _, f := range findings {
		secretFindings = append(secretFindings, f.Secret)
	}
	report := risk.Score(secretFindings, nil)
	blocked, reason := pol.IsBlocked(report)
	logger.LogScan("git-diff", report, blocked, reason)

	if blocked {
		fmt.Fprintf(os.Stderr, "\033[31m[BLOCKED]\033[0m %s\n", reason)
		os.Exit(1)
	}

	return nil
}

func printScanReport(source string, report risk.Report) {
	levelColor := levelToColor(string(report.Level))
	fmt.Printf("\n\033[1m[claude-safe scan]\033[0m Source: %s\n", source)
	fmt.Printf("  Risk Score : %d/100\n", report.Score)
	fmt.Printf("  Risk Level : %s%s\033[0m\n", levelColor, report.Level)

	if len(report.SecretFindings) > 0 {
		fmt.Printf("\n  Secrets detected (%d):\n", len(report.SecretFindings))
		for _, f := range report.SecretFindings {
			color := severityColor(string(f.Severity))
			fmt.Printf("    %s[%s]\033[0m %s (line %d) — %s\n", color, f.Severity, f.Rule, f.Line, f.Match)
		}
	}

	if len(report.CommandRisks) > 0 {
		fmt.Printf("\n  Dangerous patterns detected (%d):\n", len(report.CommandRisks))
		for _, c := range report.CommandRisks {
			color := levelToColor(string(c.RiskLevel))
			fmt.Printf("    %s[%s]\033[0m %s\n", color, c.RiskLevel, c.Reason)
			fmt.Printf("           Command: %s\n", c.Command)
		}
	}

	if len(report.Reasons) == 0 {
		fmt.Printf("\n  \033[32m✓ No issues detected\033[0m\n")
	}
}

func levelToColor(level string) string {
	switch level {
	case "CRITICAL":
		return "\033[35m" // magenta
	case "HIGH":
		return "\033[31m" // red
	case "MEDIUM":
		return "\033[33m" // yellow
	case "LOW":
		return "\033[36m" // cyan
	default:
		return "\033[32m" // green
	}
}

func severityColor(sev string) string {
	return levelToColor(sev)
}

func init() {
	scanCmd.Flags().StringVarP(&scanFile, "file", "f", "", "File to scan")
	scanCmd.Flags().BoolVar(&scanGitDiff, "git-diff", false, "Scan unstaged git diff")
	scanCmd.Flags().BoolVar(&scanStaged, "staged", false, "Scan staged git diff (pre-commit)")
	scanCmd.Flags().StringVar(&scanText, "text", "", "Inline text to scan")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.AddCommand(scanCmd)
}
