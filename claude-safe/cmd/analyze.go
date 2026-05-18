package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/analyzer"
	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/policy"
	"github.com/claude-safe/claude-safe/internal/risk"
)

var (
	analyzeFile string
	analyzeDir  string
	analyzeLang string
	analyzeText string
	analyzeJSON bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze source code for security vulnerabilities (SQL injection, XSS, SSRF, etc.)",
	Long: `Analyze AI-generated or existing source code for OWASP Top-10 vulnerabilities.

Uses regex patterns for all languages. If semgrep is installed, it also runs
a deeper OWASP ruleset scan automatically.

Examples:
  claude-safe analyze --file main.py
  claude-safe analyze --file app.js
  claude-safe analyze --dir ./src
  claude-safe analyze --lang go --text "db.Query(fmt.Sprintf(...), id)"
  cat generated.go | claude-safe analyze --lang go`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pol, err := policy.Load(policyFile)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
		logger := audit.New(pol.AuditLogPath, pol.AuditLog)

		switch {
		case analyzeDir != "":
			return runDirAnalysis(analyzeDir, pol, logger)

		case analyzeFile != "":
			return runFileAnalysis(analyzeFile, pol, logger)

		case analyzeText != "":
			lang := analyzer.DetectFromPath("." + analyzeLang)
			if lang == analyzer.LangUnknown && analyzeLang != "" {
				lang = analyzer.Language(analyzeLang)
			}
			report := analyzer.AnalyzeContentWithLang(analyzeText, lang, "")
			printAnalysisReport("<inline>", report)
			return checkAndBlock(report, pol, logger, "<inline>")

		default:
			// Read from stdin
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				return fmt.Errorf("provide --file, --dir, --text, or pipe code via stdin")
			}
			data, err := io.ReadAll(bufio.NewReader(os.Stdin))
			if err != nil {
				return err
			}
			lang := analyzer.Language(analyzeLang)
			report := analyzer.AnalyzeContentWithLang(string(data), lang, "")
			printAnalysisReport("<stdin>", report)
			return checkAndBlock(report, pol, logger, "<stdin>")
		}
	},
}

func runFileAnalysis(path string, pol *policy.Policy, logger *audit.Logger) error {
	report, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	printAnalysisReport(path, report)
	return checkAndBlock(report, pol, logger, path)
}

func runDirAnalysis(dir string, pol *policy.Policy, logger *audit.Logger) error {
	extensions := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true,
		".java": true, ".php": true, ".rb": true, ".tsx": true, ".jsx": true,
	}

	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if extensions[strings.ToLower(filepath.Ext(path))] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Printf("No source files found in %s\n", dir)
		return nil
	}

	totalScore := 0
	totalFindings := 0
	blocked := false

	fmt.Printf("\n\033[1m[claude-safe analyze dir]\033[0m Scanning %d files in %s\n", len(files), dir)
	if analyzer.IsAvailable() {
		fmt.Println("  + Semgrep available — running deep OWASP scan")
	} else {
		fmt.Println("  (semgrep not found — using regex patterns only)")
	}
	fmt.Println()

	for _, f := range files {
		report, err := analyzer.AnalyzeFile(f)
		if err != nil {
			continue
		}
		if len(report.Findings) == 0 {
			continue
		}
		printAnalysisReport(f, report)
		totalScore += report.RiskScore
		totalFindings += report.Stats.Total
		b, _ := pol.IsBlocked(riskReportFromScore(report.RiskScore))
		if b {
			blocked = true
		}
		logger.LogScan(f, riskReportFromScore(report.RiskScore), b, "")
	}

	if totalFindings == 0 {
		fmt.Println("\033[32m✓ No vulnerabilities detected across all files\033[0m")
		return nil
	}

	avg := totalScore / len(files)
	fmt.Printf("\n\033[1mDirectory Summary\033[0m — %d file(s) scanned\n", len(files))
	fmt.Printf("  Total findings : %d\n", totalFindings)
	fmt.Printf("  Avg risk score : %d/100\n", avg)

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[BLOCKED]\033[0m Security violations found — review findings above\n")
		os.Exit(1)
	}
	return nil
}

func checkAndBlock(report *analyzer.Report, pol *policy.Policy, logger *audit.Logger, source string) error {
	rr := riskReportFromScore(report.RiskScore)
	blocked, reason := pol.IsBlocked(rr)
	logger.LogScan(source, rr, blocked, reason)

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[BLOCKED]\033[0m %s\n", reason)
		os.Exit(1)
	}
	return nil
}

func riskReportFromScore(score int) risk.Report {
	return risk.Report{
		Score:       score,
		Level:       scoreToRiskLevel(score),
		ShouldBlock: score > 0,
	}
}

func scoreToRiskLevel(score int) risk.Level {
	switch {
	case score == 0:
		return risk.LevelSafe
	case score < 10:
		return risk.LevelLow
	case score < 25:
		return risk.LevelMedium
	case score < 40:
		return risk.LevelHigh
	default:
		return risk.LevelCritical
	}
}

func printAnalysisReport(source string, report *analyzer.Report) {
	if analyzeJSON {
		printAnalysisJSON(source, report)
		return
	}

	levelColor := levelToColor(report.RiskLevel)

	fmt.Printf("\n\033[1m[claude-safe analyze]\033[0m %s\n", source)
	fmt.Printf("  Language   : %s", report.Language)
	if report.SemgrepUsed {
		fmt.Printf("  \033[32m(+ semgrep)\033[0m")
	}
	fmt.Println()
	fmt.Printf("  Risk Score : %d/100\n", report.RiskScore)
	fmt.Printf("  Risk Level : %s%s\033[0m\n", levelColor, report.RiskLevel)

	if report.Stats.Total == 0 {
		fmt.Printf("  \033[32m✓ No vulnerabilities detected\033[0m\n")
		return
	}

	fmt.Printf("  Findings   : %d total", report.Stats.Total)
	if report.Stats.Critical > 0 {
		fmt.Printf("  \033[35m%d critical\033[0m", report.Stats.Critical)
	}
	if report.Stats.High > 0 {
		fmt.Printf("  \033[31m%d high\033[0m", report.Stats.High)
	}
	if report.Stats.Medium > 0 {
		fmt.Printf("  \033[33m%d medium\033[0m", report.Stats.Medium)
	}
	if report.Stats.Low > 0 {
		fmt.Printf("  \033[36m%d low\033[0m", report.Stats.Low)
	}
	fmt.Println()
	fmt.Println()

	for _, f := range report.Findings {
		color := severityColorCode(f.Severity)
		fmt.Printf("  %s[%s]\033[0m  Line %-4d  %s\n", color, f.Severity, f.Line, f.VulnType)
		fmt.Printf("    Description : %s\n", f.Description)
		fmt.Printf("    Code        : %s\n", f.Code)
		fmt.Printf("    Fix         : %s\n", f.Remediation)
		if f.Source == "semgrep" {
			fmt.Printf("    Rule        : %s\n", f.RuleID)
		}
		fmt.Println()
	}
}

func printAnalysisJSON(source string, report *analyzer.Report) {
	out := map[string]interface{}{
		"source":       source,
		"language":     report.Language,
		"risk_score":   report.RiskScore,
		"risk_level":   report.RiskLevel,
		"semgrep_used": report.SemgrepUsed,
		"stats":        report.Stats,
		"findings":     report.Findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func severityColorCode(s analyzer.Severity) string {
	switch s {
	case analyzer.SevCritical:
		return "\033[35m"
	case analyzer.SevHigh:
		return "\033[31m"
	case analyzer.SevMedium:
		return "\033[33m"
	default:
		return "\033[36m"
	}
}

func init() {
	analyzeCmd.Flags().StringVarP(&analyzeFile, "file", "f", "", "Source file to analyze")
	analyzeCmd.Flags().StringVarP(&analyzeDir, "dir", "d", "", "Directory to scan recursively")
	analyzeCmd.Flags().StringVar(&analyzeLang, "lang", "", "Language hint: go|python|javascript|typescript|java|php|ruby")
	analyzeCmd.Flags().StringVar(&analyzeText, "text", "", "Inline code snippet to analyze")
	analyzeCmd.Flags().BoolVar(&analyzeJSON, "json", false, "Output results as JSON")
	rootCmd.AddCommand(analyzeCmd)
}
