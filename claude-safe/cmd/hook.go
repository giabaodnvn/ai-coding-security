package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/analyzer"
	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/policy"
	"github.com/claude-safe/claude-safe/internal/reporter"
	"github.com/claude-safe/claude-safe/internal/risk"
	"github.com/claude-safe/claude-safe/internal/secrets"
)

// claudeHookInput mirrors the JSON Claude Code sends to hooks via stdin
type claudeHookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type bashToolInput struct {
	Command string `json:"command"`
}

type writeToolInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

type editToolInput struct {
	FilePath  string `json:"file_path"`
	OldString string `json:"old_string"`
	NewString string `json:"new_string"`
}

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Process Claude Code hook events from stdin (used by .claude/hooks scripts)",
	Long: `Reads a Claude Code hook JSON payload from stdin and applies security checks.
Exit code 2 blocks the tool call. Exit code 0 allows it.

This command is invoked automatically by .claude/hooks scripts — you don't need to call it directly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		var input claudeHookInput
		if err := json.Unmarshal(data, &input); err != nil {
			// If we can't parse, allow through (don't break Claude)
			return nil
		}

		pol, err := loadHookPolicy()
		if err != nil {
			return nil // don't block Claude if policy missing
		}
		logger := newLogger(pol)
		rep := reporter.FromEnv()

		switch input.ToolName {
		case "Bash":
			return hookBash(input.ToolInput, pol, logger, rep)
		case "Write":
			return hookWrite(input.ToolInput, pol, logger, rep)
		case "Edit":
			return hookEdit(input.ToolInput, pol, logger, rep)
		default:
			return nil
		}
	},
}

func hookBash(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger, rep *reporter.Reporter) error {
	var ti bashToolInput
	if err := json.Unmarshal(raw, &ti); err != nil || ti.Command == "" {
		return nil
	}

	validator := command.New().WithAllowList(pol.AllowList)
	detector := secrets.New()

	cmdRisk := validator.Validate(ti.Command)
	secretFindings := detector.ScanText(ti.Command)
	report := risk.Score(secretFindings, []command.CommandRisk{cmdRisk})

	printRunReport(ti.Command, report, cmdRisk)

	blocked, reason := pol.IsBlocked(report)
	logger.LogScan(ti.Command, report, blocked, reason)
	rep.Send(reporter.Event{
		ToolName: "Bash", Input: ti.Command,
		RiskLevel: string(report.Level), RiskScore: report.Score,
		Blocked: blocked, Reason: reason,
	})

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m %s\n", reason)
		fmt.Fprintf(os.Stderr, "\n\033[33mTo run manually outside Claude Code:\033[0m\n  %s\n", ti.Command)
		os.Exit(2)
	}
	return nil
}

func hookWrite(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger, rep *reporter.Reporter) error {
	var ti writeToolInput
	if err := json.Unmarshal(raw, &ti); err != nil {
		return nil
	}

	// Phase 0: Sensitive file path check — runs even when content is empty
	// (empty Write to .env would silently clear the file without this guard)
	if blocked, severity, reason := checkSensitivePath(ti.FilePath, pol); reason != "" {
		report := riskReportFromScore(sensitivePathScore(severity))
		logger.LogScan(ti.FilePath, report, blocked, reason)
		rep.Send(reporter.Event{
			ToolName: "Write", Input: ti.FilePath,
			RiskLevel: severity, RiskScore: report.Score,
			Blocked: blocked, Reason: reason,
		})
		if blocked {
			fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m Writing %s: %s\n", ti.FilePath, reason)
			os.Exit(2)
		}
		fmt.Printf("\n\033[33m[claude-safe WARNING]\033[0m Writing %s: %s\n", ti.FilePath, reason)
	}

	if ti.Content == "" {
		return nil
	}
	return hookAnalyzeContent(ti.Content, ti.FilePath, "Writing", pol, logger, rep)
}

func hookEdit(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger, rep *reporter.Reporter) error {
	var ti editToolInput
	if err := json.Unmarshal(raw, &ti); err != nil {
		return nil
	}

	// Phase 0: Sensitive file path check — runs even when new_string is empty
	if blocked, severity, reason := checkSensitivePath(ti.FilePath, pol); reason != "" {
		report := riskReportFromScore(sensitivePathScore(severity))
		logger.LogScan(ti.FilePath, report, blocked, reason)
		rep.Send(reporter.Event{
			ToolName: "Edit", Input: ti.FilePath,
			RiskLevel: severity, RiskScore: report.Score,
			Blocked: blocked, Reason: reason,
		})
		if blocked {
			fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m Editing %s: %s\n", ti.FilePath, reason)
			os.Exit(2)
		}
		fmt.Printf("\n\033[33m[claude-safe WARNING]\033[0m Editing %s: %s\n", ti.FilePath, reason)
	}

	if ti.NewString == "" {
		return nil
	}
	return hookAnalyzeContent(ti.NewString, ti.FilePath, "Editing", pol, logger, rep)
}

// sensitivePathScore converts a severity label to a risk score for logging.
func sensitivePathScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 60
	default: // MEDIUM
		return 20
	}
}

// hookAnalyzeContent runs both secret detection and code vulnerability analysis.
func hookAnalyzeContent(content, filePath, action string, pol *policy.Policy, logger *audit.Logger, rep *reporter.Reporter) error {
	// 1. Secret detection (Phase 1)
	detector := secrets.New()
	secretFindings := detector.ScanText(content)
	secretReport := risk.Score(secretFindings, nil)

	if len(secretFindings) > 0 {
		printScanReport(filePath, secretReport)
	}

	blocked, reason := pol.IsBlocked(secretReport)
	logger.LogScan(filePath, secretReport, blocked, reason)
	rep.Send(reporter.Event{
		ToolName: action, Input: filePath,
		RiskLevel: string(secretReport.Level), RiskScore: secretReport.Score,
		Blocked: blocked, Reason: reason,
	})

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m %s %s: %s\n", action, filePath, reason)
		os.Exit(2)
	}

	// 2. Code vulnerability analysis (Phase 2)
	codeReport := analyzer.AnalyzeContent(content, filePath)
	if codeReport.Stats.Total > 0 {
		printCodeAnalysisSummary(filePath, codeReport)

		if codeReport.RiskScore > 0 {
			logger.LogScan(filePath, riskReportFromScore(codeReport.RiskScore), true, "Code vulnerabilities detected")
			rep.Send(reporter.Event{
				ToolName: action, Input: filePath,
				RiskLevel: codeReport.RiskLevel, RiskScore: codeReport.RiskScore,
				Blocked: true, Reason: "Code vulnerabilities detected",
			})
			fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m %s %s: %d code vulnerabilities detected (score %d/100)\n",
				action, filePath, codeReport.Stats.Total, codeReport.RiskScore)
			os.Exit(2)
		}

		// Warn but don't block for medium/low
		logger.LogScan(filePath, riskReportFromScore(codeReport.RiskScore), false, "")
		rep.Send(reporter.Event{
			ToolName: action, Input: filePath,
			RiskLevel: codeReport.RiskLevel, RiskScore: codeReport.RiskScore,
			Blocked: false,
		})
	}

	return nil
}

// printCodeAnalysisSummary prints a compact version for hook output.
func printCodeAnalysisSummary(filePath string, report *analyzer.Report) {
	fmt.Printf("\n\033[1m[claude-safe analyze]\033[0m %s — %s (score %d/100)\n",
		filePath, report.Language, report.RiskScore)
	for _, f := range report.Findings {
		color := severityColorCode(f.Severity)
		fmt.Printf("  %s[%s]\033[0m Line %-4d %s — %s\n", color, f.Severity, f.Line, f.VulnType, f.Description)
	}
}

// sensitivePathEntry describes a file path pattern that warrants special handling.
type sensitivePathEntry struct {
	pattern  *regexp.Regexp
	severity string // "CRITICAL", "HIGH", "MEDIUM"
	reason   string
	block    bool // true = block; false = warn only
}

// sensitivePathRules is ordered from most to least severe.
// CRITICAL rules fire regardless of BlockSensitivePaths policy.
var sensitivePathRules = []sensitivePathEntry{
	// CRITICAL — always block, no policy override
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.ssh[\\/](id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)$`),
		severity: "CRITICAL",
		reason:   "SSH private key or authorized_keys — writing to this path is never allowed",
		block:    true,
	},
	{
		pattern:  regexp.MustCompile(`^[\\/]etc[\\/](passwd|shadow|sudoers)$`),
		severity: "CRITICAL",
		reason:   "System authentication file — writing to this path is never allowed",
		block:    true,
	},
	// HIGH — block when BlockSensitivePaths is enabled (default: true)
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.aws[\\/](credentials|config)$`),
		severity: "HIGH",
		reason:   "AWS credentials file — writing may expose cloud access keys",
		block:    true,
	},
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.env\.(production|prod|staging|live)$`),
		severity: "HIGH",
		reason:   "Production environment config — writing may expose production secrets",
		block:    true,
	},
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.env$`),
		severity: "HIGH",
		reason:   ".env file — writing may expose application secrets",
		block:    true,
	},
	// MEDIUM — warn only, never block
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.github[\\/]workflows[\\/][^\\/]+\.ya?ml$`),
		severity: "MEDIUM",
		reason:   "GitHub Actions workflow — CI/CD pipeline changes should be reviewed carefully",
		block:    false,
	},
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.env\.(local|development|dev|test)$`),
		severity: "MEDIUM",
		reason:   "Local environment config — verify no real secrets are included",
		block:    false,
	},
	{
		pattern:  regexp.MustCompile(`(^|[\\/])\.env\.example$`),
		severity: "MEDIUM",
		reason:   ".env.example — ensure it contains only placeholder values",
		block:    false,
	},
}

// checkSensitivePath returns (blocked, severity, reason).
// CRITICAL entries always block. HIGH entries block when policy allows.
// MEDIUM entries return blocked=false (warn only). Empty reason means no match.
func checkSensitivePath(filePath string, pol *policy.Policy) (blocked bool, severity string, reason string) {
	normalized := filepath.ToSlash(filepath.Clean(expandHome(filePath)))
	for _, rule := range sensitivePathRules {
		if !rule.pattern.MatchString(normalized) {
			continue
		}
		if rule.severity == "CRITICAL" {
			return true, rule.severity, rule.reason
		}
		if !pol.BlockSensitivePaths {
			return false, "", ""
		}
		return rule.block, rule.severity, rule.reason
	}
	return false, "", ""
}

// expandHome replaces a leading ~/ with the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func init() {
	rootCmd.AddCommand(hookCmd)
}
