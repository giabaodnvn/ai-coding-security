package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/analyzer"
	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/policy"
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

		pol, err := policy.Load(policyFile)
		if err != nil {
			return nil // don't block Claude if policy missing
		}
		logger := audit.New(pol.AuditLogPath, pol.AuditLog)

		switch input.ToolName {
		case "Bash":
			return hookBash(input.ToolInput, pol, logger)
		case "Write":
			return hookWrite(input.ToolInput, pol, logger)
		case "Edit":
			return hookEdit(input.ToolInput, pol, logger)
		default:
			return nil
		}
	},
}

func hookBash(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger) error {
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

	if blocked {
		fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m %s\n", reason)
		os.Exit(2) // exit 2 = block the tool call in Claude Code
	}
	return nil
}

func hookWrite(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger) error {
	var ti writeToolInput
	if err := json.Unmarshal(raw, &ti); err != nil || ti.Content == "" {
		return nil
	}
	return hookAnalyzeContent(ti.Content, ti.FilePath, "Writing", pol, logger)
}

func hookEdit(raw json.RawMessage, pol *policy.Policy, logger *audit.Logger) error {
	var ti editToolInput
	if err := json.Unmarshal(raw, &ti); err != nil || ti.NewString == "" {
		return nil
	}
	return hookAnalyzeContent(ti.NewString, ti.FilePath, "Editing", pol, logger)
}

// hookAnalyzeContent runs both secret detection and code vulnerability analysis.
func hookAnalyzeContent(content, filePath, action string, pol *policy.Policy, logger *audit.Logger) error {
	// 1. Secret detection (Phase 1)
	detector := secrets.New()
	secretFindings := detector.ScanText(content)
	secretReport := risk.Score(secretFindings, nil)

	if len(secretFindings) > 0 {
		printScanReport(filePath, secretReport)
	}

	blocked, reason := pol.IsBlocked(secretReport)
	logger.LogScan(filePath, secretReport, blocked, reason)

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
			fmt.Fprintf(os.Stderr, "\n\033[31m[claude-safe BLOCKED]\033[0m %s %s: %d code vulnerabilities detected (score %d/100)\n",
				action, filePath, codeReport.Stats.Total, codeReport.RiskScore)
			os.Exit(2)
		}

		// Warn but don't block for medium/low
		logger.LogScan(filePath, riskReportFromScore(codeReport.RiskScore), false, "")
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

func init() {
	rootCmd.AddCommand(hookCmd)
}
