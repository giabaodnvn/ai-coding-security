package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/policy"
	"github.com/claude-safe/claude-safe/internal/risk"
	"github.com/claude-safe/claude-safe/internal/secrets"
)

var forceRun bool

var runCmd = &cobra.Command{
	Use:   "run [command]",
	Short: "Validate and execute a shell command after security check",
	Long: `Validate a shell command against security rules, then execute it if safe.
If the command is flagged as dangerous, it will be blocked unless --force is set.

Example:
  claude-safe run "ls -la"
  claude-safe run "git diff --cached"
  claude-safe run "rm -rf /tmp/test"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userCmd := strings.Join(args, " ")

		pol, err := policy.Load(policyFile)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}

		logger := audit.New(pol.AuditLogPath, pol.AuditLog)
		validator := command.New().WithAllowList(pol.AllowList)
		secretDetector := secrets.New()

		// Validate command risk
		cmdRisk := validator.Validate(userCmd)

		// Scan command text for embedded secrets
		secretFindings := secretDetector.ScanText(userCmd)

		// Calculate risk score
		report := risk.Score(secretFindings, []command.CommandRisk{cmdRisk})

		// Print scan result
		printRunReport(userCmd, report, cmdRisk)

		// Check policy
		blocked, reason := pol.IsBlocked(report)
		if blocked && !forceRun {
			logger.LogScan(userCmd, report, true, reason)
			fmt.Fprintf(os.Stderr, "\n\033[31m[BLOCKED]\033[0m %s\n", reason)
			fmt.Fprintf(os.Stderr, "Use --force to override (not recommended)\n")
			os.Exit(1)
		}

		logger.LogScan(userCmd, report, false, "")

		if report.Level != "SAFE" && report.Level != "LOW" {
			fmt.Printf("\n\033[33m[WARNING]\033[0m Executing %s risk command: %s\n", report.Level, userCmd)
		}

		// Execute the command
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		execCmd := exec.Command(shell, "-c", userCmd)
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		return execCmd.Run()
	},
}

func printRunReport(cmd string, report risk.Report, cmdRisk command.CommandRisk) {
	levelColor := levelToColor(string(report.Level))
	fmt.Printf("\n\033[1m[claude-safe run]\033[0m Checking: %s\n", cmd)
	fmt.Printf("  Command Risk : %s%s\033[0m\n", levelColor, cmdRisk.RiskLevel)
	fmt.Printf("  Risk Score   : %d/100\n", report.Score)
	fmt.Printf("  Risk Level   : %s%s\033[0m\n", levelColor, report.Level)
	if cmdRisk.Reason != "" && cmdRisk.RiskLevel != command.RiskLow {
		fmt.Printf("  Reason       : %s\n", cmdRisk.Reason)
	}
	if len(report.SecretFindings) > 0 {
		fmt.Printf("  Secrets      : %d detected\n", len(report.SecretFindings))
	}
}

func init() {
	runCmd.Flags().BoolVarP(&forceRun, "force", "f", false, "Force execute even if blocked by policy")
	rootCmd.AddCommand(runCmd)
}
