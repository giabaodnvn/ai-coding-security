package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var policyFile string

var rootCmd = &cobra.Command{
	Use:   "claude-safe",
	Short: "AI Coding Security Guard — protect your AI coding workflows",
	Long: `claude-safe is a security layer for AI coding assistants.
It detects secrets, validates dangerous commands, scans git diffs,
and enforces security policies before code reaches your system.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&policyFile, "policy", "p", ".claude-safe/policy.yaml", "Path to policy file")
}
