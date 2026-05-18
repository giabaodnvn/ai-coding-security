package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/claude-safe/claude-safe/internal/policy"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize claude-safe in the current project",
	Long: `Initialize claude-safe by creating:
  - .claude-safe/policy.yaml     (security policy)
  - .claude/settings.json        (Claude Code hooks)
  - .git/hooks/pre-commit        (git commit protection)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := initPolicyFile(); err != nil {
			return err
		}
		if err := initClaudeHooks(); err != nil {
			return err
		}
		if err := initGitHook(); err != nil {
			return err
		}
		fmt.Println("\n\033[32m✓ claude-safe initialized successfully!\033[0m")
		fmt.Println("\nWhat was set up:")
		fmt.Println("  .claude-safe/policy.yaml   — security policy (edit to customize)")
		fmt.Println("  .claude/settings.json       — Claude Code hooks (auto-scan on tool use)")
		fmt.Println("  .git/hooks/pre-commit       — blocks commits containing secrets")
		fmt.Println("\nRun 'claude-safe scan --help' to get started.")
		return nil
	},
}

func initPolicyFile() error {
	dir := ".claude-safe"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating .claude-safe dir: %w", err)
	}

	path := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  [skip] %s already exists\n", path)
		return nil
	}

	if err := policy.Save(policy.Default(), path); err != nil {
		return fmt.Errorf("writing policy: %w", err)
	}
	fmt.Printf("  [created] %s\n", path)
	return nil
}

func initClaudeHooks() error {
	claudeDir := ".claude"
	if err := os.MkdirAll(claudeDir, 0750); err != nil {
		return fmt.Errorf("creating .claude dir: %w", err)
	}

	// settings.json: claude-safe hook reads stdin JSON natively (no jq needed)
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if _, err := os.Stat(settingsPath); err == nil {
		fmt.Printf("  [skip] %s already exists\n", settingsPath)
		return nil
	}

	settings := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "claude-safe hook --policy .claude-safe/policy.yaml"
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "claude-safe hook --policy .claude-safe/policy.yaml"
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "claude-safe hook --policy .claude-safe/policy.yaml"
          }
        ]
      }
    ]
  }
}
`
	if err := os.WriteFile(settingsPath, []byte(settings), 0640); err != nil {
		return fmt.Errorf("writing Claude settings: %w", err)
	}
	fmt.Printf("  [created] %s\n", settingsPath)
	return nil
}

func initGitHook() error {
	hooksDir := ".git/hooks"
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Println("  [skip] not a git repository — skipping git hook")
		return nil
	}

	if err := os.MkdirAll(hooksDir, 0750); err != nil {
		return fmt.Errorf("creating hooks dir: %w", err)
	}

	path := filepath.Join(hooksDir, "pre-commit")
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  [skip] %s already exists — add claude-safe manually\n", path)
		return nil
	}

	hookContent := `#!/bin/sh
# claude-safe pre-commit hook
# Blocks commits that contain secrets or dangerous patterns

echo "[claude-safe] Scanning staged changes..."
claude-safe scan --staged --policy .claude-safe/policy.yaml
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "[claude-safe] Commit blocked due to security issues."
  echo "Fix the issues above or run with SKIP_SECURITY=1 git commit to bypass."
  exit 1
fi

echo "[claude-safe] ✓ Security scan passed"
exit 0
`
	if err := os.WriteFile(path, []byte(hookContent), 0750); err != nil {
		return fmt.Errorf("writing git hook: %w", err)
	}
	fmt.Printf("  [created] %s\n", path)
	return nil
}

func init() {
	rootCmd.AddCommand(initCmd)
}
