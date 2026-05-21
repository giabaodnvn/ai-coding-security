package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	uninstallDryRun     bool
	uninstallYes        bool
	uninstallKeepPolicy bool
)

// preCommitTemplate is the exact content written by `claude-safe init`.
// Used to detect whether the hook file is "pure" claude-safe and safe to delete.
const preCommitTemplate = `#!/bin/sh
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

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove claude-safe hooks and configuration from the current project",
	Long: `Remove all claude-safe artifacts from the current project:
  - .git/hooks/pre-commit    (only if created by claude-safe)
  - .claude/settings.json    (surgically removes claude-safe hook entries)
  - .claude-safe/            (policy and audit log directory)`,
	RunE: runUninstall,
}

type uninstallStep struct {
	preview   string
	warning   string
	skip      bool
	hasEffect bool // true if this step actually deletes or modifies a file
	run       func() error
}

func runUninstall(cmd *cobra.Command, args []string) error {
	steps := gatherUninstallSteps()

	fmt.Println("claude-safe uninstall will perform the following:")
	anyEffect := false
	anyVisible := false
	for _, s := range steps {
		if s.skip {
			continue
		}
		anyVisible = true
		if s.hasEffect {
			anyEffect = true
		}
		fmt.Printf("  %s\n", s.preview)
		if s.warning != "" {
			fmt.Printf("  \033[33m  ⚠  %s\033[0m\n", s.warning)
		}
	}

	if !anyVisible {
		fmt.Println("  Nothing to remove — claude-safe does not appear to be installed here.")
		return nil
	}

	if uninstallDryRun {
		fmt.Println("\n(dry-run: no changes made)")
		return nil
	}

	if !anyEffect {
		// Only manual-action warnings remain; print them and exit without prompting.
		fmt.Println()
		for _, s := range steps {
			if s.skip || s.run == nil {
				continue
			}
			_ = s.run()
		}
		return nil
	}

	if !uninstallYes {
		fmt.Print("\nProceed? [y/N]: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	fmt.Println()
	for _, s := range steps {
		if s.skip || s.run == nil {
			continue
		}
		if err := s.run(); err != nil {
			return err
		}
	}

	fmt.Println("\n\033[32m✓ claude-safe uninstalled successfully.\033[0m")
	return nil
}

func gatherUninstallSteps() []uninstallStep {
	return []uninstallStep{
		planRemoveGitHook(),
		planCleanSettings(),
		planRemovePolicyDir(),
	}
}

func planRemoveGitHook() uninstallStep {
	path := filepath.Join(".git", "hooks", "pre-commit")

	data, err := os.ReadFile(path)
	if err != nil {
		return uninstallStep{skip: true}
	}

	content := string(data)
	if !strings.Contains(content, "# claude-safe pre-commit hook") {
		// Not a claude-safe hook, don't touch it.
		return uninstallStep{skip: true}
	}

	if strings.TrimSpace(content) == strings.TrimSpace(preCommitTemplate) {
		return uninstallStep{
			preview:   "[remove]  " + path,
			hasEffect: true,
			run: func() error {
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("removing %s: %w", path, err)
				}
				fmt.Printf("  [removed] %s\n", path)
				return nil
			},
		}
	}

	// Mixed hook: has claude-safe marker but also other content.
	return uninstallStep{
		preview: "[skip]    " + path + " (contains other hooks)",
		warning: "Remove the claude-safe section from this file manually.",
		run: func() error {
			fmt.Printf("  [skipped] %s — remove claude-safe section manually\n", path)
			fmt.Printf("            (lines containing '# claude-safe' through 'exit 0')\n")
			return nil
		},
	}
}

func planCleanSettings() uninstallStep {
	path := filepath.Join(".claude", "settings.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return uninstallStep{skip: true}
	}

	if !strings.Contains(string(data), "claude-safe hook") {
		return uninstallStep{skip: true}
	}

	return uninstallStep{
		preview:   "[clean]   " + path,
		hasEffect: true,
		run: func() error {
			deleted, err := stripClaudeSafeFromSettings(path)
			if err != nil {
				return fmt.Errorf("cleaning %s: %w", path, err)
			}
			if deleted {
				fmt.Printf("  [removed] %s\n", path)
			} else {
				fmt.Printf("  [cleaned] %s (claude-safe entries removed)\n", path)
			}
			return nil
		},
	}
}

func planRemovePolicyDir() uninstallStep {
	dir := ".claude-safe"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return uninstallStep{skip: true}
	}

	if uninstallKeepPolicy {
		return uninstallStep{skip: true}
	}

	var warn string
	auditLog := filepath.Join(dir, "audit.log")
	if fi, err := os.Stat(auditLog); err == nil && fi.Size() > 0 {
		warn = fmt.Sprintf("audit.log (%d bytes) will be permanently deleted", fi.Size())
	}

	return uninstallStep{
		preview:   "[remove]  " + dir + "/",
		warning:   warn,
		hasEffect: true,
		run: func() error {
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("removing %s: %w", dir, err)
			}
			fmt.Printf("  [removed] %s/\n", dir)
			return nil
		},
	}
}

// stripClaudeSafeFromSettings parses settings.json, removes all PreToolUse hook
// entries whose commands reference "claude-safe hook", then either deletes the
// file (if nothing remains) or writes back the cleaned JSON.
// Returns true if the file was deleted.
func stripClaudeSafeFromSettings(path string) (deleted bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parsing JSON: %w", err)
	}

	hooksRaw, ok := root["hooks"]
	if !ok {
		return false, nil
	}

	var hooksMap map[string]json.RawMessage
	if err := json.Unmarshal(hooksRaw, &hooksMap); err != nil {
		return false, fmt.Errorf("parsing hooks: %w", err)
	}

	ptuRaw, ok := hooksMap["PreToolUse"]
	if !ok {
		return false, nil
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(ptuRaw, &rawEntries); err != nil {
		return false, fmt.Errorf("parsing PreToolUse: %w", err)
	}

	var keptEntries []json.RawMessage
	for _, entryRaw := range rawEntries {
		var entryMap map[string]json.RawMessage
		if err := json.Unmarshal(entryRaw, &entryMap); err != nil {
			keptEntries = append(keptEntries, entryRaw)
			continue
		}

		subRaw, hasHooks := entryMap["hooks"]
		if !hasHooks {
			keptEntries = append(keptEntries, entryRaw)
			continue
		}

		var subHooks []json.RawMessage
		if err := json.Unmarshal(subRaw, &subHooks); err != nil {
			keptEntries = append(keptEntries, entryRaw)
			continue
		}

		var keptSubs []json.RawMessage
		for _, shRaw := range subHooks {
			var sh struct {
				Command string `json:"command"`
			}
			if err := json.Unmarshal(shRaw, &sh); err != nil || !strings.Contains(sh.Command, "claude-safe hook") {
				keptSubs = append(keptSubs, shRaw)
			}
		}

		if len(keptSubs) == 0 {
			continue // entire entry was claude-safe, drop it
		}
		entryMap["hooks"], _ = json.Marshal(keptSubs)
		rebuilt, _ := json.Marshal(entryMap)
		keptEntries = append(keptEntries, rebuilt)
	}

	if len(keptEntries) == 0 {
		delete(hooksMap, "PreToolUse")
	} else {
		hooksMap["PreToolUse"], _ = json.Marshal(keptEntries)
	}

	if len(hooksMap) == 0 {
		delete(root, "hooks")
	} else {
		root["hooks"], _ = json.Marshal(hooksMap)
	}

	if len(root) == 0 {
		return true, os.Remove(path)
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshaling JSON: %w", err)
	}
	return false, os.WriteFile(path, append(out, '\n'), 0640)
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
	uninstallCmd.Flags().BoolVarP(&uninstallDryRun, "dry-run", "n", false, "Show what would be removed without making changes")
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip confirmation prompt")
	uninstallCmd.Flags().BoolVar(&uninstallKeepPolicy, "keep-policy", false, "Preserve .claude-safe/ directory (policy and audit log)")
}
