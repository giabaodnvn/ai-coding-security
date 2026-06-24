package cmd

import (
	"os"
	"path/filepath"

	"github.com/claude-safe/claude-safe/internal/audit"
	"github.com/claude-safe/claude-safe/internal/policy"
)

// resolveProjectRoot finds the directory that .claude-safe paths should be
// anchored to. Hooks are invoked by Claude Code with the working directory of
// the tool call, which may be any subdirectory of the project. Resolving
// relative paths (policy.yaml, audit.log) against that cwd scatters stray
// .claude-safe/ folders across subdirectories, so we walk up to the real root.
//
// Resolution order:
//  1. nearest ancestor that already contains a .claude-safe/ directory
//     (where `init` set up the policy and audit log), then
//  2. nearest ancestor marked by .git or .claude, then
//  3. the current working directory as a last resort.
func resolveProjectRoot() string {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return "."
	}

	if root := findUp(cwd, func(dir string) bool {
		return isDir(filepath.Join(dir, ".claude-safe"))
	}); root != "" {
		return root
	}

	if root := findUp(cwd, func(dir string) bool {
		return exists(filepath.Join(dir, ".git")) || isDir(filepath.Join(dir, ".claude"))
	}); root != "" {
		return root
	}

	return cwd
}

// findUp walks from start towards the filesystem root, returning the first
// directory for which match returns true, or "" if none matches.
func findUp(start string, match func(dir string) bool) string {
	dir := start
	for {
		if match(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// anchorToRoot turns a relative path into one rooted at the project root.
// Absolute and empty paths are returned unchanged.
func anchorToRoot(root, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

// loadPolicy loads the policy file using the --policy flag as given (relative to
// the current directory, matching normal CLI expectations) and anchors only the
// audit log to the project root, so the log never scatters .claude-safe/ folders
// across subdirectories. Used by the interactive commands (scan, run, analyze).
func loadPolicy() (*policy.Policy, error) {
	pol, err := policy.Load(policyFile)
	if err != nil {
		return nil, err
	}
	pol.AuditLogPath = anchorToRoot(resolveProjectRoot(), pol.AuditLogPath)
	return pol, nil
}

// loadHookPolicy is like loadPolicy but also anchors the policy file path to the
// project root. Claude Code invokes the hook from the working directory of the
// tool call (any subdirectory), so a relative --policy must be resolved against
// the project root to find the project's policy.yaml rather than silently
// falling back to the built-in defaults.
func loadHookPolicy() (*policy.Policy, error) {
	root := resolveProjectRoot()
	pol, err := policy.Load(anchorToRoot(root, policyFile))
	if err != nil {
		return nil, err
	}
	pol.AuditLogPath = anchorToRoot(root, pol.AuditLogPath)
	return pol, nil
}

// newLogger builds the audit logger for a loaded policy.
func newLogger(pol *policy.Policy) *audit.Logger {
	return audit.New(pol.AuditLogPath, pol.AuditLog)
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
