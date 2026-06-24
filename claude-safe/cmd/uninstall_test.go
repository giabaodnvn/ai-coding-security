package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUninstall_TargetsProjectRootFromSubdir verifies that uninstall acts on the
// project root's artifacts even when invoked from a subdirectory, rather than
// silently finding nothing (the pre-existing relative-path bug).
func TestUninstall_TargetsProjectRootFromSubdir(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "proj")
	sub := filepath.Join(root, "a", "b")
	csDir := filepath.Join(root, ".claude-safe")
	hookPath := filepath.Join(root, ".git", "hooks", "pre-commit")

	if err := os.MkdirAll(csDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(csDir, "policy.yaml"), []byte("audit_log: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte(preCommitTemplate), 0750); err != nil {
		t.Fatal(err)
	}

	chdir(t, sub)

	root2 := resolveProjectRoot()
	if root2 != root {
		t.Fatalf("resolveProjectRoot = %q, want %q", root2, root)
	}

	gitStep := planRemoveGitHook(root2)
	if gitStep.skip {
		t.Fatal("planRemoveGitHook skipped despite claude-safe pre-commit at project root")
	}
	if err := gitStep.run(); err != nil {
		t.Fatalf("git hook run: %v", err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Errorf("expected %s removed, stat err = %v", hookPath, err)
	}

	dirStep := planRemovePolicyDir(root2)
	if dirStep.skip {
		t.Fatal("planRemovePolicyDir skipped despite .claude-safe at project root")
	}
	if err := dirStep.run(); err != nil {
		t.Fatalf("policy dir run: %v", err)
	}
	if _, err := os.Stat(csDir); !os.IsNotExist(err) {
		t.Errorf("expected %s removed, stat err = %v", csDir, err)
	}
}
