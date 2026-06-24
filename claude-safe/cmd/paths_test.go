package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnchorToRoot(t *testing.T) {
	root := filepath.FromSlash("/home/user/project")
	tests := []struct {
		name string
		path string
		want string
	}{
		{"relative path anchored", ".claude-safe/audit.log", filepath.Join(root, ".claude-safe/audit.log")},
		{"empty path unchanged", "", ""},
		{"absolute path unchanged", filepath.FromSlash("/etc/claude-safe/audit.log"), filepath.FromSlash("/etc/claude-safe/audit.log")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anchorToRoot(root, tt.path); got != tt.want {
				t.Errorf("anchorToRoot(%q, %q) = %q, want %q", root, tt.path, got, tt.want)
			}
		})
	}
}

func TestFindUp(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "proj")
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(filepath.Join(root, ".claude-safe"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deep, 0750); err != nil {
		t.Fatal(err)
	}

	match := func(dir string) bool { return isDir(filepath.Join(dir, ".claude-safe")) }

	if got := findUp(deep, match); got != root {
		t.Errorf("findUp from deep = %q, want %q", got, root)
	}
	if got := findUp(root, match); got != root {
		t.Errorf("findUp from root = %q, want %q", got, root)
	}
	if got := findUp(base, match); got != "" {
		t.Errorf("findUp with no marker = %q, want empty", got)
	}
}

// TestResolveProjectRoot_AnchorsToClaudeSafe verifies that running from a deep
// subdirectory resolves back to the single .claude-safe at the project root,
// which is the bug this fix addresses (stray .claude-safe/ folders in subdirs).
func TestResolveProjectRoot_AnchorsToClaudeSafe(t *testing.T) {
	base := t.TempDir()
	// On macOS t.TempDir() lives under /var -> /private/var symlink; resolve it
	// so comparisons against os.Getwd() (which returns the real path) hold.
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "proj")
	sub := filepath.Join(root, "frontend", "src")
	if err := os.MkdirAll(filepath.Join(root, ".claude-safe"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatal(err)
	}

	chdir(t, sub)

	if got := resolveProjectRoot(); got != root {
		t.Errorf("resolveProjectRoot from %q = %q, want %q", sub, got, root)
	}
}

// TestResolveProjectRoot_FallsBackToGit verifies that without a .claude-safe
// dir, resolution falls back to the .git project marker.
func TestResolveProjectRoot_FallsBackToGit(t *testing.T) {
	base := t.TempDir()
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "proj")
	sub := filepath.Join(root, "pkg")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatal(err)
	}

	chdir(t, sub)

	if got := resolveProjectRoot(); got != root {
		t.Errorf("resolveProjectRoot from %q = %q, want %q", sub, got, root)
	}
}

// TestLoadPolicy_AuditAnchoredAndPolicySemantics verifies the per-command
// behavior: both loaders anchor the audit log to the project root (so no stray
// .claude-safe/ folders appear in subdirs), loadHookPolicy resolves the policy
// file against the root (so the hook reads the project policy from any subdir),
// and loadPolicy keeps --policy relative to cwd (so it falls back to defaults
// when the file is not next to the caller).
func TestLoadPolicy_AuditAnchoredAndPolicySemantics(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "proj")
	sub := filepath.Join(root, "a", "b")
	csDir := filepath.Join(root, ".claude-safe")
	if err := os.MkdirAll(csDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0750); err != nil {
		t.Fatal(err)
	}
	// max_risk_level: high distinguishes a loaded file from Default (medium).
	if err := os.WriteFile(filepath.Join(csDir, "policy.yaml"),
		[]byte("max_risk_level: high\naudit_log: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Restore the package-level flag after the test.
	prevFlag := policyFile
	t.Cleanup(func() { policyFile = prevFlag })
	policyFile = ".claude-safe/policy.yaml"

	chdir(t, sub)

	wantAudit := filepath.Join(root, ".claude-safe", "audit.log")

	hookPol, err := loadHookPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if hookPol.AuditLogPath != wantAudit {
		t.Errorf("loadHookPolicy audit = %q, want %q", hookPol.AuditLogPath, wantAudit)
	}
	if hookPol.MaxRiskLevel != "high" {
		t.Errorf("loadHookPolicy MaxRiskLevel = %q, want high (should read root policy.yaml)", hookPol.MaxRiskLevel)
	}

	cliPol, err := loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if cliPol.AuditLogPath != wantAudit {
		t.Errorf("loadPolicy audit = %q, want %q (must be root-anchored)", cliPol.AuditLogPath, wantAudit)
	}
	if cliPol.MaxRiskLevel != "medium" {
		t.Errorf("loadPolicy MaxRiskLevel = %q, want medium (cwd has no policy.yaml -> defaults)", cliPol.MaxRiskLevel)
	}
}

// chdir switches into dir for the duration of the test, restoring the previous
// working directory on cleanup. (t.Chdir requires Go 1.24+.)
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
