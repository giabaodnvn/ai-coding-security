package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// IsAvailable returns true if semgrep is on the PATH.
func IsAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// semgrepOutput mirrors the JSON schema that semgrep --json produces.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
}

type semgrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   semgrepPosition `json:"start"`
	Extra   semgrepExtra    `json:"extra"`
}

type semgrepPosition struct {
	Line int `json:"line"`
}

type semgrepExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"` // ERROR, WARNING, INFO
	Lines    string `json:"lines"`
}

type semgrepError struct {
	Message string `json:"message"`
}

// RunSemgrep runs semgrep on filePath using the OWASP Top-10 ruleset and
// returns findings normalised to CodeFinding. Falls back gracefully if semgrep
// is not installed or fails.
func RunSemgrep(filePath string, lang Language) ([]CodeFinding, error) {
	if !IsAvailable() {
		return nil, nil
	}

	rulesets := semgrepRulesetsFor(lang)
	if len(rulesets) == 0 {
		return nil, nil
	}

	args := []string{"--json", "--quiet"}
	for _, r := range rulesets {
		args = append(args, "--config", r)
	}
	args = append(args, filePath)

	cmd := exec.Command("semgrep", args...)
	out, err := cmd.Output()
	if err != nil {
		// semgrep exits non-zero when it finds issues — that's expected
		if len(out) == 0 {
			return nil, fmt.Errorf("semgrep error: %w", err)
		}
	}

	var result semgrepOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing semgrep output: %w", err)
	}

	var findings []CodeFinding
	for _, r := range result.Results {
		findings = append(findings, CodeFinding{
			VulnType:    semgrepVulnType(r.CheckID),
			Severity:    semgrepSeverity(r.Extra.Severity),
			Line:        r.Start.Line,
			Code:        r.Extra.Lines,
			Description: r.Extra.Message,
			Remediation: "See: https://semgrep.dev/r/" + r.CheckID,
			Source:      "semgrep",
			RuleID:      r.CheckID,
		})
	}
	return findings, nil
}

// RunSemgrepOnContent writes content to a temp file, runs semgrep, then cleans up.
func RunSemgrepOnContent(content string, lang Language) ([]CodeFinding, error) {
	if !IsAvailable() {
		return nil, nil
	}

	ext := langToExt(lang)
	tmp, err := os.CreateTemp("", "claude-safe-*"+ext)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		return nil, err
	}
	tmp.Close()

	return RunSemgrep(tmp.Name(), lang)
}

func langToExt(lang Language) string {
	switch lang {
	case LangGo:
		return ".go"
	case LangPython:
		return ".py"
	case LangJavaScript:
		return ".js"
	case LangTypeScript:
		return ".ts"
	case LangJava:
		return ".java"
	case LangPHP:
		return ".php"
	case LangRuby:
		return ".rb"
	default:
		return ".txt"
	}
}

func semgrepRulesetsFor(lang Language) []string {
	base := []string{"p/owasp-top-ten"}
	switch lang {
	case LangGo:
		return append(base, "p/golang")
	case LangPython:
		return append(base, "p/python")
	case LangJavaScript, LangTypeScript:
		return append(base, "p/javascript")
	case LangJava:
		return append(base, "p/java")
	case LangPHP:
		return append(base, "p/php")
	default:
		return base
	}
}

// semgrepVulnType maps a semgrep check_id to our VulnType enum (best-effort).
func semgrepVulnType(checkID string) VulnType {
	switch {
	case containsAny(checkID, "sql", "sqli"):
		return VulnSQLInjection
	case containsAny(checkID, "xss", "cross-site"):
		return VulnXSS
	case containsAny(checkID, "cmd", "command", "exec", "shell"):
		return VulnCommandInjection
	case containsAny(checkID, "ssrf"):
		return VulnSSRF
	case containsAny(checkID, "path", "traversal", "lfi"):
		return VulnPathTraversal
	case containsAny(checkID, "crypto", "md5", "sha1", "weak"):
		return VulnInsecureCrypto
	case containsAny(checkID, "jwt"):
		return VulnInsecureJWT
	case containsAny(checkID, "deserializ", "pickle", "unserializ"):
		return VulnUnsafeDeserialize
	case containsAny(checkID, "eval"):
		return VulnEvalInjection
	case containsAny(checkID, "xxe", "xml"):
		return VulnXXE
	default:
		return VulnType(checkID)
	}
}

func semgrepSeverity(s string) Severity {
	switch s {
	case "ERROR":
		return SevCritical
	case "WARNING":
		return SevHigh
	case "INFO":
		return SevMedium
	default:
		return SevLow
	}
}

func containsAny(s string, subs ...string) bool {
	lower := filepath.Base(s)
	for _, sub := range subs {
		if len(lower) >= len(sub) {
			for i := 0; i <= len(lower)-len(sub); i++ {
				if lower[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
