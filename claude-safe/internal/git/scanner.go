package git

import (
	"os/exec"
	"strings"

	"github.com/claude-safe/claude-safe/internal/secrets"
)

type DiffFinding struct {
	File    string
	Line    int
	Secret  secrets.Finding
}

type Scanner struct {
	detector *secrets.Detector
}

func New() *Scanner {
	return &Scanner{detector: secrets.New()}
}

// ScanStagedDiff scans files staged for commit (git diff --cached)
func (s *Scanner) ScanStagedDiff() ([]DiffFinding, error) {
	return s.runDiff("--cached")
}

// ScanWorkingDiff scans unstaged changes (git diff)
func (s *Scanner) ScanWorkingDiff() ([]DiffFinding, error) {
	return s.runDiff()
}

// ScanText scans arbitrary diff text (used for piped input)
func (s *Scanner) ScanText(diffText string) []DiffFinding {
	return s.parseDiff(diffText)
}

func (s *Scanner) runDiff(args ...string) ([]DiffFinding, error) {
	cmdArgs := append([]string{"diff"}, args...)
	out, err := exec.Command("git", cmdArgs...).Output()
	if err != nil {
		return nil, err
	}
	return s.parseDiff(string(out)), nil
}

func (s *Scanner) parseDiff(diff string) []DiffFinding {
	var findings []DiffFinding
	var currentFile string
	lineNum := 0

	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
		case strings.HasPrefix(line, "@@ "):
			// Parse hunk header to get starting line number
			lineNum = parseHunkStartLine(line)
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			// Only scan added lines (+), not removed lines (-)
			lineNum++
			added := strings.TrimPrefix(line, "+")
			secretFindings := s.detector.ScanText(added)
			for _, f := range secretFindings {
				findings = append(findings, DiffFinding{
					File:   currentFile,
					Line:   lineNum,
					Secret: f,
				})
			}
		case !strings.HasPrefix(line, "-"):
			lineNum++
		}
	}
	return findings
}

// parseHunkStartLine extracts the destination start line from a hunk header like "@@ -1,4 +5,8 @@"
func parseHunkStartLine(hunk string) int {
	// Format: @@ -old_start,old_count +new_start,new_count @@
	parts := strings.Fields(hunk)
	for _, p := range parts {
		if strings.HasPrefix(p, "+") && p != "+++" {
			p = strings.TrimPrefix(p, "+")
			if comma := strings.Index(p, ","); comma != -1 {
				p = p[:comma]
			}
			n := 0
			for _, c := range p {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			return n
		}
	}
	return 0
}
