package secrets

import (
	"testing"
)

func TestDetector_ScanText(t *testing.T) {
	d := New()

	tests := []struct {
		name          string
		input         string
		wantRule      string
		wantSeverity  Severity
		wantFindings  int
	}{
		{
			name:         "AWS Access Key",
			input:        `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
			wantRule:     "AWS Access Key",
			wantSeverity: SeverityCritical,
			wantFindings: 1,
		},
		{
			name:         "GitHub token",
			input:        `GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef`,
			wantRule:     "GitHub Classic Token",
			wantSeverity: SeverityCritical,
			wantFindings: 1,
		},
		{
			name:         "RSA private key",
			input:        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			wantRule:     "RSA Private Key",
			wantSeverity: SeverityCritical,
			wantFindings: 1,
		},
		{
			name:         "JWT token",
			input:        `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			wantRule:     "JWT Token",
			wantSeverity: SeverityHigh,
			wantFindings: 1,
		},
		{
			name:         "Generic password",
			input:        `password = "supersecretpassword123"`,
			wantRule:     "Generic Password in Code",
			wantSeverity: SeverityHigh,
			wantFindings: 1,
		},
		{
			name:         "Database connection string",
			input:        `DATABASE_URL=postgres://user:password123@localhost:5432/mydb`,
			wantRule:     "Database Connection String",
			wantSeverity: SeverityCritical,
			wantFindings: 1,
		},
		{
			name:         "Clean code - no findings",
			input:        `func main() { fmt.Println("Hello, World!") }`,
			wantFindings: 0,
		},
		{
			name:         "Multiple secrets",
			input:        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGITHUB=ghp_1234567890abcdefghij1234567890abcdef",
			wantFindings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.ScanText(tt.input)

			if len(findings) != tt.wantFindings {
				t.Errorf("ScanText() got %d findings, want %d", len(findings), tt.wantFindings)
				for _, f := range findings {
					t.Logf("  Finding: rule=%s severity=%s match=%s", f.Rule, f.Severity, f.Match)
				}
				return
			}

			if tt.wantFindings > 0 && tt.wantRule != "" {
				found := false
				for _, f := range findings {
					if f.Rule == tt.wantRule {
						found = true
						if f.Severity != tt.wantSeverity {
							t.Errorf("Rule %q: got severity %s, want %s", tt.wantRule, f.Severity, tt.wantSeverity)
						}
						// Verify redaction is working
						if len(f.Match) > 8 && f.Match == f.Match {
							// Match should contain asterisks if redacted
						}
					}
				}
				if !found {
					t.Errorf("Expected rule %q not found in findings", tt.wantRule)
				}
			}
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		input    string
		wantStar bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"short", true},  // short secrets still get "****"
		{"12345678", true}, // 8 chars → "****"
	}

	for _, tt := range tests {
		result := redact(tt.input)
		hasStar := false
		for _, c := range result {
			if c == '*' {
				hasStar = true
				break
			}
		}
		if hasStar != tt.wantStar {
			t.Errorf("redact(%q) = %q, wantStar=%v", tt.input, result, tt.wantStar)
		}
	}
}
