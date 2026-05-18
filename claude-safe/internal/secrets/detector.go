package secrets

import (
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Finding struct {
	Rule     string
	Match    string
	Severity Severity
	Line     int
}

type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
}

var defaultRules = []Rule{
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "AWS Secret Key",
		Pattern:  regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]`),
		Severity: SeverityCritical,
	},
	{
		// Covers gho_, ghu_, ghs_, ghr_ (non-classic formats)
		Name:     "GitHub Token",
		Pattern:  regexp.MustCompile(`gh[ousr]_[0-9a-zA-Z]{36,255}`),
		Severity: SeverityCritical,
	},
	{
		// Classic personal access token
		Name:     "GitHub Classic Token",
		Pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "OpenAI API Key",
		Pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "OpenAI API Key (new format)",
		Pattern:  regexp.MustCompile(`sk-proj-[a-zA-Z0-9\-_]{50,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "RSA Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity: SeverityCritical,
	},
	{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Generic Password in Code",
		Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Generic Secret in Code",
		Pattern:  regexp.MustCompile(`(?i)(secret|api_key|apikey|access_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Database Connection String",
		Pattern:  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Slack Token",
		Pattern:  regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Stripe Secret Key",
		Pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Hardcoded IP with credentials",
		Pattern:  regexp.MustCompile(`(?i)(admin|root|user)\s*:\s*[^\s@]+\s*@\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		Severity: SeverityMedium,
	},
}

type Detector struct {
	rules []Rule
}

func New() *Detector {
	return &Detector{rules: defaultRules}
}

func (d *Detector) ScanText(text string) []Finding {
	var findings []Finding
	lines := strings.Split(text, "\n")

	for lineNum, line := range lines {
		for _, rule := range d.rules {
			match := rule.Pattern.FindString(line)
			if match == "" {
				continue
			}
			// Redact the matched value in output for safety
			redacted := redact(match)
			findings = append(findings, Finding{
				Rule:     rule.Name,
				Match:    redacted,
				Severity: rule.Severity,
				Line:     lineNum + 1,
			})
		}
	}
	return findings
}

// redact masks the middle portion of a secret so it's safe to log
func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
