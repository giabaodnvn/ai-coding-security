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

	// ── BATCH 1: High-confidence, low false-positive ───────────────────────────

	{
		// Format: sk-ant-api<NN>-<95+ base64url chars>
		Name:     "Anthropic API Key",
		Pattern:  regexp.MustCompile(`sk-ant-api\d{2}-[a-zA-Z0-9_-]{95,}`),
		Severity: SeverityCritical,
	},
	{
		// Format: DefaultEndpointsProtocol=https;AccountName=...;AccountKey=<64+ base64>
		Name:     "Azure Storage Connection String",
		Pattern:  regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{64,}`),
		Severity: SeverityCritical,
	},
	{
		// Format: SG.<22 chars>.<43 chars> — exact lengths, near-zero false positives
		Name:     "SendGrid API Key",
		Pattern:  regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		Severity: SeverityHigh,
	},
	{
		// Legacy FCM Server Key: AAAA<7 chars>:<140+ base64url chars>
		Name:     "Firebase FCM Server Key",
		Pattern:  regexp.MustCompile(`AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140,}`),
		Severity: SeverityHigh,
	},

	// ── BATCH 2: Medium-confidence ────────────────────────────────────────────

	{
		// Format: hf_<34+ alphanumeric chars>
		Name:     "Hugging Face Token",
		Pattern:  regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`),
		Severity: SeverityHigh,
	},
	{
		// Format: AC<32 lowercase hex chars> — word boundaries prevent partial matches
		Name:     "Twilio Account SID",
		Pattern:  regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
		Severity: SeverityHigh,
	},

	// ── BATCH 3: Context-dependent ────────────────────────────────────────────

	{
		// 32 hex chars have no prefix — require TWILIO_AUTH_TOKEN or twilio...auth_token context
		Name:     "Twilio Auth Token",
		Pattern:  regexp.MustCompile(`(?i)(TWILIO_AUTH_TOKEN|twilio.{0,10}auth.?token)\s*[:=]\s*['"]([a-f0-9]{32})['"]`),
		Severity: SeverityHigh,
	},
	{
		// 40 alphanumeric chars have no prefix — require CF_API_TOKEN or cloudflare context
		Name:     "Cloudflare API Token",
		Pattern:  regexp.MustCompile(`(?i)(CF_API_TOKEN|cloudflare.{0,20}(api.?token|token|key))\s*[:=]\s*['"][a-zA-Z0-9_-]{40}['"]`),
		Severity: SeverityHigh,
	},
	{
		// pk_live_ is public by design but confirms production environment; pk_test_ is safe
		Name:     "Stripe Publishable Key",
		Pattern:  regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
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
