package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/claude-safe/claude-safe/internal/risk"
)

type Policy struct {
	BlockDangerousCommands bool     `yaml:"block_dangerous_commands"`
	BlockPrivateKeys       bool     `yaml:"block_private_keys"`
	BlockSecrets           bool     `yaml:"block_secrets"`
	BlockSensitivePaths    bool     `yaml:"block_sensitive_paths"`
	MaxRiskLevel           string   `yaml:"max_risk_level"`
	AllowSudo              bool     `yaml:"allow_sudo"`
	AllowList              []string `yaml:"allow_list"`
	DenyList               []string `yaml:"deny_list"`
	AuditLog               bool     `yaml:"audit_log"`
	AuditLogPath           string   `yaml:"audit_log_path"`
	NotifyOnBlock          bool     `yaml:"notify_on_block"`
}

func Default() *Policy {
	return &Policy{
		BlockDangerousCommands: true,
		BlockPrivateKeys:       true,
		BlockSecrets:           true,
		BlockSensitivePaths:    true,
		MaxRiskLevel:           "medium",
		AllowSudo:              false,
		AuditLog:               true,
		AuditLogPath:           ".claude-safe/audit.log",
		NotifyOnBlock:          true,
	}
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	p := Default()
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	return p, nil
}

func (p *Policy) IsBlocked(report risk.Report) (bool, string) {
	if !report.ShouldBlock {
		return false, ""
	}

	maxLevel := p.maxRiskLevel()

	if levelOrder(report.Level) >= levelOrder(maxLevel) && report.Level != risk.LevelSafe {
		return true, fmt.Sprintf("Risk level %s exceeds policy maximum %s", report.Level, p.MaxRiskLevel)
	}

	if p.BlockSecrets && len(report.SecretFindings) > 0 {
		return true, fmt.Sprintf("Policy blocks secrets (%d detected)", len(report.SecretFindings))
	}

	if p.BlockDangerousCommands && len(report.CommandRisks) > 0 {
		return true, fmt.Sprintf("Policy blocks dangerous commands (%d detected)", len(report.CommandRisks))
	}

	return false, ""
}

func (p *Policy) maxRiskLevel() risk.Level {
	switch p.MaxRiskLevel {
	case "low":
		return risk.LevelLow
	case "medium":
		return risk.LevelMedium
	case "high":
		return risk.LevelHigh
	case "critical":
		return risk.LevelCritical
	default:
		return risk.LevelMedium
	}
}

func levelOrder(l risk.Level) int {
	switch l {
	case risk.LevelSafe:
		return 0
	case risk.LevelLow:
		return 1
	case risk.LevelMedium:
		return 2
	case risk.LevelHigh:
		return 3
	case risk.LevelCritical:
		return 4
	}
	return 0
}

func Save(p *Policy, path string) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
