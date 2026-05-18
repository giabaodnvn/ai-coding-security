package risk

import (
	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/secrets"
)

type Level string

const (
	LevelSafe     Level = "SAFE"
	LevelLow      Level = "LOW"
	LevelMedium   Level = "MEDIUM"
	LevelHigh     Level = "HIGH"
	LevelCritical Level = "CRITICAL"
)

type Report struct {
	Score          int
	Level          Level
	Reasons        []string
	SecretFindings []secrets.Finding
	CommandRisks   []command.CommandRisk
	ShouldBlock    bool
}

// Score calculates a composite risk score (0-100) from findings
func Score(secretFindings []secrets.Finding, cmdRisks []command.CommandRisk) Report {
	report := Report{}
	score := 0

	for _, f := range secretFindings {
		report.SecretFindings = append(report.SecretFindings, f)
		switch f.Severity {
		case secrets.SeverityCritical:
			score += 40
			report.Reasons = append(report.Reasons, "[SECRET:CRITICAL] "+f.Rule+" detected")
		case secrets.SeverityHigh:
			score += 25
			report.Reasons = append(report.Reasons, "[SECRET:HIGH] "+f.Rule+" detected")
		case secrets.SeverityMedium:
			score += 15
			report.Reasons = append(report.Reasons, "[SECRET:MEDIUM] "+f.Rule+" detected")
		case secrets.SeverityLow:
			score += 5
			report.Reasons = append(report.Reasons, "[SECRET:LOW] "+f.Rule+" detected")
		}
	}

	for _, c := range cmdRisks {
		if c.RiskLevel == command.RiskLow {
			continue
		}
		report.CommandRisks = append(report.CommandRisks, c)
		switch c.RiskLevel {
		case command.RiskCritical:
			score += 50
			report.ShouldBlock = true
			report.Reasons = append(report.Reasons, "[CMD:CRITICAL] "+c.Reason)
		case command.RiskHigh:
			score += 30
			report.ShouldBlock = true
			report.Reasons = append(report.Reasons, "[CMD:HIGH] "+c.Reason)
		case command.RiskMedium:
			score += 10
			report.Reasons = append(report.Reasons, "[CMD:MEDIUM] "+c.Reason)
		}
	}

	if score > 100 {
		score = 100
	}

	// Block if any secret is critical/high severity
	for _, f := range secretFindings {
		if f.Severity == secrets.SeverityCritical || f.Severity == secrets.SeverityHigh {
			report.ShouldBlock = true
		}
	}

	report.Score = score
	report.Level = scoreToLevel(score)
	return report
}

func scoreToLevel(score int) Level {
	switch {
	case score == 0:
		return LevelSafe
	case score <= 15:
		return LevelLow
	case score <= 35:
		return LevelMedium
	case score <= 55:
		return LevelHigh
	default:
		return LevelCritical
	}
}
