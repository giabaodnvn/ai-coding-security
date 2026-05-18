package risk

import (
	"testing"

	"github.com/claude-safe/claude-safe/internal/command"
	"github.com/claude-safe/claude-safe/internal/secrets"
)

func TestScore(t *testing.T) {
	tests := []struct {
		name           string
		secretFindings []secrets.Finding
		cmdRisks       []command.CommandRisk
		wantMinScore   int
		wantLevel      Level
		wantBlocked    bool
	}{
		{
			name:         "no findings",
			wantMinScore: 0,
			wantLevel:    LevelSafe,
			wantBlocked:  false,
		},
		{
			name: "critical secret",
			secretFindings: []secrets.Finding{
				{Rule: "AWS Access Key", Severity: secrets.SeverityCritical},
			},
			wantMinScore: 40,
			wantLevel:    LevelHigh, // score=40, threshold: HIGH is 36-55
			wantBlocked:  true,
		},
		{
			name: "critical command",
			cmdRisks: []command.CommandRisk{
				{Command: "rm -rf /", RiskLevel: command.RiskCritical, ShouldBlock: true},
			},
			wantMinScore: 50,
			wantLevel:    LevelHigh, // score=50, threshold: HIGH is 36-55
			wantBlocked:  true,
		},
		{
			name: "medium command only",
			cmdRisks: []command.CommandRisk{
				{Command: "sudo apt update", RiskLevel: command.RiskMedium, ShouldBlock: false},
			},
			wantMinScore: 10,
			wantLevel:    LevelLow,
			wantBlocked:  false,
		},
		{
			name: "combined critical findings capped at 100",
			secretFindings: []secrets.Finding{
				{Rule: "AWS Key", Severity: secrets.SeverityCritical},
				{Rule: "GitHub Token", Severity: secrets.SeverityCritical},
			},
			cmdRisks: []command.CommandRisk{
				{Command: "rm -rf /", RiskLevel: command.RiskCritical, ShouldBlock: true},
			},
			wantMinScore: 100,
			wantLevel:    LevelCritical,
			wantBlocked:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Score(tt.secretFindings, tt.cmdRisks)

			if report.Score < tt.wantMinScore {
				t.Errorf("Score() = %d, want >= %d", report.Score, tt.wantMinScore)
			}
			if report.Level != tt.wantLevel {
				t.Errorf("Level() = %s, want %s (score=%d)", report.Level, tt.wantLevel, report.Score)
			}
			if report.ShouldBlock != tt.wantBlocked {
				t.Errorf("ShouldBlock = %v, want %v", report.ShouldBlock, tt.wantBlocked)
			}
		})
	}
}
