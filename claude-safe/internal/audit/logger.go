package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/claude-safe/claude-safe/internal/risk"
)

type EventType string

const (
	EventScan    EventType = "SCAN"
	EventCommand EventType = "COMMAND"
	EventBlock   EventType = "BLOCK"
	EventAllow   EventType = "ALLOW"
	EventGitDiff EventType = "GIT_DIFF"
)

type Event struct {
	Timestamp  time.Time   `json:"timestamp"`
	EventType  EventType   `json:"event_type"`
	Input      string      `json:"input"`
	RiskScore  int         `json:"risk_score"`
	RiskLevel  risk.Level  `json:"risk_level"`
	Blocked    bool        `json:"blocked"`
	Reason     string      `json:"reason,omitempty"`
	WorkingDir string      `json:"working_dir,omitempty"`
}

type Logger struct {
	path    string
	enabled bool
}

func New(path string, enabled bool) *Logger {
	return &Logger{path: path, enabled: enabled}
}

func (l *Logger) Log(event Event) error {
	if !l.enabled {
		return nil
	}

	event.Timestamp = time.Now().UTC()

	if wd, err := os.Getwd(); err == nil {
		event.WorkingDir = wd
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0750); err != nil {
		return fmt.Errorf("creating audit log directory: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}

func (l *Logger) LogScan(input string, report risk.Report, blocked bool, reason string) {
	_ = l.Log(Event{
		EventType: func() EventType {
			if blocked {
				return EventBlock
			}
			return EventAllow
		}(),
		Input:     truncate(input, 200),
		RiskScore: report.Score,
		RiskLevel: report.Level,
		Blocked:   blocked,
		Reason:    reason,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
