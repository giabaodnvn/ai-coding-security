package models

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleAdmin     Role = "admin"
	RoleAnalyst   Role = "analyst"
	RoleDeveloper Role = "developer"
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type ScanEvent struct {
	ID        string          `json:"id"`
	UserID    *string         `json:"user_id"`
	UserEmail *string         `json:"user_email"`
	UserName  *string         `json:"user_name"`
	ToolName  string          `json:"tool_name"`
	Input     string          `json:"input"`
	RiskLevel string          `json:"risk_level"`
	RiskScore int             `json:"risk_score"`
	Blocked   bool            `json:"blocked"`
	Reason    string          `json:"reason"`
	Findings  json.RawMessage `json:"findings"`
	CreatedAt time.Time       `json:"created_at"`
}

type Policy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Config      json.RawMessage `json:"config"`
	CreatedBy   *string         `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type Developer struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	TotalScans   int        `json:"total_scans"`
	BlockedScans int        `json:"blocked_scans"`
	AvgRiskScore float64    `json:"avg_risk_score"`
	LastActive   *time.Time `json:"last_active"`
}

type DashboardStats struct {
	TotalEventsToday int              `json:"total_events_today"`
	BlockedToday     int              `json:"blocked_today"`
	ActiveDevelopers int              `json:"active_developers"`
	AvgRiskScore     float64          `json:"avg_risk_score"`
	RiskDistribution map[string]int   `json:"risk_distribution"`
	EventsOverTime   []TimePoint      `json:"events_over_time"`
	RecentIncidents  []ScanEvent      `json:"recent_incidents"`
}

type TimePoint struct {
	Date    string `json:"date"`
	Total   int    `json:"total"`
	Blocked int    `json:"blocked"`
}

type APIKey struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"`
	LastUsed  *time.Time `json:"last_used"`
	CreatedAt time.Time  `json:"created_at"`
}

type Webhook struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Secret    string    `json:"-"`
	Events    []string  `json:"events"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// IngestRequest is posted by claude-safe CLI instances
type IngestRequest struct {
	UserEmail string          `json:"user_email"`
	ToolName  string          `json:"tool_name"`
	Input     string          `json:"input"`
	RiskLevel string          `json:"risk_level"`
	RiskScore int             `json:"risk_score"`
	Blocked   bool            `json:"blocked"`
	Reason    string          `json:"reason"`
	Findings  json.RawMessage `json:"findings"`
}
