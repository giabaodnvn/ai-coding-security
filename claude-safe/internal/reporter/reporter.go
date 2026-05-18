package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// Reporter sends scan events to an enterprise dashboard.
// Activated when CLAUDE_SAFE_ENTERPRISE_URL and CLAUDE_SAFE_API_KEY are set.
type Reporter struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

type Event struct {
	UserEmail string `json:"user_email"`
	ToolName  string `json:"tool_name"`
	Input     string `json:"input"`
	RiskLevel string `json:"risk_level"`
	RiskScore int    `json:"risk_score"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason"`
}

// FromEnv returns a Reporter if CLAUDE_SAFE_ENTERPRISE_URL and CLAUDE_SAFE_API_KEY
// are both set, otherwise nil (reporting is opt-in).
func FromEnv() *Reporter {
	url := os.Getenv("CLAUDE_SAFE_ENTERPRISE_URL")
	key := os.Getenv("CLAUDE_SAFE_API_KEY")
	if url == "" || key == "" {
		return nil
	}
	return &Reporter{
		baseURL: url,
		apiKey:  key,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// Send posts the event to /api/events asynchronously; errors are silently dropped
// so a network failure never blocks the CLI.
func (r *Reporter) Send(ev Event) {
	if r == nil {
		return
	}
	go r.send(ev)
}

func (r *Reporter) send(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, r.baseURL+"/api/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
