package handlers

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/claude-safe/enterprise/internal/models"
)

type DevelopersHandler struct{ db *sql.DB }

func NewDevelopersHandler(db *sql.DB) *DevelopersHandler { return &DevelopersHandler{db: db} }

func (h *DevelopersHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT u.id, u.email, u.name,
		       COUNT(se.id)                                            AS total_scans,
		       SUM(CASE WHEN se.blocked THEN 1 ELSE 0 END)            AS blocked_scans,
		       COALESCE(AVG(se.risk_score),0)                         AS avg_risk_score,
		       MAX(se.created_at)                                      AS last_active
		FROM users u
		LEFT JOIN scan_events se ON se.user_id = u.id
		WHERE u.role = 'developer'
		GROUP BY u.id, u.email, u.name
		ORDER BY total_scans DESC`)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	devs := []models.Developer{}
	for rows.Next() {
		var d models.Developer
		rows.Scan(&d.ID, &d.Email, &d.Name,
			&d.TotalScans, &d.BlockedScans, &d.AvgRiskScore, &d.LastActive)
		devs = append(devs, d)
	}
	jsonOK(w, devs)
}

func (h *DevelopersHandler) Activity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Last 30 events for this developer
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT se.id, se.user_id, u.email, u.name, se.tool_name, se.input,
		       se.risk_level, se.risk_score, se.blocked, se.reason, se.findings, se.created_at
		FROM scan_events se
		LEFT JOIN users u ON u.id = se.user_id
		WHERE se.user_id = $1
		ORDER BY se.created_at DESC LIMIT 30`, id)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := []models.ScanEvent{}
	for rows.Next() {
		var e models.ScanEvent
		rows.Scan(&e.ID, &e.UserID, &e.UserEmail, &e.UserName,
			&e.ToolName, &e.Input, &e.RiskLevel, &e.RiskScore,
			&e.Blocked, &e.Reason, &e.Findings, &e.CreatedAt)
		events = append(events, e)
	}

	// Developer info
	var dev models.Developer
	err = h.db.QueryRowContext(r.Context(), `
		SELECT u.id, u.email, u.name,
		       COUNT(se.id), SUM(CASE WHEN se.blocked THEN 1 ELSE 0 END),
		       COALESCE(AVG(se.risk_score),0), MAX(se.created_at)
		FROM users u
		LEFT JOIN scan_events se ON se.user_id = u.id
		WHERE u.id = $1
		GROUP BY u.id, u.email, u.name`, id,
	).Scan(&dev.ID, &dev.Email, &dev.Name,
		&dev.TotalScans, &dev.BlockedScans, &dev.AvgRiskScore, &dev.LastActive)
	if err == sql.ErrNoRows {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}

	jsonOK(w, map[string]interface{}{
		"developer": dev,
		"events":    events,
	})
}
