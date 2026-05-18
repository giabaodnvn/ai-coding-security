package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
)

type AuditHandler struct{ db *sql.DB }

func NewAuditHandler(db *sql.DB) *AuditHandler { return &AuditHandler{db: db} }

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit == 0 {
		limit = 50
	}

	rows, err := h.db.QueryContext(r.Context(), `
		SELECT se.id, se.user_id, u.email, u.name, se.tool_name, se.input,
		       se.risk_level, se.risk_score, se.blocked, se.reason, se.findings, se.created_at
		FROM scan_events se
		LEFT JOIN users u ON u.id = se.user_id
		ORDER BY se.created_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
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

	var total int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM scan_events`).Scan(&total)

	jsonOK(w, map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// Ingest accepts events POSTed by claude-safe CLI instances
func (h *AuditHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	var req models.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Resolve user by email
	var userID *string
	var uid string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id FROM users WHERE email = $1`, req.UserEmail).Scan(&uid)
	if err == nil {
		userID = &uid
	}

	findings := req.Findings
	if findings == nil {
		findings = json.RawMessage("[]")
	}

	// Get claims for authenticated ingest (optional)
	if claims := middleware.GetClaims(r); claims != nil && userID == nil {
		userID = &claims.UserID
	}

	_, err = h.db.ExecContext(r.Context(), `
		INSERT INTO scan_events (user_id, tool_name, input, risk_level, risk_score, blocked, reason, findings)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		userID, req.ToolName, req.Input, req.RiskLevel, req.RiskScore,
		req.Blocked, req.Reason, findings)
	if err != nil {
		jsonError(w, "insert failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"ok":true}`))
}
