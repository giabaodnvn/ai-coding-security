package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/claude-safe/enterprise/internal/models"
)

type IncidentsHandler struct{ db *sql.DB }

func NewIncidentsHandler(db *sql.DB) *IncidentsHandler { return &IncidentsHandler{db: db} }

func (h *IncidentsHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit == 0 {
		limit = 20
	}
	level := q.Get("risk_level")

	query := `
		SELECT se.id, se.user_id, u.email, u.name, se.tool_name, se.input,
		       se.risk_level, se.risk_score, se.blocked, se.reason, se.findings, se.created_at
		FROM scan_events se
		LEFT JOIN users u ON u.id = se.user_id
		WHERE se.blocked = true`
	args := []interface{}{}
	argN := 1

	if level != "" {
		query += " AND se.risk_level = $" + strconv.Itoa(argN)
		args = append(args, level)
		argN++
	}
	query += " ORDER BY se.created_at DESC"
	query += " LIMIT $" + strconv.Itoa(argN) + " OFFSET $" + strconv.Itoa(argN+1)
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	incidents := []models.ScanEvent{}
	for rows.Next() {
		var e models.ScanEvent
		rows.Scan(&e.ID, &e.UserID, &e.UserEmail, &e.UserName,
			&e.ToolName, &e.Input, &e.RiskLevel, &e.RiskScore,
			&e.Blocked, &e.Reason, &e.Findings, &e.CreatedAt)
		incidents = append(incidents, e)
	}

	// total count
	countQuery := `SELECT COUNT(*) FROM scan_events WHERE blocked = true`
	countArgs := []interface{}{}
	if level != "" {
		countQuery += " AND risk_level = $1"
		countArgs = append(countArgs, level)
	}
	var total int
	h.db.QueryRowContext(r.Context(), countQuery, countArgs...).Scan(&total)

	jsonOK(w, map[string]interface{}{
		"incidents": incidents,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}
