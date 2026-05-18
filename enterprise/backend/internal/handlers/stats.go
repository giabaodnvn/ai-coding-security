package handlers

import (
	"database/sql"
	"net/http"

	"github.com/claude-safe/enterprise/internal/models"
)

type StatsHandler struct{ db *sql.DB }

func NewStatsHandler(db *sql.DB) *StatsHandler { return &StatsHandler{db: db} }

func (h *StatsHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats := models.DashboardStats{
		RiskDistribution: map[string]int{},
	}

	// Today's totals
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN blocked THEN 1 ELSE 0 END),0)
		 FROM scan_events WHERE created_at >= CURRENT_DATE`).
		Scan(&stats.TotalEventsToday, &stats.BlockedToday)

	// Active developers (scanned in last 7 days)
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT user_id) FROM scan_events WHERE created_at >= NOW() - INTERVAL '7 days'`).
		Scan(&stats.ActiveDevelopers)

	// Avg risk score
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(risk_score),0) FROM scan_events WHERE created_at >= CURRENT_DATE`).
		Scan(&stats.AvgRiskScore)

	// Risk distribution
	rows, err := h.db.QueryContext(ctx,
		`SELECT risk_level, COUNT(*) FROM scan_events GROUP BY risk_level`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var level string
			var count int
			rows.Scan(&level, &count)
			stats.RiskDistribution[level] = count
		}
	}

	// Events over last 14 days
	timeRows, err := h.db.QueryContext(ctx,
		`SELECT TO_CHAR(d::date,'YYYY-MM-DD'),
		        COALESCE(SUM(CASE WHEN created_at::date = d::date THEN 1 ELSE 0 END),0),
		        COALESCE(SUM(CASE WHEN created_at::date = d::date AND blocked THEN 1 ELSE 0 END),0)
		 FROM generate_series(NOW()-INTERVAL '13 days', NOW(), INTERVAL '1 day') d
		 LEFT JOIN scan_events ON created_at::date = d::date
		 GROUP BY d ORDER BY d`)
	if err == nil {
		defer timeRows.Close()
		for timeRows.Next() {
			var pt models.TimePoint
			timeRows.Scan(&pt.Date, &pt.Total, &pt.Blocked)
			stats.EventsOverTime = append(stats.EventsOverTime, pt)
		}
	}

	// Recent blocked incidents (last 10)
	incRows, err := h.db.QueryContext(ctx,
		`SELECT se.id, se.user_id, u.email, u.name, se.tool_name, se.input,
		        se.risk_level, se.risk_score, se.blocked, se.reason, se.findings, se.created_at
		 FROM scan_events se
		 LEFT JOIN users u ON u.id = se.user_id
		 WHERE se.blocked = true
		 ORDER BY se.created_at DESC LIMIT 10`)
	if err == nil {
		defer incRows.Close()
		for incRows.Next() {
			var e models.ScanEvent
			incRows.Scan(&e.ID, &e.UserID, &e.UserEmail, &e.UserName,
				&e.ToolName, &e.Input, &e.RiskLevel, &e.RiskScore,
				&e.Blocked, &e.Reason, &e.Findings, &e.CreatedAt)
			stats.RecentIncidents = append(stats.RecentIncidents, e)
		}
	}
	if stats.RecentIncidents == nil {
		stats.RecentIncidents = []models.ScanEvent{}
	}
	if stats.EventsOverTime == nil {
		stats.EventsOverTime = []models.TimePoint{}
	}

	jsonOK(w, stats)
}
