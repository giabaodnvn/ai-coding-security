package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"

	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
)

type WebhooksHandler struct{ db *sql.DB }

func NewWebhooksHandler(db *sql.DB) *WebhooksHandler { return &WebhooksHandler{db: db} }

func (h *WebhooksHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, user_id, name, url, events, active, created_at
		FROM webhooks WHERE user_id = $1 ORDER BY created_at DESC`, claims.UserID)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	hooks := []models.Webhook{}
	for rows.Next() {
		var wh models.Webhook
		rows.Scan(&wh.ID, &wh.UserID, &wh.Name, &wh.URL, pq.Array(&wh.Events), &wh.Active, &wh.CreatedAt)
		hooks = append(hooks, wh)
	}
	jsonOK(w, hooks)
}

func (h *WebhooksHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	var req struct {
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.URL == "" {
		jsonError(w, "name and url are required", http.StatusBadRequest)
		return
	}
	if len(req.Events) == 0 {
		req.Events = []string{"blocked"}
	}

	var wh models.Webhook
	err := h.db.QueryRowContext(r.Context(), `
		INSERT INTO webhooks (user_id, name, url, secret, events)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, user_id, name, url, events, active, created_at`,
		claims.UserID, req.Name, req.URL, req.Secret, pq.Array(req.Events),
	).Scan(&wh.ID, &wh.UserID, &wh.Name, &wh.URL, pq.Array(&wh.Events), &wh.Active, &wh.CreatedAt)
	if err != nil {
		jsonError(w, "insert failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, wh)
}

func (h *WebhooksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	id := chi.URLParam(r, "id")
	res, err := h.db.ExecContext(r.Context(),
		`DELETE FROM webhooks WHERE id=$1 AND user_id=$2`, id, claims.UserID)
	if err != nil {
		jsonError(w, "delete failed", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// FireWebhooks sends the event payload to all active webhooks for a user that match the event type.
func FireWebhooks(db *sql.DB, userID *string, eventType string, payload interface{}) {
	if userID == nil {
		return
	}
	rows, err := db.Query(`
		SELECT url, secret FROM webhooks
		WHERE user_id=$1 AND active=true AND $2=ANY(events)`, *userID, eventType)
	if err != nil {
		return
	}
	defer rows.Close()

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	for rows.Next() {
		var url, secret string
		rows.Scan(&url, &secret)
		go deliverWebhook(url, secret, body)
	}
}

func deliverWebhook(url, secret string, body []byte) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "claude-safe-webhook/1.0")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Claude-Safe-Signature", fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil))))
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
