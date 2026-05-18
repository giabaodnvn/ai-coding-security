package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
)

type PoliciesHandler struct{ db *sql.DB }

func NewPoliciesHandler(db *sql.DB) *PoliciesHandler { return &PoliciesHandler{db: db} }

func (h *PoliciesHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, name, description, config, created_by, created_at, updated_at
		FROM policies ORDER BY created_at DESC`)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	policies := []models.Policy{}
	for rows.Next() {
		var p models.Policy
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.Config,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
		policies = append(policies, p)
	}
	jsonOK(w, policies)
}

func (h *PoliciesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Config      json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	claims := middleware.GetClaims(r)
	var p models.Policy
	err := h.db.QueryRowContext(r.Context(), `
		INSERT INTO policies (name, description, config, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING id, name, description, config, created_by, created_at, updated_at`,
		req.Name, req.Description, req.Config, claims.UserID,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Config,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		jsonError(w, "insert failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, p)
}

func (h *PoliciesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Config      json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	var p models.Policy
	err := h.db.QueryRowContext(r.Context(), `
		UPDATE policies SET name=$1, description=$2, config=$3, updated_at=NOW()
		WHERE id=$4
		RETURNING id, name, description, config, created_by, created_at, updated_at`,
		req.Name, req.Description, req.Config, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Config,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "update failed", http.StatusInternalServerError)
		return
	}
	jsonOK(w, p)
}

func (h *PoliciesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	res, err := h.db.ExecContext(r.Context(), `DELETE FROM policies WHERE id=$1`, id)
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
