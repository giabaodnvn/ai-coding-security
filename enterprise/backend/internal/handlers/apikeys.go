package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
)

type APIKeysHandler struct{ db *sql.DB }

func NewAPIKeysHandler(db *sql.DB) *APIKeysHandler { return &APIKeysHandler{db: db} }

func (h *APIKeysHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, user_id, name, key_prefix, last_used, created_at
		FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, claims.UserID)
	if err != nil {
		jsonError(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	keys := []models.APIKey{}
	for rows.Next() {
		var k models.APIKey
		rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyPrefix, &k.LastUsed, &k.CreatedAt)
		keys = append(keys, k)
	}
	jsonOK(w, keys)
}

func (h *APIKeysHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	// Generate cs_ + 40 random hex chars
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		jsonError(w, "key generation failed", http.StatusInternalServerError)
		return
	}
	randomPart := hex.EncodeToString(raw) // 40 chars
	fullKey := "cs_" + randomPart

	hash := sha256.Sum256([]byte(fullKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := "cs_" + randomPart[:8] + "..."

	var id string
	err := h.db.QueryRowContext(r.Context(), `
		INSERT INTO api_keys (user_id, name, key_hash, key_prefix)
		VALUES ($1,$2,$3,$4) RETURNING id`,
		claims.UserID, req.Name, keyHash, keyPrefix,
	).Scan(&id)
	if err != nil {
		jsonError(w, "insert failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{
		"id":     id,
		"key":    fullKey,
		"prefix": keyPrefix,
	})
}

func (h *APIKeysHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	id := chi.URLParam(r, "id")
	res, err := h.db.ExecContext(r.Context(),
		`DELETE FROM api_keys WHERE id=$1 AND user_id=$2`, id, claims.UserID)
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
