package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/claude-safe/enterprise/internal/auth"
	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
)

type AuthHandler struct {
	db     *sql.DB
	secret string
}

func NewAuthHandler(db *sql.DB, secret string) *AuthHandler {
	return &AuthHandler{db: db, secret: secret}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	var user models.User
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, email, name, role, password_hash, created_at FROM users WHERE email = $1`,
		req.Email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.PasswordHash, &user.CreatedAt)
	if err == sql.ErrNoRows {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateToken(&user, h.secret)
	if err != nil {
		jsonError(w, "could not generate token", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)

	var user models.User
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, email, name, role, created_at FROM users WHERE id = $1`,
		claims.UserID,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.CreatedAt)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	jsonOK(w, user)
}
