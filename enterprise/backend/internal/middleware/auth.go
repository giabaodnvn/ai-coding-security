package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/claude-safe/enterprise/internal/auth"
	"github.com/claude-safe/enterprise/internal/models"
)

type contextKey string

const ClaimsKey contextKey = "claims"

func Authenticate(secret string, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try Bearer JWT first
			if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
				claims, err := auth.ValidateToken(strings.TrimPrefix(header, "Bearer "), secret)
				if err != nil {
					http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
					return
				}
				ctx := context.WithValue(r.Context(), ClaimsKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Try X-API-Key header
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				claims, err := lookupAPIKey(r.Context(), db, apiKey)
				if err != nil {
					http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
					return
				}
				ctx := context.WithValue(r.Context(), ClaimsKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}

func lookupAPIKey(ctx context.Context, db *sql.DB, key string) (*auth.Claims, error) {
	hash := sha256.Sum256([]byte(key))
	keyHash := hex.EncodeToString(hash[:])

	var userID, email, role, keyID string
	err := db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.role, ak.id
		FROM api_keys ak
		JOIN users u ON u.id = ak.user_id
		WHERE ak.key_hash = $1`, keyHash,
	).Scan(&userID, &email, &role, &keyID)
	if err != nil {
		return nil, err
	}

	// Update last_used asynchronously
	go db.Exec(`UPDATE api_keys SET last_used=NOW() WHERE id=$1`, keyID)

	return &auth.Claims{
		UserID: userID,
		Email:  email,
		Role:   models.Role(role),
	}, nil
}

func RequireRole(roles ...models.Role) func(http.Handler) http.Handler {
	allowed := make(map[models.Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsKey).(*auth.Claims)
			if !ok || !allowed[claims.Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GetClaims(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(ClaimsKey).(*auth.Claims)
	return c
}
