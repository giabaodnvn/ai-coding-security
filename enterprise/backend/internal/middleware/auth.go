package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/claude-safe/enterprise/internal/auth"
	"github.com/claude-safe/enterprise/internal/models"
)

type contextKey string

const ClaimsKey contextKey = "claims"

func Authenticate(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			claims, err := auth.ValidateToken(strings.TrimPrefix(header, "Bearer "), secret)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
