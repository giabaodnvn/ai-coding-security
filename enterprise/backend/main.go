package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/claude-safe/enterprise/internal/config"
	"github.com/claude-safe/enterprise/internal/db"
	"github.com/claude-safe/enterprise/internal/handlers"
	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
	"github.com/claude-safe/enterprise/internal/ratelimit"
)

func main() {
	cfg := config.Load()
	database := db.Connect(cfg.DatabaseURL)
	defer database.Close()

	// Handlers
	authH := handlers.NewAuthHandler(database, cfg.JWTSecret)
	statsH := handlers.NewStatsHandler(database)
	incH := handlers.NewIncidentsHandler(database)
	auditH := handlers.NewAuditHandler(database)
	polH := handlers.NewPoliciesHandler(database)
	devH := handlers.NewDevelopersHandler(database)
	apiKeyH := handlers.NewAPIKeysHandler(database)
	webhookH := handlers.NewWebhooksHandler(database)

	limiter := ratelimit.New()

	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{cfg.CORSOrigin},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: true,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Auth (public)
	r.Post("/api/auth/login", authH.Login)

	// Ingest — public but rate-limited per API key / IP
	r.With(rateLimitMiddleware(limiter)).Post("/api/events", auditH.Ingest)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.Authenticate(cfg.JWTSecret, database))

		r.Get("/api/auth/me", authH.Me)

		// Dashboard
		r.Get("/api/stats", statsH.Dashboard)

		// Incidents (blocked events)
		r.Get("/api/incidents", incH.List)

		// Audit log
		r.Get("/api/audit-logs", auditH.List)

		// Developers
		r.Get("/api/developers", devH.List)
		r.Get("/api/developers/{id}/activity", devH.Activity)

		// Policies (admin + analyst can write)
		r.Route("/api/policies", func(r chi.Router) {
			r.Get("/", polH.List)
			r.With(middleware.RequireRole(models.RoleAdmin, models.RoleAnalyst)).Post("/", polH.Create)
			r.With(middleware.RequireRole(models.RoleAdmin, models.RoleAnalyst)).Put("/{id}", polH.Update)
			r.With(middleware.RequireRole(models.RoleAdmin)).Delete("/{id}", polH.Delete)
		})

		// API keys (own keys only)
		r.Route("/api/api-keys", func(r chi.Router) {
			r.Get("/", apiKeyH.List)
			r.Post("/", apiKeyH.Create)
			r.Delete("/{id}", apiKeyH.Delete)
		})

		// Webhooks (own webhooks only)
		r.Route("/api/webhooks", func(r chi.Router) {
			r.Get("/", webhookH.List)
			r.Post("/", webhookH.Create)
			r.Delete("/{id}", webhookH.Delete)
		})
	})

	addr := ":" + cfg.Port
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Printf("server listening on %s\n", addr)
	log.Fatal(srv.ListenAndServe())
}

func rateLimitMiddleware(limiter *ratelimit.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.RemoteAddr
			}
			if !limiter.Allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
