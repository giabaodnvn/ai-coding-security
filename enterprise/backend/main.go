package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/claude-safe/enterprise/internal/config"
	"github.com/claude-safe/enterprise/internal/db"
	"github.com/claude-safe/enterprise/internal/handlers"
	"github.com/claude-safe/enterprise/internal/middleware"
	"github.com/claude-safe/enterprise/internal/models"
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

	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{cfg.CORSOrigin},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Auth (public)
	r.Post("/api/auth/login", authH.Login)

	// Ingest (accepts API key or JWT — open for claude-safe CLI)
	r.Post("/api/events", auditH.Ingest)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.Authenticate(cfg.JWTSecret))

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

		// Policies (admin + analyst)
		r.Route("/api/policies", func(r chi.Router) {
			r.Get("/", polH.List)
			r.With(middleware.RequireRole(models.RoleAdmin, models.RoleAnalyst)).Post("/", polH.Create)
			r.With(middleware.RequireRole(models.RoleAdmin, models.RoleAnalyst)).Put("/{id}", polH.Update)
			r.With(middleware.RequireRole(models.RoleAdmin)).Delete("/{id}", polH.Delete)
		})
	})

	addr := ":" + cfg.Port
	fmt.Printf("server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
