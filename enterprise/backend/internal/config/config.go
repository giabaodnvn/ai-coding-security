package config

import "os"

type Config struct {
	DatabaseURL string
	JWTSecret   string
	Port        string
	CORSOrigin  string
}

func Load() *Config {
	return &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://claude_safe:secret@localhost:5432/claude_safe?sslmode=disable"),
		JWTSecret:   getEnv("JWT_SECRET", "dev-secret-change-in-production!!"),
		Port:        getEnv("PORT", "8080"),
		CORSOrigin:  getEnv("CORS_ORIGIN", "http://localhost:3000"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
