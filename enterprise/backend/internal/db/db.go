package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func Connect(dsn string) *sql.DB {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("db: open: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db: ping: %v", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	fmt.Println("db: connected")
	return db
}
