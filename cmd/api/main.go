package main

import (
	"log"

	"github.com/joakimcarlsson/zeroauth/internal/config"
	"github.com/joakimcarlsson/zeroauth/internal/server"
	"github.com/joakimcarlsson/zeroauth/pkg/database"
)

func main() {
	cfg := config.Load()

	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	srv := server.NewServer(cfg, db)
	log.Fatal(srv.Start())
}
