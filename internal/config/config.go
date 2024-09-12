package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseURL      string
	JWTAccessSecret  string
	JWTRefreshSecret string
	ServerPort       string
	BaseURL          string
}

func Load() *Config {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%s", os.Getenv("SERVER_PORT"))
	}

	return &Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		JWTAccessSecret:  os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret: os.Getenv("JWT_REFRESH_SECRET"),
		ServerPort:       os.Getenv("SERVER_PORT"),
		BaseURL:          baseURL,
	}
}
