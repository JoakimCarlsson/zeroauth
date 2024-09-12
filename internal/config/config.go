package config

import "os"

type Config struct {
	DatabaseURL string
	JWTSecret   string
	ServerPort  string
}

func Load() *Config {
	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		ServerPort:  os.Getenv("SERVER_PORT"),
	}
}
