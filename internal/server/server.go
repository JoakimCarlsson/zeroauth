﻿package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	authHttp "github.com/joakimcarlsson/zeroauth/internal/auth/delivery/http"
	authRepo "github.com/joakimcarlsson/zeroauth/internal/auth/repository/postgres"
	authUseCase "github.com/joakimcarlsson/zeroauth/internal/auth/usecase"
	"golang.org/x/time/rate"

	"github.com/joakimcarlsson/zeroauth/internal/config"
	"github.com/joakimcarlsson/zeroauth/internal/middleware"
	"github.com/joakimcarlsson/zeroauth/pkg/hash"
	"github.com/joakimcarlsson/zeroauth/pkg/jwt"
	"github.com/joakimcarlsson/zeroauth/pkg/token"
)

type Server struct {
	cfg    *config.Config
	router *http.ServeMux
}

func NewServer(
	cfg *config.Config,
	db *sql.DB,
) *Server {
	s := &Server{
		cfg:    cfg,
		router: http.NewServeMux(),
	}

	hashService := hash.NewBcryptService()
	tokenService := token.NewTokenService(32)

	jwtService := jwt.NewJWTService(
		cfg.JWTAccessSecret,
		cfg.JWTRefreshSecret,
		time.Minute*15,
		time.Hour*24*7,
		tokenService,
		token.StrategyComposite,
		cfg.BaseURL,
		cfg.BaseURL,
	)

	limiter := middleware.NewIPRateLimiter(rate.Limit(5), 10)

	authRepo := authRepo.NewAuthRepository(db)
	authUseCase := authUseCase.NewAuthUseCase(authRepo, hashService, jwtService)
	authHandler := authHttp.NewAuthHandler(authUseCase)

	s.router.HandleFunc("/register", middleware.AuditLogMiddleware(middleware.RateLimitMiddleware(limiter)(authHandler.Register)))
	s.router.HandleFunc("/login", middleware.AuditLogMiddleware(middleware.RateLimitMiddleware(limiter)(authHandler.Login)))
	s.router.HandleFunc("/refresh", middleware.AuditLogMiddleware(middleware.RateLimitMiddleware(limiter)(authHandler.RefreshToken)))
	s.router.HandleFunc("/logout", middleware.AuditLogMiddleware(authHandler.Logout))
	s.router.HandleFunc("/protected", middleware.AuditLogMiddleware(middleware.AuthMiddleware(jwtService)(protectedHandler)))

	return s
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Protected route accessed successfully",
		"user_id": userID,
	})
}

func (s *Server) Start() error {
	return http.ListenAndServe(":"+s.cfg.ServerPort, s.router)
}
