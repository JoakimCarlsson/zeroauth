package server

import (
	"database/sql"
	"fmt"
	"net/http"

	authHttp "github.com/joakimcarlsson/zeroauth/internal/auth/delivery/http"
	authRepo "github.com/joakimcarlsson/zeroauth/internal/auth/repository/postgres"
	authUseCase "github.com/joakimcarlsson/zeroauth/internal/auth/usecase"

	"github.com/joakimcarlsson/zeroauth/internal/config"
	"github.com/joakimcarlsson/zeroauth/internal/middleware"
	"github.com/joakimcarlsson/zeroauth/pkg/hash"
	"github.com/joakimcarlsson/zeroauth/pkg/jwt"
)

type Server struct {
	cfg    *config.Config
	router *http.ServeMux
}

func NewServer(cfg *config.Config, db *sql.DB) *Server {
	s := &Server{
		cfg:    cfg,
		router: http.NewServeMux(),
	}

	hashService := hash.NewBcryptService()
	jwtService := jwt.NewJWTService(cfg.JWTSecret)

	authRepo := authRepo.NewAuthRepository(db)
	authUseCase := authUseCase.NewAuthUseCase(authRepo, hashService, jwtService)
	authHandler := authHttp.NewAuthHandler(authUseCase)

	s.router.HandleFunc("/register", authHandler.Register)
	s.router.HandleFunc("/login", authHandler.Login)
	s.router.HandleFunc("/protected", middleware.AuthMiddleware(jwtService)(s.protectedHandler))

	return s
}

func (s *Server) protectedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id")
	fmt.Fprintf(w, "Protected route accessed by user %v", userID)
}

func (s *Server) Start() error {
	return http.ListenAndServe(":"+s.cfg.ServerPort, s.router)
}
