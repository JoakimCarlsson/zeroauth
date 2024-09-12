package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/joakimcarlsson/zeroauth/pkg/jwt"
)

func AuthMiddleware(jwtService jwt.Service) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing authorization header", http.StatusUnauthorized)
				return
			}

			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) != 2 {
				http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			userID, err := jwtService.Validate(bearerToken[1])
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
