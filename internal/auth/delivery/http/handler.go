package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/joakimcarlsson/zeroauth/internal/auth"
	"github.com/joakimcarlsson/zeroauth/internal/auth/attempt"
)

type AuthHandler struct {
	useCase auth.UseCase
	tracker *attempt.Tracker
}

func NewAuthHandler(useCase auth.UseCase) *AuthHandler {
	return &AuthHandler{
		useCase: useCase,
		tracker: attempt.NewTracker(5, 15*time.Minute),
	}
}

func (h *AuthHandler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.useCase.Register(req.Email, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func (h *AuthHandler) Login(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if h.tracker.ShouldBlock(req.Email) {
		http.Error(w, "Too many failed attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}

	accessToken, refreshToken, err := h.useCase.Login(req.Email, req.Password)
	if err != nil {
		h.tracker.AddAttempt(req.Email, false)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	h.tracker.AddAttempt(req.Email, true)
	h.tracker.ResetAttempts(req.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *AuthHandler) RefreshToken(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newAccessToken, newRefreshToken, err := h.useCase.RefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func (h *AuthHandler) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.useCase.Logout(req.RefreshToken); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}
