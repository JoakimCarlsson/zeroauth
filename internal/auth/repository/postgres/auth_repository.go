package postgres

import (
	"database/sql"
	"time"

	"github.com/joakimcarlsson/zeroauth/internal/auth"
)

type authRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) auth.Repository {
	return &authRepository{db: db}
}

func (r *authRepository) CreateUser(user *auth.User) error {
	_, err := r.db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", user.Email, user.Password)
	return err
}

func (r *authRepository) CreateRefreshToken(userID int, token string, expiresAt time.Time) error {
	_, err := r.db.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		userID, token, expiresAt)
	return err
}

func (r *authRepository) GetRefreshToken(token string) (*auth.RefreshToken, error) {
	var rt auth.RefreshToken
	err := r.db.QueryRow("SELECT id, user_id, token, expires_at FROM refresh_tokens WHERE token = $1", token).
		Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *authRepository) DeleteRefreshToken(token string) error {
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE token = $1", token)
	return err
}

func (r *authRepository) DeleteUserRefreshTokens(userID int) error {
	_, err := r.db.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	return err
}

func (r *authRepository) GetUserByEmail(email string) (*auth.User, error) {
	user := &auth.User{}
	err := r.db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}
