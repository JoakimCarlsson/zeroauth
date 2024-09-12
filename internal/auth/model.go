package auth

import "time"

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

type RefreshToken struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Repository interface {
	CreateUser(user *User) error
	GetUserByEmail(email string) (*User, error)
	CreateRefreshToken(userID int, token string, expiresAt time.Time) error
	GetRefreshToken(token string) (*RefreshToken, error)
	DeleteRefreshToken(token string) error
	DeleteUserRefreshTokens(userID int) error
}

type UseCase interface {
	Register(email, password string) error
	Login(email, password string) (accessToken string, refreshToken string, err error)
	RefreshToken(refreshToken string) (newAccessToken string, newRefreshToken string, err error)
	Logout(refreshToken string) error
}
