package postgres

import (
	"database/sql"

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

func (r *authRepository) GetUserByEmail(email string) (*auth.User, error) {
	user := &auth.User{}
	err := r.db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}
