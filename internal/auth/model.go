package auth

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

type Repository interface {
	CreateUser(user *User) error
	GetUserByEmail(email string) (*User, error)
}

type UseCase interface {
	Register(email, password string) error
	Login(email, password string) (string, error)
}
