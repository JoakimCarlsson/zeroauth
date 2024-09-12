package hash

import "golang.org/x/crypto/bcrypt"

type Service interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) bool
}

type bcryptService struct{}

func NewBcryptService() Service {
	return &bcryptService{}
}

func (s *bcryptService) Hash(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s *bcryptService) Compare(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
