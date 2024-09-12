package usecase

import (
	"errors"

	"github.com/joakimcarlsson/zeroauth/internal/auth"
	"github.com/joakimcarlsson/zeroauth/pkg/hash"
	"github.com/joakimcarlsson/zeroauth/pkg/jwt"
)

type authUseCase struct {
	repo        auth.Repository
	hashService hash.Service
	jwtService  jwt.Service
}

func NewAuthUseCase(repo auth.Repository, hashService hash.Service, jwtService jwt.Service) auth.UseCase {
	return &authUseCase{
		repo:        repo,
		hashService: hashService,
		jwtService:  jwtService,
	}
}

func (uc *authUseCase) Register(email, password string) error {
	hashedPassword, err := uc.hashService.Hash(password)
	if err != nil {
		return err
	}

	user := &auth.User{
		Email:    email,
		Password: hashedPassword,
	}

	return uc.repo.CreateUser(user)
}

func (uc *authUseCase) Login(email, password string) (string, error) {
	user, err := uc.repo.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	if !uc.hashService.Compare(user.Password, password) {
		return "", errors.New("invalid credentials")
	}

	return uc.jwtService.Generate(user.ID)
}
