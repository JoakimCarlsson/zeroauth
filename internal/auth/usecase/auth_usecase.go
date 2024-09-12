package usecase

import (
	"errors"
	"time"

	"github.com/joakimcarlsson/zeroauth/internal/auth"
	"github.com/joakimcarlsson/zeroauth/pkg/hash"
	"github.com/joakimcarlsson/zeroauth/pkg/jwt"
)

type authUseCase struct {
	repo        auth.Repository
	hashService hash.Service
	jwtService  jwt.Service
}

func NewAuthUseCase(
	repo auth.Repository,
	hashService hash.Service,
	jwtService jwt.Service,
) auth.UseCase {
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

func (uc *authUseCase) Login(email, password string) (string, string, error) {
	user, err := uc.repo.GetUserByEmail(email)
	if err != nil {
		return "", "", err
	}

	if !uc.hashService.Compare(user.Password, password) {
		return "", "", errors.New("invalid credentials")
	}

	accessToken, err := uc.jwtService.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := uc.jwtService.GenerateRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	expiresAt := time.Now().Add(uc.jwtService.GetRefreshTokenExpiry())
	err = uc.repo.CreateRefreshToken(user.ID, refreshToken, expiresAt)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (uc *authUseCase) RefreshToken(refreshToken string) (string, string, error) {
	storedToken, err := uc.repo.GetRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	if time.Now().After(storedToken.ExpiresAt) {
		uc.repo.DeleteRefreshToken(refreshToken)
		return "", "", errors.New("refresh token expired")
	}

	newAccessToken, err := uc.jwtService.GenerateAccessToken(storedToken.UserID)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := uc.jwtService.GenerateRefreshToken(storedToken.ID)
	if err != nil {
		return "", "", err
	}

	expiresAt := time.Now().Add(uc.jwtService.GetRefreshTokenExpiry())
	err = uc.repo.CreateRefreshToken(storedToken.UserID, newRefreshToken, expiresAt)
	if err != nil {
		return "", "", err
	}

	uc.repo.DeleteRefreshToken(refreshToken)

	return newAccessToken, newRefreshToken, nil
}

func (uc *authUseCase) Logout(refreshToken string) error {
	return uc.repo.DeleteRefreshToken(refreshToken)
}
