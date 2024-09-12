package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joakimcarlsson/zeroauth/pkg/token"
)

type Service interface {
	GenerateAccessToken(userID int) (string, error)
	GenerateRefreshToken(userID int) (string, error)
	ValidateAccessToken(token string) (int, error)
	GetRefreshTokenExpiry() time.Duration
}

type jwtService struct {
	accessSecretKey  []byte
	refreshSecretKey []byte
	accessExpiry     time.Duration
	refreshExpiry    time.Duration
	tokenService     token.Service
	tokenStrategy    token.Strategy
}

func NewJWTService(
	accessSecret, refreshSecret string,
	accessExpiry, refreshExpiry time.Duration,
	tokenService token.Service,
	tokenStrategy token.Strategy,
) Service {
	return &jwtService{
		accessSecretKey:  []byte(accessSecret),
		refreshSecretKey: []byte(refreshSecret),
		accessExpiry:     accessExpiry,
		refreshExpiry:    refreshExpiry,
		tokenService:     tokenService,
		tokenStrategy:    tokenStrategy,
	}
}

func (s *jwtService) GenerateAccessToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(s.accessExpiry).Unix(),
	})

	return token.SignedString(s.accessSecretKey)
}

func (s *jwtService) GenerateRefreshToken(userID int) (string, error) {
	return s.tokenService.GenerateRefreshToken(userID, s.tokenStrategy)
}

func (s *jwtService) ValidateAccessToken(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.accessSecretKey, nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := int(claims["user_id"].(float64))
		return userID, nil
	}

	return 0, jwt.ErrSignatureInvalid
}

func (s *jwtService) GetRefreshTokenExpiry() time.Duration {
	return s.refreshExpiry
}
