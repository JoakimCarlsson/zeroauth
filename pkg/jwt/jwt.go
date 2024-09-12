package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Service interface {
	Generate(userID int) (string, error)
	Validate(token string) (int, error)
}

type jwtService struct {
	secretKey []byte
}

func NewJWTService(secretKey string) Service {
	return &jwtService{secretKey: []byte(secretKey)}
}

func (s *jwtService) Generate(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString(s.secretKey)
}

func (s *jwtService) Validate(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.secretKey, nil
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
