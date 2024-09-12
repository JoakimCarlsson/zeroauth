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

type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

type jwtService struct {
	accessSecretKey  []byte
	refreshSecretKey []byte
	accessExpiry     time.Duration
	refreshExpiry    time.Duration
	tokenService     token.Service
	tokenStrategy    token.Strategy
	issuer           string
	audience         string
}

func NewJWTService(
	accessSecret, refreshSecret string,
	accessExpiry, refreshExpiry time.Duration,
	tokenService token.Service,
	tokenStrategy token.Strategy,
	issuer, audience string,
) Service {
	return &jwtService{
		accessSecretKey:  []byte(accessSecret),
		refreshSecretKey: []byte(refreshSecret),
		accessExpiry:     accessExpiry,
		refreshExpiry:    refreshExpiry,
		tokenService:     tokenService,
		tokenStrategy:    tokenStrategy,
		issuer:           issuer,
		audience:         audience,
	}
}

func (s *jwtService) GenerateAccessToken(userID int) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(s.accessExpiry).Unix(),
			NotBefore: now.Unix(),
			Issuer:    s.issuer,
			Audience:  s.audience,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.accessSecretKey)
}

func (s *jwtService) GenerateRefreshToken(userID int) (string, error) {
	return s.tokenService.GenerateRefreshToken(userID, s.tokenStrategy)
}

func (s *jwtService) ValidateAccessToken(tokenString string) (int, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return s.accessSecretKey, nil
	})

	if err != nil {
		return 0, err
	}

	if !token.Valid {
		return 0, jwt.ErrSignatureInvalid
	}

	if err := claims.Valid(); err != nil {
		return 0, err
	}

	if !claims.VerifyIssuer(s.issuer, true) {
		return 0, jwt.NewValidationError("Invalid issuer", jwt.ValidationErrorIssuer)
	}

	if !claims.VerifyAudience(s.audience, true) {
		return 0, jwt.NewValidationError("Invalid audience", jwt.ValidationErrorAudience)
	}

	return claims.UserID, nil
}

func (s *jwtService) GetRefreshTokenExpiry() time.Duration {
	return s.refreshExpiry
}
