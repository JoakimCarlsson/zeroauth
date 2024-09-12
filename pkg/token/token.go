package token

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Strategy int

const (
	StrategyGUID Strategy = iota
	StrategyRandom
	StrategyComposite
)

type Service interface {
	GenerateRefreshToken(userID int, strategy Strategy) (string, error)
	ParseCompositeToken(token string) (int, time.Time, error)
}

type tokenService struct {
	refreshTokenLength int
}

func NewTokenService(refreshTokenLength int) Service {
	return &tokenService{refreshTokenLength: refreshTokenLength}
}

func (s *tokenService) GenerateRefreshToken(userID int, strategy Strategy) (string, error) {
	switch strategy {
	case StrategyGUID:
		return uuid.NewString(), nil
	case StrategyRandom:
		return s.generateRandomToken()
	case StrategyComposite:
		return s.generateCompositeToken(userID)
	default:
		return "", fmt.Errorf("unknown token strategy")
	}
}

func (s *tokenService) generateRandomToken() (string, error) {
	b := make([]byte, s.refreshTokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *tokenService) generateCompositeToken(userID int) (string, error) {
	timestamp := time.Now().Unix()
	randomPart, err := s.generateRandomToken()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%s", userID, timestamp, randomPart), nil
}

func (s *tokenService) ParseCompositeToken(token string) (int, time.Time, error) {
	var userID int
	var timestamp int64
	var randomPart string
	_, err := fmt.Sscanf(token, "%d:%d:%s", &userID, &timestamp, &randomPart)
	if err != nil {
		return 0, time.Time{}, err
	}
	return userID, time.Unix(timestamp, 0), nil
}
