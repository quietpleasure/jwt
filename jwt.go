package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrAccessTokenExpired error = jwt.ErrTokenExpired

type Token struct {
	Access  string
	Refresh string
}

type SignableDetails struct {
	jwt.RegisteredClaims
	AccountData any
}

type (
	RegisteredClaims = jwt.RegisteredClaims
	ClaimStrings     = jwt.ClaimStrings
)

func IssueTokens(accessKey []byte, claims *SignableDetails, accessExpiresAt, refreshExpiresAt time.Duration) (*Token, error) {
	tn := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(tn)
	claims.ExpiresAt = jwt.NewNumericDate(tn.Add(accessExpiresAt))
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(accessKey)
	if err != nil {
		return nil, err
	}
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(tn.Add(refreshExpiresAt))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(accessKey)
	if err != nil {
		return nil, err
	}
	return &Token{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func CheckToken(accessKey []byte, token string) (*SignableDetails, error) {
	claims := new(SignableDetails)
	if _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessKey), nil
	}); err != nil && errors.Is(err, jwt.ErrTokenExpired) {
		return claims, ErrAccessTokenExpired
	} else if err != nil {
		return nil, err
	}
	return claims, nil
}
