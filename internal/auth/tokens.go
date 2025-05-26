package auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	"net/http"
)

func (s *Service) RefreshTokens(ctx context.Context, r *http.Request, refreshToken string) (*Tokens, error) {
	tokenHash := s.hashToken(refreshToken)

	rt, err := s.queries.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserLoginFailed, nil, false, ErrTokenInvalid)
		return nil, ErrTokenInvalid
	}

	user, err := s.queries.GetUserById(ctx, rt.UserID)
	if err != nil {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserLoginFailed, &rt.UserID, false, ErrUserNotFound)
		return nil, ErrUserNotFound
	}

	if err := s.queries.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("revoke refresh token: %w", err)
	}

	tokens, err := s.generateTokens(ctx, user, string(rt.DeviceInfo))
	if err != nil {
		return nil, err
	}

	s.audit.LogEventFromRequest(ctx, r, audit.EventUserLogin, &user.ID, true, nil)
	return tokens, nil
}

func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.Config.Auth.JWTSecret), nil
	})

	if err != nil {
		return nil, ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenInvalid
}
