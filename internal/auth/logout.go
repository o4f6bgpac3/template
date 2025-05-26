package auth

import (
	"context"
	"github.com/google/uuid"
	"github.com/o4f6bgpac3/template/internal/audit"
	"net/http"
)

func (s *Service) Logout(ctx context.Context, r *http.Request, refreshToken string) error {
	tokenHash := s.hashToken(refreshToken)

	rt, err := s.queries.GetRefreshToken(ctx, tokenHash)
	var userID *uuid.UUID
	if err == nil {
		userID = &rt.UserID
	}

	err = s.queries.RevokeRefreshToken(ctx, tokenHash)
	s.audit.LogEventFromRequest(ctx, r, audit.EventUserLogout, userID, err == nil, err)
	return err
}

func (s *Service) LogoutAllDevices(ctx context.Context, r *http.Request, userID uuid.UUID) error {
	err := s.queries.RevokeAllUserRefreshTokens(ctx, userID)
	s.audit.LogEventFromRequest(ctx, r, audit.EventUserLogout, &userID, err == nil, err)
	return err
}
