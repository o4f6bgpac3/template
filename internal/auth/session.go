package auth

import (
	"context"
	"github.com/google/uuid"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
)

func (s *Service) GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]db.UserSession, error) {
	return s.queries.GetActiveSessions(ctx, userID)
}

func (s *Service) InvalidateSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	// First, verify the session belongs to the user
	sessions, err := s.queries.GetActiveSessions(ctx, userID)
	if err != nil {
		return err
	}

	sessionExists := false
	for _, session := range sessions {
		if session.ID == sessionID {
			sessionExists = true
			break
		}
	}

	if !sessionExists {
		return ErrUserNotFound
	}

	return s.queries.InvalidateUserSession(ctx, sessionID.String())
}
