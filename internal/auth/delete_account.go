package auth

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/o4f6bgpac3/template/internal/audit"
	"github.com/o4f6bgpac3/template/internal/validation"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func (s *Service) DeleteAccount(ctx context.Context, r *http.Request, userID uuid.UUID, password string) error {
	validationErrs := &validation.ValidationErrors{}

	if err := validation.ValidatePassword(password); err != nil {
		validationErrs.Add("password", "Password is required")
	}

	if validationErrs.HasErrors() {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserDelete, &userID, false, validationErrs)
		return validationErrs
	}

	err := s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		user, err := qtx.GetUserById(ctx, userID)
		if err != nil {
			return fmt.Errorf("get user: %w", err)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			return ErrInvalidCredentials
		}

		err = qtx.DeactivateUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("delete user: %w", err)
		}

		err = qtx.RevokeAllUserRefreshTokens(ctx, userID)
		if err != nil {
			return fmt.Errorf("revoke refresh tokens: %w", err)
		}

		err = qtx.InvalidateAllUserSessions(ctx, userID)
		if err != nil {
			return fmt.Errorf("invalidate sessions: %w", err)
		}

		err = qtx.InvalidateUserPasswordResetTokens(ctx, userID)
		if err != nil {
			return fmt.Errorf("invalidate password reset tokens: %w", err)
		}

		err = qtx.DeleteUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("delete user: %w", err)
		}

		return nil
	})

	if err != nil {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserDelete, &userID, false, err)
		return err
	}

	s.audit.LogEventFromRequest(ctx, r, audit.EventUserDelete, &userID, true, nil)
	return nil
}
