package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"github.com/o4f6bgpac3/template/internal/validation"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (s *Service) ChangePassword(ctx context.Context, r *http.Request, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.queries.GetUserById(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserPasswordChange, &userID, false, map[string]string{
			"reason": "invalid_old_password",
		}, ErrInvalidCredentials)
		return ErrInvalidCredentials
	}

	if err := validation.ValidatePassword(newPassword); err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserPasswordChange, &userID, false, map[string]string{
			"reason": "invalid_new_password",
		}, err)
		return err
	}

	if cfg.Config.Auth.PasswordHistoryLimit > 0 {
		if err := s.checkPasswordHistory(ctx, userID, newPassword); err != nil {
			s.audit.LogAuthEvent(ctx, r, audit.EventUserPasswordChange, &userID, false, map[string]string{
				"reason": "password_reused",
			}, err)
			return err
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), cfg.Config.Auth.BCryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		err := s.updateUser(ctx, tx, userID, func(ctx context.Context, user *db.User) error {
			user.PasswordHash = string(hash)
			return nil
		})
		if err != nil {
			return err
		}

		if cfg.Config.Auth.PasswordHistoryLimit > 0 {
			_, err = qtx.CreatePasswordHistory(ctx, db.CreatePasswordHistoryParams{
				UserID:       userID,
				PasswordHash: string(hash),
			})
			if err != nil {
				return fmt.Errorf("create password history: %w", err)
			}

			err = qtx.CleanupPasswordHistory(ctx, db.CleanupPasswordHistoryParams{
				UserID: userID,
				Limit:  int32(cfg.Config.Auth.PasswordHistoryLimit),
			})
			if err != nil {
				return fmt.Errorf("cleanup password history: %w", err)
			}
		}

		return qtx.RevokeAllUserRefreshTokens(ctx, userID)
	})

	if err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserPasswordChange, &userID, false, nil, err)
		return err
	}

	s.audit.LogAuthEvent(ctx, r, audit.EventUserPasswordChange, &userID, true, nil, nil)
	return nil
}

func (s *Service) CreatePasswordResetToken(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return ErrUserNotFound
	}

	token, err := s.generateSecureToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	tokenHash := s.hashToken(token)
	expiresAt := time.Now().Add(1 * time.Hour)

	err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		err := qtx.InvalidateUserPasswordResetTokens(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("invalidate existing tokens: %w", err)
		}

		_, err = qtx.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
			UserID:    user.ID,
			TokenHash: tokenHash,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return fmt.Errorf("create reset token: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

// CreatePasswordResetTokenConstantTime creates a password reset token with constant-time behavior
// to prevent email enumeration attacks. Always performs the same operations regardless of
// whether the email exists or not.
func (s *Service) CreatePasswordResetTokenConstantTime(ctx context.Context, email string) error {
	// Always generate a token to consume the same amount of time
	token, err := s.generateSecureToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	
	tokenHash := s.hashToken(token)
	expiresAt := time.Now().Add(1 * time.Hour)

	// Always look up the user
	user, err := s.queries.GetUserByEmail(ctx, email)
	userExists := err == nil

	if userExists {
		// User exists - create the actual reset token
		err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
			qtx := s.queries.WithTx(tx)

			err := qtx.InvalidateUserPasswordResetTokens(ctx, user.ID)
			if err != nil {
				return fmt.Errorf("invalidate existing tokens: %w", err)
			}

			_, err = qtx.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
				UserID:    user.ID,
				TokenHash: tokenHash,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				return fmt.Errorf("create reset token: %w", err)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		// TODO: Send reset email with token
	} else {
		// User doesn't exist - perform fake work to match timing
		// Simulate the database operations that would happen for a real user
		s.performFakePasswordResetWork(ctx, tokenHash, expiresAt)
		
		// TODO: Consider sending a fake email or no email to maintain timing
	}

	// Always return success to prevent email enumeration
	// The response should be identical regardless of email existence
	return nil
}

// performFakePasswordResetWork simulates the database work done for real password resets
// to maintain constant timing and prevent email enumeration via timing attacks
func (s *Service) performFakePasswordResetWork(ctx context.Context, tokenHash string, expiresAt time.Time) {
	// Simulate the work that would be done for a real user
	// This should take approximately the same time as the real operations
	
	// Simulate transaction work by doing equivalent database operations
	_ = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)
		
		// Simulate InvalidateUserPasswordResetTokens by doing a query that will take similar time
		// Use a nil UUID which will return "no rows found" but consume database time
		_, _ = qtx.GetUserById(ctx, uuid.Nil)
		
		// Simulate the CreatePasswordResetToken operation by doing another database query
		// This ensures we consume similar time to the real token creation process
		_, _ = qtx.GetUserById(ctx, uuid.Nil)
		
		return nil
	})
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	tokenHash := s.hashToken(token)

	resetToken, err := s.queries.GetPasswordResetToken(ctx, tokenHash)
	if err != nil {
		return ErrTokenInvalid
	}

	user, err := s.queries.GetUserById(ctx, resetToken.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	if cfg.Config.Auth.PasswordHistoryLimit > 0 {
		if err := s.checkPasswordHistory(ctx, user.ID, newPassword); err != nil {
			return err
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), cfg.Config.Auth.BCryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		err := qtx.UsePasswordResetToken(ctx, tokenHash)
		if err != nil {
			return fmt.Errorf("mark token as used: %w", err)
		}

		err = s.updateUser(ctx, tx, user.ID, func(ctx context.Context, user *db.User) error {
			user.PasswordHash = string(hash)
			return nil
		})
		if err != nil {
			return err
		}

		if cfg.Config.Auth.PasswordHistoryLimit > 0 {
			_, err = qtx.CreatePasswordHistory(ctx, db.CreatePasswordHistoryParams{
				UserID:       user.ID,
				PasswordHash: string(hash),
			})
			if err != nil {
				return fmt.Errorf("create password history: %w", err)
			}

			err = qtx.CleanupPasswordHistory(ctx, db.CleanupPasswordHistoryParams{
				UserID: user.ID,
				Limit:  int32(cfg.Config.Auth.PasswordHistoryLimit),
			})
			if err != nil {
				return fmt.Errorf("cleanup password history: %w", err)
			}
		}

		return qtx.RevokeAllUserRefreshTokens(ctx, user.ID)
	})

	return err
}

func (s *Service) checkPasswordHistory(ctx context.Context, userID uuid.UUID, newPassword string) error {
	history, err := s.queries.GetPasswordHistory(ctx, db.GetPasswordHistoryParams{
		UserID: userID,
		Limit:  int32(cfg.Config.Auth.PasswordHistoryLimit),
	})
	if err != nil {
		return nil
	}

	for _, oldHash := range history {
		if err := bcrypt.CompareHashAndPassword([]byte(oldHash.PasswordHash), []byte(newPassword)); err == nil {
			return ErrPasswordReused
		}
	}

	return nil
}

func (s *Service) generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
