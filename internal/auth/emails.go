package auth

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"time"
)

func (s *Service) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := s.generateSecureToken()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	tokenHash := s.hashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = s.queries.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("create verification token: %w", err)
	}

	return token, nil
}

func (s *Service) ResendEmailVerification(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return ErrUserNotFound
	}

	if user.EmailVerified != nil && *user.EmailVerified {
		return fmt.Errorf("email already verified")
	}

	token, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		return err
	}

	// TODO: Send email with verification link containing the token
	_ = token
	return nil
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	tokenHash := s.hashToken(token)

	verificationToken, err := s.queries.GetEmailVerificationToken(ctx, tokenHash)
	if err != nil {
		return ErrTokenInvalid
	}

	err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		err := qtx.UseEmailVerificationToken(ctx, tokenHash)
		if err != nil {
			return fmt.Errorf("mark token as used: %w", err)
		}

		emailVerified := true
		_, err = qtx.UpdateUser(ctx, db.UpdateUserParams{
			ID:            verificationToken.UserID,
			EmailVerified: &emailVerified,
		})
		if err != nil {
			return fmt.Errorf("mark email as verified: %w", err)
		}

		return nil
	})

	return err
}
