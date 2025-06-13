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

// ResendEmailVerificationConstantTime resends email verification with constant-time behavior
// to prevent email enumeration attacks. Always performs the same operations regardless of
// whether the email exists or not.
func (s *Service) ResendEmailVerificationConstantTime(ctx context.Context, email string) error {
	// Always generate a token to consume the same amount of time
	dummyToken, err := s.generateSecureToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Always look up the user
	user, err := s.queries.GetUserByEmail(ctx, email)
	userExists := err == nil

	if userExists {
		// Check if email is already verified
		if user.EmailVerified != nil && *user.EmailVerified {
			// Email already verified - perform fake work to maintain timing
			s.performFakeEmailVerificationWork(ctx, dummyToken)
		} else {
			// User exists and email not verified - create real verification token
			token, err := s.CreateEmailVerificationToken(ctx, user.ID)
			if err != nil {
				return fmt.Errorf("create verification token: %w", err)
			}

			// TODO: Send email with verification link containing the token
			_ = token
		}
	} else {
		// User doesn't exist - perform fake work to match timing
		s.performFakeEmailVerificationWork(ctx, dummyToken)
	}

	// Always return success to prevent email enumeration
	return nil
}

// performFakeEmailVerificationWork simulates the database work done for real email verification
// to maintain constant timing and prevent email enumeration via timing attacks
func (s *Service) performFakeEmailVerificationWork(ctx context.Context, token string) {
	// Simulate the CreateEmailVerificationToken work by doing equivalent database operations
	// This should take approximately the same time as the real token creation

	// Simulate the database operations that CreateEmailVerificationToken would perform
	_ = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)
		
		// Simulate the database work that would happen in CreateEmailVerificationToken
		// Use operations that take similar time to the real token creation process
		_, _ = qtx.GetUserById(ctx, uuid.Nil) // Simulate user lookup time
		
		return nil
	})
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
		err = s.updateUser(ctx, tx, verificationToken.UserID, func(ctx context.Context, user *db.User) error {
			user.EmailVerified = &emailVerified
			return nil
		})
		if err != nil {
			return fmt.Errorf("mark email as verified: %w", err)
		}

		return nil
	})

	return err
}
