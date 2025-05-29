package auth

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
)

func (s *Service) updateUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID, fn func(ctx context.Context, user *db.User) error) error {
	qtx := s.queries.WithTx(tx)

	user, err := qtx.GetUserById(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if err := fn(ctx, &user); err != nil {
		return err
	}

	_, err = qtx.UpdateUser(ctx, db.UpdateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		PasswordHash:  user.PasswordHash,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
		LockedUntil:   user.LockedUntil,
		LastLoginAt:   user.LastLoginAt,
		LoginCount:    user.LoginCount,
	})
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}
