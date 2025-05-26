package auth

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"github.com/o4f6bgpac3/template/internal/utils"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (s *Service) Login(ctx context.Context, r *http.Request, emailOrUsername, password, deviceInfo string) (*Tokens, error) {
	user, err := s.getUserByEmailOrUsername(ctx, emailOrUsername)
	if err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserLoginFailed, nil, false, map[string]string{
			"email_or_username": emailOrUsername,
			"reason":            "user_not_found",
		}, ErrInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	if err := s.checkAccountLocked(ctx, user.ID); err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserLoginFailed, &user.ID, false, map[string]string{
			"reason": "account_locked",
		}, err)
		return nil, err
	}

	if cfg.Config.Auth.RequireEmailVerification && (user.EmailVerified == nil || !*user.EmailVerified) {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserLoginFailed, &user.ID, false, map[string]string{
			"reason": "email_not_verified",
		}, ErrEmailNotVerified)
		return nil, ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		s.recordFailedLogin(ctx, user.ID, r)
		s.audit.LogAuthEvent(ctx, r, audit.EventUserLoginFailed, &user.ID, false, map[string]string{
			"reason": "invalid_password",
		}, ErrInvalidCredentials)
		return nil, ErrInvalidCredentials
	}

	s.clearFailedLogins(ctx, user.ID)

	tokens, err := s.generateTokens(ctx, user, deviceInfo)
	if err != nil {
		s.audit.LogAuthEvent(ctx, r, audit.EventUserLoginFailed, &user.ID, false, map[string]string{
			"reason": "token_generation_failed",
		}, err)
		return nil, err
	}

	s.audit.LogAuthEvent(ctx, r, audit.EventUserLogin, &user.ID, true, map[string]string{
		"device_info": deviceInfo,
	}, nil)

	return tokens, nil
}

func (s *Service) checkAccountLocked(ctx context.Context, userID uuid.UUID) error {
	user, err := s.queries.GetUserById(ctx, userID)
	if err != nil {
		return err
	}

	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return ErrAccountLocked
	}

	if user.LockedUntil.Valid && user.LockedUntil.Time.Before(time.Now()) {
		err := s.queries.UnlockUserAccount(ctx, userID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) clearFailedLogins(ctx context.Context, userID uuid.UUID) {
	err := s.queries.ClearFailedLogins(ctx, userID)
	if err != nil {
		return
	}
	err = s.queries.UnlockUserAccount(ctx, userID)
	if err != nil {
		return
	}
}

func (s *Service) getUserByEmailOrUsername(ctx context.Context, emailOrUsername string) (db.User, error) {
	user, err := s.queries.GetUserByEmail(ctx, emailOrUsername)
	if err != nil {
		user, err = s.queries.GetUserByUsername(ctx, emailOrUsername)
		if err != nil {
			return db.User{}, ErrUserNotFound
		}
	}
	return user, nil
}

func (s *Service) recordFailedLogin(ctx context.Context, userID uuid.UUID, r *http.Request) {
	clientIp := utils.GetClientIp(r)
	userAgent := r.UserAgent()

	_, err := s.queries.RecordFailedLogin(ctx, db.RecordFailedLoginParams{
		UserID:    userID,
		IpAddress: clientIp,
		UserAgent: &userAgent,
	})
	if err != nil {
		return
	}

	lockoutDuration := cfg.Config.Auth.LockoutDuration
	attemptedAtPg := pgtype.Timestamptz{
		Time: time.Now().Add(-lockoutDuration),
	}

	count, err := s.queries.GetFailedLoginCount(ctx, db.GetFailedLoginCountParams{
		UserID:      userID,
		AttemptedAt: attemptedAtPg,
	})
	if err != nil {
		return
	}

	if count >= int64(cfg.Config.Auth.MaxLoginAttempts) {
		lockUntil := pgtype.Timestamptz{
			Time:  time.Now().Add(cfg.Config.Auth.LockoutDuration),
			Valid: true,
		}
		err := s.queries.LockUserAccount(ctx, db.LockUserAccountParams{
			ID:          userID,
			LockedUntil: lockUntil,
		})
		if err != nil {
			return
		}
		s.audit.LogEventFromRequest(context.Background(), r, audit.EventUserAccountLocked, &userID, true, nil)
	}
}
