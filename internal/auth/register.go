package auth

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"github.com/o4f6bgpac3/template/internal/validation"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func (s *Service) Register(ctx context.Context, r *http.Request, email, username, password, reqRole string) (*db.User, error) {
	if !cfg.Config.Auth.AllowSelfRegistration {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserRegister, nil, false, ErrRegistrationDisabled)
		return nil, ErrRegistrationDisabled
	}

	validationErrs := &validation.ValidationErrors{}

	email = validation.SanitizeInput(email)
	username = validation.SanitizeInput(username)

	if err := validation.ValidateEmail(email); err != nil {
		validationErrs.Add("email", err.Error())
	}

	if err := validation.ValidateUsername(username); err != nil {
		validationErrs.Add("username", err.Error())
	}

	if err := validation.ValidatePassword(password); err != nil {
		validationErrs.Add("password", err.Error())
	}

	if validationErrs.HasErrors() {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserRegister, nil, false, validationErrs)
		return nil, validationErrs
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Config.Auth.BCryptCost)
	if err != nil {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserRegister, nil, false, err)
		return nil, fmt.Errorf("hash password: %w", err)
	}

	var user db.User
	err = s.db.Transaction(ctx, func(tx pgx.Tx) error {
		qtx := s.queries.WithTx(tx)

		user, err = qtx.CreateUser(ctx, db.CreateUserParams{
			Email:        email,
			Username:     username,
			PasswordHash: string(hash),
		})
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		if cfg.Config.Auth.PasswordHistoryLimit > 0 {
			_, err = qtx.CreatePasswordHistory(ctx, db.CreatePasswordHistoryParams{
				UserID:       user.ID,
				PasswordHash: string(hash),
			})
			if err != nil {
				return fmt.Errorf("create password history: %w", err)
			}
		}

		var r string
		if reqRole == "" {
			r = cfg.Config.Auth.DefaultRole
		} else {
			r = reqRole
		}

		role, err := qtx.GetRoleByName(ctx, r)
		if err != nil {
			return fmt.Errorf("get role %s: %w", r, err)
		}

		err = qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
			UserID:    user.ID,
			RoleID:    role.ID,
			GrantedBy: user.ID,
		})
		if err != nil {
			return fmt.Errorf("assign default role: %w", err)
		}

		return nil
	})

	if err != nil {
		s.audit.LogEventFromRequest(ctx, r, audit.EventUserRegister, nil, false, err)
		return nil, err
	}

	s.audit.LogEventFromRequest(ctx, r, audit.EventUserRegister, &user.ID, true, nil)
	return &user, nil
}
