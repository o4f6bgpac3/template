package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	"github.com/o4f6bgpac3/template/internal/database"
	"github.com/o4f6bgpac3/template/internal/database/sqlc"
)

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrTokenInvalid         = errors.New("token invalid")
	ErrUserNotFound         = errors.New("user not found")
	ErrAccountLocked        = errors.New("account locked due to failed login attempts")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrRegistrationDisabled = errors.New("self-registration is disabled")
	ErrPasswordReused       = errors.New("password was recently used")
	ErrWeakJWTSecret        = errors.New("JWT secret is too weak")
)

type Service struct {
	db      *database.DB
	queries *db.Queries
	audit   *audit.Service
}

type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Roles    []string  `json:"roles"`
	jwt.RegisteredClaims
}

type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func NewService(db *database.DB, queries *db.Queries, auditService *audit.Service) (*Service, error) {
	// Validate JWT secret strength
	if err := validateJWTSecret(cfg.Config.Auth.JWTSecret); err != nil {
		return nil, fmt.Errorf("JWT secret validation failed: %w", err)
	}

	return &Service{
		db:      db,
		queries: queries,
		audit:   auditService,
	}, nil
}

func (s *Service) CheckPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	result, err := s.queries.CheckUserPermission(ctx, db.CheckUserPermissionParams{
		UserID:   userID,
		Resource: resource,
		Action:   action,
	})
	if err != nil {
		return false, fmt.Errorf("check permission: %w", err)
	}

	return result, nil
}

func (s *Service) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType string, from, to *time.Time, limit, offset int) ([]db.AuditLog, error) {
	var userIDParam uuid.UUID
	var eventTypeParam string
	var fromParam, toParam time.Time

	if userID != nil {
		userIDParam = *userID
	}

	if eventType != "" {
		eventTypeParam = eventType
	}

	epochTime := time.Unix(0, 0)
	if from != nil {
		fromParam = *from
	} else {
		fromParam = epochTime
	}

	if to != nil {
		toParam = *to
	} else {
		toParam = epochTime
	}

	return s.queries.GetAuditLogs(ctx, db.GetAuditLogsParams{
		Column1: userIDParam,
		Column2: eventTypeParam,
		Column3: fromParam,
		Column4: toParam,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
}

func (s *Service) GetSecurityStats(ctx context.Context) (db.GetSecurityStatsRow, error) {
	return s.queries.GetSecurityStats(ctx)
}

func (s *Service) generateTokens(ctx context.Context, user db.User, deviceInfo string) (*Tokens, error) {
	roles, err := s.queries.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	now := time.Now()
	accessClaims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    roleNames,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.Config.Auth.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "template-app",
			Subject:   user.ID.String(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(cfg.Config.Auth.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	deviceInfoJSON, err := json.Marshal(deviceInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal device info: %w", err)
	}

	refreshTokenHash := s.hashToken(refreshToken)
	_, err = s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:     user.ID,
		TokenHash:  refreshTokenHash,
		ExpiresAt:  now.Add(cfg.Config.Auth.RefreshTokenTTL),
		DeviceInfo: deviceInfoJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &Tokens{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
		ExpiresAt:    accessClaims.ExpiresAt.Time,
	}, nil
}

func (s *Service) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *Service) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// validateJWTSecret validates that the JWT secret meets security requirements
func validateJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("%w: JWT secret is empty", ErrWeakJWTSecret)
	}

	if len(secret) < 32 {
		return fmt.Errorf("%w: JWT secret must be at least 32 characters long (current: %d)", ErrWeakJWTSecret, len(secret))
	}

	// Check for common weak secrets
	weakSecrets := []string{
		"secret",
		"jwt-secret",
		"your-secret-key",
		"change-me",
		"default",
		"password",
		"123456",
		"abcdef",
	}

	for _, weak := range weakSecrets {
		if secret == weak {
			return fmt.Errorf("%w: JWT secret cannot be a common weak value", ErrWeakJWTSecret)
		}
	}

	return nil
}
