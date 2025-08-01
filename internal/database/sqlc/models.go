// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package db

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuditLog struct {
	ID        uuid.UUID          `json:"id"`
	EventType string             `json:"event_type"`
	UserID    uuid.UUID          `json:"user_id"`
	IpAddress *netip.Addr        `json:"ip_address"`
	UserAgent *string            `json:"user_agent"`
	Resource  *string            `json:"resource"`
	Action    *string            `json:"action"`
	Success   bool               `json:"success"`
	Error     *string            `json:"error"`
	Metadata  []byte             `json:"metadata"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
}

type EmailVerificationToken struct {
	ID        uuid.UUID          `json:"id"`
	UserID    uuid.UUID          `json:"user_id"`
	TokenHash string             `json:"token_hash"`
	ExpiresAt time.Time          `json:"expires_at"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UsedAt    pgtype.Timestamptz `json:"used_at"`
}

type FailedLoginAttempt struct {
	ID          uuid.UUID          `json:"id"`
	UserID      uuid.UUID          `json:"user_id"`
	IpAddress   netip.Addr         `json:"ip_address"`
	UserAgent   *string            `json:"user_agent"`
	AttemptedAt pgtype.Timestamptz `json:"attempted_at"`
}

type PasswordHistory struct {
	ID           uuid.UUID          `json:"id"`
	UserID       uuid.UUID          `json:"user_id"`
	PasswordHash string             `json:"password_hash"`
	CreatedAt    pgtype.Timestamptz `json:"created_at"`
}

type PasswordResetToken struct {
	ID        uuid.UUID          `json:"id"`
	UserID    uuid.UUID          `json:"user_id"`
	TokenHash string             `json:"token_hash"`
	ExpiresAt time.Time          `json:"expires_at"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UsedAt    pgtype.Timestamptz `json:"used_at"`
}

type Permission struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Resource    string             `json:"resource"`
	Action      string             `json:"action"`
	Description *string            `json:"description"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
}

type RefreshToken struct {
	ID         uuid.UUID          `json:"id"`
	UserID     uuid.UUID          `json:"user_id"`
	TokenHash  string             `json:"token_hash"`
	ExpiresAt  time.Time          `json:"expires_at"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	RevokedAt  pgtype.Timestamptz `json:"revoked_at"`
	DeviceInfo []byte             `json:"device_info"`
}

type Role struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Description *string            `json:"description"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
}

type RolePermission struct {
	RoleID       uuid.UUID          `json:"role_id"`
	PermissionID uuid.UUID          `json:"permission_id"`
	GrantedAt    pgtype.Timestamptz `json:"granted_at"`
}

type User struct {
	ID            uuid.UUID          `json:"id"`
	Email         string             `json:"email"`
	Username      string             `json:"username"`
	PasswordHash  string             `json:"password_hash"`
	IsActive      *bool              `json:"is_active"`
	EmailVerified *bool              `json:"email_verified"`
	LockedUntil   pgtype.Timestamptz `json:"locked_until"`
	LastLoginAt   pgtype.Timestamptz `json:"last_login_at"`
	LoginCount    *int32             `json:"login_count"`
	CreatedAt     pgtype.Timestamptz `json:"created_at"`
	UpdatedAt     pgtype.Timestamptz `json:"updated_at"`
}

type UserRole struct {
	UserID    uuid.UUID          `json:"user_id"`
	RoleID    uuid.UUID          `json:"role_id"`
	GrantedAt pgtype.Timestamptz `json:"granted_at"`
	GrantedBy uuid.UUID          `json:"granted_by"`
}

type UserSession struct {
	ID             uuid.UUID          `json:"id"`
	UserID         uuid.UUID          `json:"user_id"`
	SessionID      string             `json:"session_id"`
	IpAddress      *netip.Addr        `json:"ip_address"`
	UserAgent      *string            `json:"user_agent"`
	CreatedAt      pgtype.Timestamptz `json:"created_at"`
	LastAccessedAt pgtype.Timestamptz `json:"last_accessed_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
}
