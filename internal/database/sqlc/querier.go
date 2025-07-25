// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Querier interface {
	AssignRoleToUser(ctx context.Context, arg AssignRoleToUserParams) error
	CheckUserPermission(ctx context.Context, arg CheckUserPermissionParams) (bool, error)
	CleanupExpiredRefreshTokens(ctx context.Context) error
	// Cleanup and utility queries
	CleanupExpiredTokens(ctx context.Context) error
	CleanupOldAuditLogs(ctx context.Context, createdAt pgtype.Timestamptz) error
	CleanupPasswordHistory(ctx context.Context, arg CleanupPasswordHistoryParams) error
	ClearFailedLogins(ctx context.Context, userID uuid.UUID) error
	// Audit log queries
	CreateAuditLog(ctx context.Context, arg CreateAuditLogParams) (AuditLog, error)
	// Email verification queries
	CreateEmailVerificationToken(ctx context.Context, arg CreateEmailVerificationTokenParams) (EmailVerificationToken, error)
	// Password history queries
	CreatePasswordHistory(ctx context.Context, arg CreatePasswordHistoryParams) (PasswordHistory, error)
	// Password reset queries
	CreatePasswordResetToken(ctx context.Context, arg CreatePasswordResetTokenParams) (PasswordResetToken, error)
	// Refresh token queries
	CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error)
	CreateRole(ctx context.Context, arg CreateRoleParams) (Role, error)
	// User management queries
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	// User session queries
	CreateUserSession(ctx context.Context, arg CreateUserSessionParams) (UserSession, error)
	DeactivateUser(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]UserSession, error)
	GetAuditLogs(ctx context.Context, arg GetAuditLogsParams) ([]AuditLog, error)
	GetEmailVerificationToken(ctx context.Context, tokenHash string) (EmailVerificationToken, error)
	GetFailedLoginCount(ctx context.Context, arg GetFailedLoginCountParams) (int64, error)
	GetPasswordHistory(ctx context.Context, arg GetPasswordHistoryParams) ([]PasswordHistory, error)
	GetPasswordResetToken(ctx context.Context, tokenHash string) (PasswordResetToken, error)
	GetPermissionsByRoleId(ctx context.Context, roleID uuid.UUID) ([]Permission, error)
	GetRecentFailedLogins(ctx context.Context, arg GetRecentFailedLoginsParams) ([]FailedLoginAttempt, error)
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	GetRoleByName(ctx context.Context, name string) (Role, error)
	GetSecurityStats(ctx context.Context) (GetSecurityStatsRow, error)
	GetUserAuditLogs(ctx context.Context, arg GetUserAuditLogsParams) ([]AuditLog, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserById(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error)
	// Role and permission queries
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error)
	GetUserSession(ctx context.Context, sessionID string) (UserSession, error)
	InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error
	InvalidateUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error
	InvalidateUserSession(ctx context.Context, sessionID string) error
	LockUserAccount(ctx context.Context, arg LockUserAccountParams) error
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error
	// Failed login attempt queries
	RecordFailedLogin(ctx context.Context, arg RecordFailedLoginParams) (FailedLoginAttempt, error)
	RemoveRoleFromUser(ctx context.Context, arg RemoveRoleFromUserParams) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	UnlockUserAccount(ctx context.Context, id uuid.UUID) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	UpdateSessionAccess(ctx context.Context, sessionID string) error
	UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error)
	UseEmailVerificationToken(ctx context.Context, tokenHash string) error
	UsePasswordResetToken(ctx context.Context, tokenHash string) error
}

var _ Querier = (*Queries)(nil)
