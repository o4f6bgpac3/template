-- User management queries

-- name: CreateUser :one
INSERT INTO users (
    email,
    username,
    password_hash
) VALUES (
             $1, $2, $3
         ) RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 AND is_active = true
LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1 AND is_active = true
LIMIT 1;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1 AND is_active = true
LIMIT 1;

-- name: UpdateUser :one
UPDATE users
SET
    email = COALESCE($2, email),
    username = COALESCE($3, username),
    password_hash = COALESCE($4, password_hash),
    is_active = COALESCE($5, is_active),
    email_verified = COALESCE($6, email_verified),
    locked_until = COALESCE($7, locked_until),
    last_login_at = COALESCE($8, last_login_at),
    login_count = COALESCE($9, login_count)
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
UPDATE users
SET is_active = false
WHERE id = $1;

-- name: LockUserAccount :exec
UPDATE users
SET locked_until = $2
WHERE id = $1;

-- name: UnlockUserAccount :exec
UPDATE users
SET locked_until = NULL
WHERE id = $1;

-- name: UpdateLastLogin :exec
UPDATE users
SET
    last_login_at = CURRENT_TIMESTAMP,
    login_count = login_count + 1
WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users
SET email_verified = true
WHERE id = $1;

-- Role and permission queries

-- name: GetUserRoles :many
SELECT r.* FROM roles r
                    INNER JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1;

-- name: GetUserPermissions :many
SELECT DISTINCT p.* FROM permissions p
                             INNER JOIN role_permissions rp ON rp.permission_id = p.id
                             INNER JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id, granted_by)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RemoveRoleFromUser :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: GetRoleByName :one
SELECT * FROM roles
WHERE name = $1
LIMIT 1;

-- name: CreateRole :one
INSERT INTO roles (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: GetPermissionsByRoleId :many
SELECT p.* FROM permissions p
                    INNER JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1;

-- name: CheckUserPermission :one
SELECT EXISTS (
    SELECT 1 FROM permissions p
                      INNER JOIN role_permissions rp ON rp.permission_id = p.id
                      INNER JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.user_id = $1
      AND p.resource = $2
      AND p.action = $3
) AS has_permission;

-- Refresh token queries

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id,
    token_hash,
    expires_at,
    device_info
) VALUES (
             $1, $2, $3, $4
         ) RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1
  AND expires_at > CURRENT_TIMESTAMP
  AND revoked_at IS NULL
LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP
WHERE token_hash = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CleanupExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < CURRENT_TIMESTAMP
   OR revoked_at < CURRENT_TIMESTAMP - INTERVAL '30 days';

-- Failed login attempt queries

-- name: RecordFailedLogin :one
INSERT INTO failed_login_attempts (
    user_id,
    ip_address,
    user_agent
) VALUES (
             $1, $2, $3
         ) RETURNING *;

-- name: GetFailedLoginCount :one
SELECT COUNT(*) FROM failed_login_attempts
WHERE user_id = $1 AND attempted_at > $2;

-- name: ClearFailedLogins :exec
DELETE FROM failed_login_attempts
WHERE user_id = $1;

-- name: GetRecentFailedLogins :many
SELECT * FROM failed_login_attempts
WHERE user_id = $1 AND attempted_at > $2
ORDER BY attempted_at DESC;

-- Password history queries

-- name: CreatePasswordHistory :one
INSERT INTO password_history (
    user_id,
    password_hash
) VALUES (
             $1, $2
         ) RETURNING *;

-- name: GetPasswordHistory :many
SELECT * FROM password_history
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: CleanupPasswordHistory :exec
DELETE FROM password_history
WHERE password_history.user_id = $1
  AND password_history.id NOT IN (
    SELECT ph.id FROM password_history ph
    WHERE ph.user_id = $1
    ORDER BY ph.created_at DESC
    LIMIT $2
);

-- Audit log queries

-- name: CreateAuditLog :one
INSERT INTO audit_logs (
    event_type,
    user_id,
    ip_address,
    user_agent,
    resource,
    action,
    success,
    error,
    metadata,
    created_at
) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
         ) RETURNING *;

-- name: GetAuditLogs :many
SELECT * FROM audit_logs
WHERE ($1::uuid IS NULL OR user_id = $1)
  AND ($2::text IS NULL OR event_type = $2)
  AND ($3::timestamptz IS NULL OR created_at >= $3)
  AND ($4::timestamptz IS NULL OR created_at <= $4)
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: GetUserAuditLogs :many
SELECT * FROM audit_logs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- Email verification queries

-- name: CreateEmailVerificationToken :one
INSERT INTO email_verification_tokens (
    user_id,
    token_hash,
    expires_at
) VALUES (
             $1, $2, $3
         ) RETURNING *;

-- name: GetEmailVerificationToken :one
SELECT * FROM email_verification_tokens
WHERE token_hash = $1
  AND expires_at > CURRENT_TIMESTAMP
  AND used_at IS NULL
LIMIT 1;

-- name: UseEmailVerificationToken :exec
UPDATE email_verification_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE token_hash = $1;

-- Password reset queries

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (
    user_id,
    token_hash,
    expires_at
) VALUES (
             $1, $2, $3
         ) RETURNING *;

-- name: GetPasswordResetToken :one
SELECT * FROM password_reset_tokens
WHERE token_hash = $1
  AND expires_at > CURRENT_TIMESTAMP
  AND used_at IS NULL
LIMIT 1;

-- name: UsePasswordResetToken :exec
UPDATE password_reset_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE token_hash = $1;

-- name: InvalidateUserPasswordResetTokens :exec
UPDATE password_reset_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND used_at IS NULL;

-- User session queries

-- name: CreateUserSession :one
INSERT INTO user_sessions (
    user_id,
    session_id,
    ip_address,
    user_agent,
    expires_at
) VALUES (
             $1, $2, $3, $4, $5
         ) RETURNING *;

-- name: GetUserSession :one
SELECT * FROM user_sessions
WHERE session_id = $1
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1;

-- name: UpdateSessionAccess :exec
UPDATE user_sessions
SET last_accessed_at = CURRENT_TIMESTAMP
WHERE session_id = $1;

-- name: InvalidateUserSession :exec
DELETE FROM user_sessions
WHERE session_id = $1;

-- name: InvalidateAllUserSessions :exec
DELETE FROM user_sessions
WHERE user_id = $1;

-- name: GetActiveSessions :many
SELECT * FROM user_sessions
WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP
ORDER BY last_accessed_at DESC;

-- Cleanup and utility queries

-- name: CleanupExpiredTokens :exec
SELECT cleanup_expired_data();

-- name: CleanupOldAuditLogs :exec
DELETE FROM audit_logs
WHERE created_at < $1;

-- name: GetSecurityStats :one
SELECT
    (SELECT COUNT(*) FROM users WHERE is_active = true) as active_users,
    (SELECT COUNT(*) FROM users WHERE locked_until > CURRENT_TIMESTAMP) as locked_users,
    (SELECT COUNT(*) FROM failed_login_attempts WHERE attempted_at > CURRENT_TIMESTAMP - INTERVAL '24 hours') as failed_logins_24h,
    (SELECT COUNT(*) FROM audit_logs WHERE success = false AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours') as security_events_24h,
    (SELECT COUNT(*) FROM user_sessions WHERE expires_at > CURRENT_TIMESTAMP) as active_sessions;