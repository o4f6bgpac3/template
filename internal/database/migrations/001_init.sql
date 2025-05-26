-- Create users table with security fields
create table users
(
    id             UUID primary key default gen_random_uuid(),
    email          VARCHAR(255) unique not null,
    username       VARCHAR(100) unique not null,
    password_hash  VARCHAR(255)        not null,
    is_active      BOOLEAN          default true,
    email_verified BOOLEAN          default false,
    locked_until   TIMESTAMPTZ,
    last_login_at  TIMESTAMPTZ,
    login_count    INTEGER          default 0,
    created_at     TIMESTAMPTZ      default current_timestamp,
    updated_at     TIMESTAMPTZ      default current_timestamp
);

-- Create roles table
create table roles
(
    id          UUID primary key default gen_random_uuid(),
    name        VARCHAR(50) unique not null,
    description TEXT,
    created_at  TIMESTAMPTZ      default current_timestamp
);

-- Create user_roles junction table
create table user_roles
(
    user_id    UUID not null references users (id) on delete cascade,
    role_id    UUID not null references roles (id) on delete cascade,
    granted_at TIMESTAMPTZ default current_timestamp,
    granted_by UUID not null references users (id),
    primary key (user_id, role_id)
);

-- Create permissions table
create table permissions
(
    id          UUID primary key default gen_random_uuid(),
    name        VARCHAR(100) unique not null,
    resource    VARCHAR(100)        not null,
    action      VARCHAR(50)         not null,
    description TEXT,
    created_at  TIMESTAMPTZ      default current_timestamp,
    unique (resource, action)
);

-- Create role_permissions junction table
create table role_permissions
(
    role_id       UUID not null references roles (id) on delete cascade,
    permission_id UUID not null references permissions (id) on delete cascade,
    granted_at    TIMESTAMPTZ default current_timestamp,
    primary key (role_id, permission_id)
);

-- Create refresh_tokens table for JWT refresh tokens
create table refresh_tokens
(
    id          UUID primary key default gen_random_uuid(),
    user_id     UUID                not null references users (id) on delete cascade,
    token_hash  VARCHAR(255) unique not null,
    expires_at  TIMESTAMPTZ         not null,
    created_at  TIMESTAMPTZ      default current_timestamp,
    revoked_at  TIMESTAMPTZ,
    device_info JSONB
);

-- Create failed login attempts table
create table failed_login_attempts
(
    id           UUID primary key default gen_random_uuid(),
    user_id      UUID not null references users (id) on delete cascade,
    ip_address   INET not null,
    user_agent   TEXT,
    attempted_at TIMESTAMPTZ      default current_timestamp
);

-- Create password history table
create table password_history
(
    id            UUID primary key default gen_random_uuid(),
    user_id       UUID         not null references users (id) on delete cascade,
    password_hash VARCHAR(255) not null,
    created_at    TIMESTAMPTZ      default current_timestamp
);

-- Create audit logs table
create table audit_logs
(
    id         UUID primary key default gen_random_uuid(),
    event_type VARCHAR(50) not null,
    user_id    UUID        not null references users (id) on delete cascade,
    ip_address INET,
    user_agent TEXT,
    resource   VARCHAR(100),
    action     VARCHAR(50),
    success    BOOLEAN     not null,
    error      TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ      default current_timestamp
);

-- Create email verification tokens table
create table email_verification_tokens
(
    id         UUID primary key default gen_random_uuid(),
    user_id    UUID                not null references users (id) on delete cascade,
    token_hash VARCHAR(255) unique not null,
    expires_at TIMESTAMPTZ         not null,
    created_at TIMESTAMPTZ      default current_timestamp,
    used_at    TIMESTAMPTZ
);

-- Create password reset tokens table
create table password_reset_tokens
(
    id         UUID primary key default gen_random_uuid(),
    user_id    UUID                not null references users (id) on delete cascade,
    token_hash VARCHAR(255) unique not null,
    expires_at TIMESTAMPTZ         not null,
    created_at TIMESTAMPTZ      default current_timestamp,
    used_at    TIMESTAMPTZ
);

-- Create user sessions table for tracking active sessions
create table user_sessions
(
    id               UUID primary key default gen_random_uuid(),
    user_id          UUID                not null references users (id) on delete cascade,
    session_id       VARCHAR(255) unique not null,
    ip_address       INET,
    user_agent       TEXT,
    created_at       TIMESTAMPTZ      default current_timestamp,
    last_accessed_at TIMESTAMPTZ      default current_timestamp,
    expires_at       TIMESTAMPTZ         not null
);

-- Create indexes for performance
create index idx_users_email on users (email);
create index idx_users_username on users (username);
create index idx_users_locked_until on users (locked_until);
create index idx_refresh_tokens_user_id on refresh_tokens (user_id);
create index idx_refresh_tokens_expires_at on refresh_tokens (expires_at);
create index idx_user_roles_user_id on user_roles (user_id);
create index idx_user_roles_role_id on user_roles (role_id);
create index idx_role_permissions_role_id on role_permissions (role_id);

create index idx_failed_login_user_time on failed_login_attempts (user_id, attempted_at);
create index idx_failed_login_ip on failed_login_attempts (ip_address, attempted_at);

create index idx_password_history_user on password_history (user_id, created_at desc);

create index idx_audit_logs_user_id on audit_logs (user_id);
create index idx_audit_logs_event_type on audit_logs (event_type);
create index idx_audit_logs_created_at on audit_logs (created_at);
create index idx_audit_logs_success on audit_logs (success);

create index idx_email_verification_expires on email_verification_tokens (expires_at);
create index idx_password_reset_expires on password_reset_tokens (expires_at);

create index idx_user_sessions_user on user_sessions (user_id);
create index idx_user_sessions_expires on user_sessions (expires_at);
create index idx_user_sessions_last_accessed on user_sessions (last_accessed_at);

-- Create update trigger for updated_at
create or replace function trigger_set_timestamp()
    returns TRIGGER as
$$
begin
    NEW.updated_at = current_timestamp;
    return NEW;
end;
$$ language plpgsql;

create trigger set_timestamp
    before update
    on users
    for each row
execute function trigger_set_timestamp();

-- Add cleanup function for expired tokens and sessions
create or replace function cleanup_expired_data()
    returns void as
$$
begin
    -- Clean up expired email verification tokens
    delete
    from email_verification_tokens
    where expires_at < current_timestamp;

    -- Clean up expired password reset tokens
    delete
    from password_reset_tokens
    where expires_at < current_timestamp;

    -- Clean up expired user sessions
    delete
    from user_sessions
    where expires_at < current_timestamp;

    -- Clean up old failed login attempts (older than 30 days)
    delete
    from failed_login_attempts
    where attempted_at < current_timestamp - interval '30 days';

    -- Clean up old audit logs (older than 1 year)
    delete
    from audit_logs
    where created_at < current_timestamp - interval '1 year';
end;
$$ language plpgsql;

-- Insert default roles
insert into roles (name, description)
values ('admin', 'Full system access'),
       ('user', 'Standard user access'),
       ('moderator', 'Content moderation access');

---- create above / drop below ----

-- Drop cleanup function
drop function if exists cleanup_expired_data();

-- Drop triggers
drop trigger if exists set_timestamp on users;
drop function if exists trigger_set_timestamp();

-- Drop indexes
drop index if exists idx_user_sessions_last_accessed;
drop index if exists idx_user_sessions_expires;
drop index if exists idx_user_sessions_user;
drop index if exists idx_password_reset_expires;
drop index if exists idx_email_verification_expires;
drop index if exists idx_audit_logs_success;
drop index if exists idx_audit_logs_created_at;
drop index if exists idx_audit_logs_event_type;
drop index if exists idx_audit_logs_user_id;
drop index if exists idx_password_history_user;
drop index if exists idx_failed_login_ip;
drop index if exists idx_failed_login_user_time;
drop index if exists idx_role_permissions_role_id;
drop index if exists idx_user_roles_role_id;
drop index if exists idx_user_roles_user_id;
drop index if exists idx_refresh_tokens_expires_at;
drop index if exists idx_refresh_tokens_user_id;
drop index if exists idx_users_locked_until;
drop index if exists idx_users_username;
drop index if exists idx_users_email;

-- Drop tables
drop table if exists user_sessions;
drop table if exists password_reset_tokens;
drop table if exists email_verification_tokens;
drop table if exists audit_logs;
drop table if exists password_history;
drop table if exists failed_login_attempts;
drop table if exists refresh_tokens;
drop table if exists role_permissions;
drop table if exists permissions;
drop table if exists user_roles;
drop table if exists roles;
drop table if exists users;