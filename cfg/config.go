package cfg

import (
	"fmt"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

var Config = &Configuration{}

type Configuration struct {
	Auth     AuthConfiguration     `mapstructure:"auth"`
	Database DatabaseConfiguration `mapstructure:"database"`
	Env      uint                  `mapstructure:"env"`
	HTTP     HTTPConfiguration     `mapstructure:"http"`
	Security SecurityConfiguration `mapstructure:"security"`
}

type AuthConfiguration struct {
	AccessTokenTTL           time.Duration `mapstructure:"access_token_ttl"`
	AllowSelfRegistration    bool          `mapstructure:"allow_self_registration"`
	BCryptCost               int           `mapstructure:"bcrypt_cost"`
	DefaultRole              string        `mapstructure:"default_role"`
	EnableMFA                bool          `mapstructure:"enable_mfa"`
	JWTSecret                string        `mapstructure:"jwt_secret"`
	LockoutDuration          time.Duration `mapstructure:"lockout_duration"`
	MaxLoginAttempts         int           `mapstructure:"max_login_attempts"`
	PasswordHistoryLimit     int           `mapstructure:"password_history_limit"`
	PasswordMinLength        int           `mapstructure:"password_min_length"`
	PasswordRequireLower     bool          `mapstructure:"password_require_lower"`
	PasswordRequireNumber    bool          `mapstructure:"password_require_number"`
	PasswordRequireSpecial   bool          `mapstructure:"password_require_special"`
	PasswordRequireUpper     bool          `mapstructure:"password_require_upper"`
	RefreshTokenTTL          time.Duration `mapstructure:"refresh_token_ttl"`
	RequireEmailVerification bool          `mapstructure:"require_email_verification"`
}

type DatabaseConfiguration struct {
	MaxConnections  int32         `mapstructure:"max_connections"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
	MinConnections  int32         `mapstructure:"min_connections"`
	URL             string        `mapstructure:"url"`
}

type HTTPConfiguration struct {
	BaseURL string   `mapstructure:"base_url"`
	Hosts   []string `mapstructure:"hosts"`
}

type SecurityConfiguration struct {
	EnableAuditLogging    bool          `mapstructure:"enable_audit_logging"`
	EnableCSRFProtection  bool          `mapstructure:"enable_csrf_protection"`
	RateLimitRequests     int           `mapstructure:"rate_limit_requests"`
	RateLimitWindow       time.Duration `mapstructure:"rate_limit_window"`
	SessionCookieHTTPOnly bool          `mapstructure:"session_cookie_http_only"`
	SessionCookieName     string        `mapstructure:"session_cookie_name"`
	SessionCookieSameSite string        `mapstructure:"session_cookie_same_site"`
	SessionCookieSecure   bool          `mapstructure:"session_cookie_secure"`
	TrustedProxies        []string      `mapstructure:"trusted_proxies"`
	TrustProxyHeaders     bool          `mapstructure:"trust_proxy_headers"`
}

func LoadEnv() error {
	_ = godotenv.Load()

	cfg := viper.New()
	cfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	cfg.AutomaticEnv()

	setDefaults(cfg)

	if err := cfg.Unmarshal(Config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func setDefaults(cfg *viper.Viper) {
	// Database defaults
	cfg.SetDefault("database.max_connections", 25)
	cfg.SetDefault("database.max_conn_idle_time", 10*time.Minute)
	cfg.SetDefault("database.max_conn_lifetime", 1*time.Hour)
	cfg.SetDefault("database.min_connections", 5)

	// Auth defaults
	cfg.SetDefault("auth.access_token_ttl", 15*time.Minute)
	cfg.SetDefault("auth.allow_self_registration", true)
	cfg.SetDefault("auth.bcrypt_cost", 12)
	cfg.SetDefault("auth.default_role", "user")
	cfg.SetDefault("auth.enable_mfa", false)
	cfg.SetDefault("auth.lockout_duration", 15*time.Minute)
	cfg.SetDefault("auth.max_login_attempts", 5)
	cfg.SetDefault("auth.password_history_limit", 5)
	cfg.SetDefault("auth.password_min_length", 8)
	cfg.SetDefault("auth.password_require_lower", true)
	cfg.SetDefault("auth.password_require_number", true)
	cfg.SetDefault("auth.password_require_special", true)
	cfg.SetDefault("auth.password_require_upper", true)
	cfg.SetDefault("auth.refresh_token_ttl", 7*24*time.Hour)
	cfg.SetDefault("auth.require_email_verification", false)

	// Security defaults
	cfg.SetDefault("security.enable_audit_logging", true)
	cfg.SetDefault("security.enable_csrf_protection", true)
	cfg.SetDefault("security.rate_limit_requests", 60)
	cfg.SetDefault("security.rate_limit_window", 1*time.Minute)
	cfg.SetDefault("security.session_cookie_http_only", true)
	cfg.SetDefault("security.session_cookie_name", "access_token")
	cfg.SetDefault("security.session_cookie_same_site", "strict")
	cfg.SetDefault("security.session_cookie_secure", true)
	cfg.SetDefault("security.trusted_proxies", []string{}) // Empty by default for security
	cfg.SetDefault("security.trust_proxy_headers", false)   // Disabled by default for security
}
