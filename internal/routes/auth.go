package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/auth"
	"github.com/o4f6bgpac3/template/internal/middleware"
	"github.com/o4f6bgpac3/template/internal/services"
	"github.com/o4f6bgpac3/template/internal/validation"
)

type authHandler struct {
	authService *auth.Service
}

type registerRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

type loginRequest struct {
	EmailOrUsername string `json:"email_or_username"`
	Password        string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

type errorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

func setupAuthRoutes(r chi.Router, svc *services.Services) {
	h := &authHandler{authService: svc.Auth}

	r.Route("/auth", func(r chi.Router) {
		r.Use(middleware.RateLimit(svc.RateLimitStore,
			cfg.Config.Security.RateLimitRequests,
			cfg.Config.Security.RateLimitWindow))

		// Public routes
		r.Post("/register", h.register)
		r.Post("/login", h.login)
		r.Post("/refresh", h.refresh)
		r.Post("/logout", h.logout)
		r.Post("/forgot-password", h.forgotPassword)
		r.Post("/reset-password", h.resetPassword)
		r.Post("/verify-email", h.verifyEmail)
		r.Post("/resend-verification", h.resendVerification)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(svc.Auth, svc.Audit))
			r.Get("/me", h.getCurrentUser)
			r.Post("/logout-all", h.logoutAll)
			r.Put("/change-password", h.changePassword)
			r.Get("/sessions", h.getActiveSessions)
			r.Delete("/sessions/{sessionId}", h.invalidateSession)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(svc.Auth, svc.Audit))
			r.Use(middleware.RequireRole(svc.Audit, "admin"))
			r.Get("/audit-logs", h.getAuditLogs)
			r.Get("/security-stats", h.getSecurityStats)
		})
	})
}

func (h *authHandler) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	user, err := h.authService.Register(r.Context(), r, req.Email, req.Username, req.Password, req.Role)
	if err != nil {
		var validationErr *validation.ValidationErrors
		if errors.As(err, &validationErr) {
			h.writeError(w, "Validation failed", http.StatusBadRequest, validationErr.Errors)
			return
		}

		switch {
		case errors.Is(err, auth.ErrRegistrationDisabled):
			h.writeError(w, "Registration is disabled", http.StatusForbidden, nil)
		default:
			h.writeError(w, "Failed to create user", http.StatusInternalServerError, nil)
		}
		return
	}

	if !cfg.Config.Auth.RequireEmailVerification {
		tokens, err := h.authService.Login(r.Context(), r, req.Email, req.Password, r.UserAgent())
		if err != nil {
			h.writeError(w, "Registration successful but login failed", http.StatusCreated, nil)
			return
		}

		h.setCookie(w, tokens)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":   user,
			"tokens": tokens,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    user,
		"message": "Registration successful. Please check your email for verification.",
	})
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	tokens, err := h.authService.Login(r.Context(), r, req.EmailOrUsername, req.Password, r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			h.writeError(w, "Invalid credentials", http.StatusUnauthorized, nil)
		case errors.Is(err, auth.ErrAccountLocked):
			h.writeError(w, "Account locked due to too many failed attempts", http.StatusLocked, nil)
		case errors.Is(err, auth.ErrEmailNotVerified):
			h.writeError(w, "Email not verified", http.StatusForbidden, nil)
		default:
			h.writeError(w, "Login failed", http.StatusInternalServerError, nil)
		}
		return
	}

	h.setCookie(w, tokens)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	tokens, err := h.authService.RefreshTokens(r.Context(), r, req.RefreshToken)
	if err != nil {
		h.writeError(w, "Invalid refresh token", http.StatusUnauthorized, nil)
		return
	}

	h.setCookie(w, tokens)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.Logout(r.Context(), r, req.RefreshToken); err != nil {
		h.writeError(w, "Logout failed", http.StatusInternalServerError, nil)
		return
	}

	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		h.writeError(w, "Unauthorized", http.StatusUnauthorized, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func (h *authHandler) logoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		h.writeError(w, "Unauthorized", http.StatusUnauthorized, nil)
		return
	}

	if err := h.authService.LogoutAllDevices(r.Context(), r, userID); err != nil {
		h.writeError(w, "Failed to logout all devices", http.StatusInternalServerError, nil)
		return
	}

	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) changePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		h.writeError(w, "Unauthorized", http.StatusUnauthorized, nil)
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.ChangePassword(r.Context(), r, userID, req.OldPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			h.writeError(w, "Invalid current password", http.StatusBadRequest, nil)
		case errors.Is(err, auth.ErrPasswordReused):
			h.writeError(w, "Password was recently used", http.StatusBadRequest, nil)
		default:
			var validationErr *validation.ValidationErrors
			if errors.As(err, &validationErr) {
				h.writeError(w, "Validation failed", http.StatusBadRequest, validationErr.Errors)
				return
			}
			h.writeError(w, "Failed to change password", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := validation.ValidateEmail(req.Email); err != nil {
		h.writeError(w, "Invalid email format", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.CreatePasswordResetToken(r.Context(), req.Email); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "If the email exists, a password reset link has been sent.",
			})
			return
		}
		h.writeError(w, "Failed to process password reset request", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists, a password reset link has been sent.",
	})
}

func (h *authHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := validation.ValidatePassword(req.Password); err != nil {
		var validationErr *validation.ValidationErrors
		if errors.As(err, &validationErr) {
			h.writeError(w, "Validation failed", http.StatusBadRequest, validationErr.Errors)
			return
		}
		h.writeError(w, err.Error(), http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		switch {
		case errors.Is(err, auth.ErrTokenInvalid):
			h.writeError(w, "Invalid or expired reset token", http.StatusBadRequest, nil)
		default:
			h.writeError(w, "Failed to reset password", http.StatusInternalServerError, nil)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password has been reset successfully.",
	})
}

func (h *authHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), req.Token); err != nil {
		switch {
		case errors.Is(err, auth.ErrTokenInvalid):
			h.writeError(w, "Invalid or expired verification token", http.StatusBadRequest, nil)
		default:
			h.writeError(w, "Failed to verify email", http.StatusInternalServerError, nil)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Email verified successfully.",
	})
}

func (h *authHandler) resendVerification(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if err := validation.ValidateEmail(req.Email); err != nil {
		h.writeError(w, "Invalid email format", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.ResendEmailVerification(r.Context(), req.Email); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "If the email exists and is unverified, a verification link has been sent.",
			})
			return
		}
		h.writeError(w, "Failed to resend verification email", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists and is unverified, a verification link has been sent.",
	})
}

func (h *authHandler) getActiveSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		h.writeError(w, "Unauthorized", http.StatusUnauthorized, nil)
		return
	}

	sessions, err := h.authService.GetActiveSessions(r.Context(), userID)
	if err != nil {
		h.writeError(w, "Failed to get active sessions", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
	})
}

func (h *authHandler) invalidateSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		h.writeError(w, "Unauthorized", http.StatusUnauthorized, nil)
		return
	}

	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		h.writeError(w, "Session ID is required", http.StatusBadRequest, nil)
		return
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		h.writeError(w, "Invalid session ID format", http.StatusBadRequest, nil)
		return
	}

	if err := h.authService.InvalidateSession(r.Context(), userID, sessionUUID); err != nil {
		switch {
		case errors.Is(err, auth.ErrUserNotFound):
			h.writeError(w, "Session not found", http.StatusNotFound, nil)
		default:
			h.writeError(w, "Failed to invalidate session", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) getAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	var userID *uuid.UUID
	var eventType string
	var from, to *time.Time

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	if u := r.URL.Query().Get("user_id"); u != "" {
		if parsed, err := uuid.Parse(u); err == nil {
			userID = &parsed
		}
	}

	if e := r.URL.Query().Get("event_type"); e != "" {
		eventType = e
	}

	if f := r.URL.Query().Get("from"); f != "" {
		if parsed, err := time.Parse(time.RFC3339, f); err == nil {
			from = &parsed
		}
	}

	if t := r.URL.Query().Get("to"); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			to = &parsed
		}
	}

	logs, err := h.authService.GetAuditLogs(r.Context(), userID, eventType, from, to, limit, offset)
	if err != nil {
		h.writeError(w, "Failed to get audit logs", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":   logs,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *authHandler) getSecurityStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.authService.GetSecurityStats(r.Context())
	if err != nil {
		h.writeError(w, "Failed to get security statistics", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *authHandler) setCookie(w http.ResponseWriter, tokens *auth.Tokens) {
	sameSite := http.SameSiteStrictMode
	switch cfg.Config.Security.SessionCookieSameSite {
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Config.Security.SessionCookieName,
		Value:    tokens.AccessToken,
		Expires:  tokens.ExpiresAt,
		HttpOnly: cfg.Config.Security.SessionCookieHTTPOnly,
		Secure:   cfg.Config.Security.SessionCookieSecure,
		SameSite: sameSite,
		Path:     "/",
	})
}

func (h *authHandler) clearCookie(w http.ResponseWriter) {
	sameSite := http.SameSiteStrictMode
	switch cfg.Config.Security.SessionCookieSameSite {
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Config.Security.SessionCookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: cfg.Config.Security.SessionCookieHTTPOnly,
		Secure:   cfg.Config.Security.SessionCookieSecure,
		SameSite: sameSite,
		Path:     "/",
	})
}

func (h *authHandler) writeError(w http.ResponseWriter, message string, statusCode int, details map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := errorResponse{
		Error:   message,
		Details: details,
	}

	json.NewEncoder(w).Encode(response)
}
