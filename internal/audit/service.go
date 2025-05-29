package audit

import (
	"context"
	"encoding/json"
	"github.com/o4f6bgpac3/template/internal/utils"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/o4f6bgpac3/template/internal/database"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"github.com/rs/zerolog"
)

type EventType string

const (
	EventUserLogin          EventType = "user_login"
	EventUserLoginFailed    EventType = "user_login_failed"
	EventUserLogout         EventType = "user_logout"
	EventUserRegister       EventType = "user_register"
	EventUserPasswordChange EventType = "user_password_change"
	EventUserAccountLocked  EventType = "user_account_locked"
	EventPermissionDenied   EventType = "permission_denied"
	EventUserDelete         EventType = "user_delete"
)

type Service struct {
	db      *database.DB
	queries *db.Queries
	logger  zerolog.Logger
	enabled bool
}

type Event struct {
	Type      EventType   `json:"type"`
	UserId    *uuid.UUID  `json:"user_id,omitempty"`
	IpAddress netip.Addr  `json:"ip_address"`
	UserAgent string      `json:"user_agent"`
	Resource  string      `json:"resource,omitempty"`
	Action    string      `json:"action,omitempty"`
	Success   bool        `json:"success"`
	Error     string      `json:"error,omitempty"`
	Metadata  interface{} `json:"metadata,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewService(db *database.DB, queries *db.Queries, logger zerolog.Logger, enabled bool) *Service {
	return &Service{
		db:      db,
		queries: queries,
		logger:  logger,
		enabled: enabled,
	}
}

func (s *Service) LogEvent(ctx context.Context, event Event) {
	if !s.enabled {
		return
	}

	event.Timestamp = time.Now()

	go func() {
		if err := s.storeEvent(ctx, event); err != nil {
			s.logger.Error().Err(err).Msg("Failed to store audit event")
		}

		s.logToConsole(event)
	}()
}

func (s *Service) LogEventFromRequest(ctx context.Context, r *http.Request, eventType EventType, userID *uuid.UUID, success bool, err error) {
	event := Event{
		Type:      eventType,
		UserId:    userID,
		IpAddress: utils.GetClientIp(r),
		UserAgent: r.UserAgent(),
		Success:   success,
		Timestamp: time.Now(),
	}

	if err != nil {
		event.Error = err.Error()
	}

	s.LogEvent(ctx, event)
}

func (s *Service) LogAuthEvent(ctx context.Context, r *http.Request, eventType EventType, userID *uuid.UUID, success bool, metadata interface{}, err error) {
	event := Event{
		Type:      eventType,
		UserId:    userID,
		IpAddress: utils.GetClientIp(r),
		UserAgent: r.UserAgent(),
		Success:   success,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	if err != nil {
		event.Error = err.Error()
	}

	s.LogEvent(ctx, event)
}

func (s *Service) LogPermissionDenied(ctx context.Context, r *http.Request, userID uuid.UUID, resource, action string) {
	event := Event{
		Type:      EventPermissionDenied,
		UserId:    &userID,
		IpAddress: utils.GetClientIp(r),
		UserAgent: r.UserAgent(),
		Resource:  resource,
		Action:    action,
		Success:   false,
		Timestamp: time.Now(),
	}

	s.LogEvent(ctx, event)
}

func (s *Service) storeEvent(ctx context.Context, event Event) error {
	metadataJSON, _ := json.Marshal(event.Metadata)

	var userID uuid.UUID
	if event.UserId != nil {
		userID = *event.UserId
	}

	var userAgent *string
	if event.UserAgent != "" {
		userAgent = &event.UserAgent
	}

	var resource *string
	if event.Resource != "" {
		resource = &event.Resource
	}

	var action *string
	if event.Action != "" {
		action = &event.Action
	}

	var errorStr *string
	if event.Error != "" {
		errorStr = &event.Error
	}

	_, err := s.queries.CreateAuditLog(ctx, db.CreateAuditLogParams{
		EventType: string(event.Type),
		UserID:    userID,
		IpAddress: &event.IpAddress,
		UserAgent: userAgent,
		Resource:  resource,
		Action:    action,
		Success:   event.Success,
		Error:     errorStr,
		Metadata:  metadataJSON,
		CreatedAt: pgtype.Timestamptz{
			Time:  event.Timestamp,
			Valid: true,
		},
	})

	return err
}

func (s *Service) logToConsole(event Event) {
	logEvent := s.logger.Info()

	if !event.Success {
		logEvent = s.logger.Warn()
	}

	logEvent.
		Str("event_type", string(event.Type)).
		Str("ip_address", event.IpAddress.String()).
		Bool("success", event.Success)

	if event.UserId != nil {
		logEvent.Str("user_id", event.UserId.String())
	}

	if event.Resource != "" {
		logEvent.Str("resource", event.Resource)
	}

	if event.Action != "" {
		logEvent.Str("action", event.Action)
	}

	if event.Error != "" {
		logEvent.Str("error", event.Error)
	}

	logEvent.Msg("Audit event")
}
