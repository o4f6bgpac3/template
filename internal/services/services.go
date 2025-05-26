package services

import (
	"context"
	"os"
	"time"

	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	"github.com/o4f6bgpac3/template/internal/auth"
	"github.com/o4f6bgpac3/template/internal/database"
	db "github.com/o4f6bgpac3/template/internal/database/sqlc"
	"github.com/o4f6bgpac3/template/internal/middleware"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

type Services struct {
	Log            zerolog.Logger
	DB             *database.DB
	Queries        *db.Queries
	Auth           *auth.Service
	Audit          *audit.Service
	RateLimitStore *middleware.RateLimitStore
}

func Init(cmd *cobra.Command, args []string) (*Services, error) {
	if err := cfg.LoadEnv(); err != nil {
		return nil, err
	}

	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	ctx := context.Background()
	dbInstance, err := database.NewDB(ctx)
	if err != nil {
		return nil, err
	}

	if err := dbInstance.Migrate(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to run migrations")
	}

	queries := db.New(dbInstance.Pool)

	auditService := audit.NewService(
		dbInstance,
		queries,
		log,
		cfg.Config.Security.EnableAuditLogging,
	)

	authService := auth.NewService(dbInstance, queries, auditService)

	rateLimitStore := middleware.NewRateLimitStore(15 * time.Minute)

	return &Services{
		Log:            log,
		DB:             dbInstance,
		Queries:        queries,
		Auth:           authService,
		Audit:          auditService,
		RateLimitStore: rateLimitStore,
	}, nil
}

func (s *Services) Cleanup() {
	if s.DB != nil {
		s.DB.Close()
	}
}
