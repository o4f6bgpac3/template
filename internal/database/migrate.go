package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/tern/v2/migrate"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func (db *DB) Migrate(ctx context.Context) error {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	migrator, err := migrate.NewMigrator(ctx, conn.Conn(), "schema_version")
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}

	// Create a sub-filesystem pointing to the migrations directory
	migrationsDir, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("create migrations sub-filesystem: %w", err)
	}

	if err := migrator.LoadMigrations(migrationsDir); err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

func (db *DB) GetMigrationStatus(ctx context.Context) (int32, error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	migrator, err := migrate.NewMigrator(ctx, conn.Conn(), "schema_version")
	if err != nil {
		return 0, fmt.Errorf("create migrator: %w", err)
	}

	// Create a sub-filesystem pointing to the migrations directory
	migrationsDir, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return 0, fmt.Errorf("create migrations sub-filesystem: %w", err)
	}

	if err := migrator.LoadMigrations(migrationsDir); err != nil {
		return 0, fmt.Errorf("load migrations: %w", err)
	}

	version, err := migrator.GetCurrentVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("get current version: %w", err)
	}

	return version, nil
}
