package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/o4f6bgpac3/template/cfg"
)

type DB struct {
	*pgxpool.Pool
}

func NewDB(ctx context.Context) (*DB, error) {
	config, err := pgxpool.ParseConfig(cfg.Config.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DATABASE_URL: %w", err)
	}

	config.MaxConns = cfg.Config.Database.MaxConnections
	config.MinConns = cfg.Config.Database.MinConnections
	config.MaxConnLifetime = cfg.Config.Database.MaxConnLifetime
	config.MaxConnIdleTime = cfg.Config.Database.MaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

func (db *DB) Transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("rollback transaction: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (db *DB) Close() {
	db.Pool.Close()
}
