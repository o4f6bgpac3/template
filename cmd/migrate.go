package cmd

import (
	"context"
	"fmt"

	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/database"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cfg.LoadEnv(); err != nil {
			return err
		}

		ctx := context.Background()
		db, err := database.NewDB(ctx)
		if err != nil {
			return fmt.Errorf("connect to database: %w", err)
		}
		defer db.Close()

		currentVersion, _ := db.GetMigrationStatus(ctx)
		fmt.Printf("Current migration version: %d\n", currentVersion)

		fmt.Println("Running migrations...")
		if err := db.Migrate(ctx); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}

		newVersion, _ := db.GetMigrationStatus(ctx)
		fmt.Printf("New migration version: %d\n", newVersion)

		if currentVersion == newVersion {
			fmt.Println("No new migrations to run")
		} else {
			fmt.Println("Migrations completed successfully")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
