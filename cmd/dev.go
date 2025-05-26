package cmd

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/o4f6bgpac3/template/internal/routes"
	"github.com/o4f6bgpac3/template/internal/services"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"time"
)

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Run in development mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := services.Init(cmd, args)
		if err != nil {
			return err
		}

		var g run.Group
		r := chi.NewMux()

		routes.Setup(r, nil, svc)

		port := os.Getenv("PORT")
		if port == "" {
			svc.Log.Info().Str("port", port).Msg("No port specified, using default")
			port = "3000"
		}

		addr := ":" + port
		srv := &http.Server{
			Addr:    addr,
			Handler: r,
		}

		g.Add(
			func() error {
				svc.Log.Info().Str("addr", addr).Msg("Starting development API server")
				svc.Log.Info().Msg("Frontend should be started separately with 'npm run dev'")
				return srv.ListenAndServe()
			},
			func(error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				svc.Log.Info().Msg("Shutting down development API server")
				_ = srv.Shutdown(ctx)
				svc.Cleanup()
			},
		)

		svc.Log.Info().Msg("Development mode started")
		return g.Run()
	},
}

func init() {
	rootCmd.AddCommand(devCmd)
}
