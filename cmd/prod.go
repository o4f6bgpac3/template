package cmd

import (
	"context"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/o4f6bgpac3/template/internal/middleware"
	"github.com/o4f6bgpac3/template/internal/routes"
	"github.com/o4f6bgpac3/template/internal/services"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"io/fs"
	"net/http"
	"os"
	"time"
)

var GetStaticFS func() (fs.FS, error)

var prodCmd = &cobra.Command{
	Use:   "prod",
	Short: "Start the application in production mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		if GetStaticFS == nil {
			return fmt.Errorf("static file system not initialized")
		}

		svc, err := services.Init(cmd, args)
		if err != nil {
			return err
		}

		fSys, err := GetStaticFS()
		if err != nil {
			return err
		}

		var g run.Group
		r := chi.NewMux()

		middleware.Setup(r)
		routes.Setup(r, fSys, svc)

		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		addr := ":" + port
		srv := &http.Server{
			Addr:    addr,
			Handler: r,
		}

		g.Add(
			func() error {
				svc.Log.Info().Str("addr", addr).Msg("Starting HTTP server")
				return srv.ListenAndServe()
			},
			func(error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				svc.Log.Info().Msg("Shutting down HTTP server")
				_ = srv.Shutdown(ctx)
				svc.Cleanup()
			},
		)

		svc.Log.Info().Msg("Application started in production mode")
		return g.Run()
	},
}

func init() {
	rootCmd.AddCommand(prodCmd)
}
