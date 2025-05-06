package services

import (
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"os"
)

func Init(cmd *cobra.Command, args []string) (*Services, error) {
	if err := cfg.LoadEnv(); err != nil {
		return nil, err
	}

	log := zerolog.New(os.Stdout).With().Timestamp().Logger()
	return &Services{
		Log: log,
	}, nil
}

type Services struct {
	Log zerolog.Logger
}
