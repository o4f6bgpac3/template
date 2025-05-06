package cfg

import (
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"strings"
)

var Config = &Configuration{}

type (
	Configuration struct {
		Env  uint              `mapstructure:"env"`
		Http HttpConfiguration `mapstructure:"http"`
	}

	HttpConfiguration struct {
		BaseURL string   `mapstructure:"base_url"`
		Hosts   []string `mapstructure:"hosts"`
	}
)

func LoadEnv() error {
	_ = godotenv.Load()

	cfg := viper.New()
	cfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	cfg.AutomaticEnv()
	return cfg.Unmarshal(Config)
}
