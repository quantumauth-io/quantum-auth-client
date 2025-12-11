package config

import (
	"os"
	"path/filepath"

	utilsconfig "github.com/quantumauth-io/quantum-go-utils/config"
)

type ClientSettings struct {
	LocalHost   string
	ServerURL   string
	Port        string
	DeviceLabel string
	Email       string
}

type Config struct {
	ClientSettings ClientSettings
}

func Load() (*Config, error) {
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(home, ".config", "quantum-auth-client"),
		filepath.Join(home, "config"),
		".",
	}

	return utilsconfig.ParseConfigWithEmbedded[Config](paths, EmbeddedConfigYAML)
}
