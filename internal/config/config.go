package config

import (
	"os"
)

type Config struct {
	ServerURL   string
	DeviceLabel string
	Email       string
	Password    string
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (*Config, error) {
	return &Config{
		ServerURL:   getEnv("QA_SERVER_URL", "http://localhost:1042/quantum-auth/v1"),
		DeviceLabel: getEnv("QA_DEVICE_LABEL", "default-device"),
		Email:       getEnv("QA_EMAIL", ""),
		Password:    getEnv("QA_PASSWORD", ""),
	}, nil
}
