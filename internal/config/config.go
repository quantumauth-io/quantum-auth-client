package config

import (
	"os"
)

type Config struct {
	// QuantumAuth server base URL, e.g. http://localhost:1042/quantum-auth/v1
	ServerURL string

	// Optional label for this device, e.g. "nitro-laptop"
	DeviceLabel string

	// Optional email/password for bootstrapping a user
	Email    string
	Password string
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
		Email:       getEnv("Q_AEMAIL", ""),
		Password:    getEnv("QA_PASSWORD", ""),
	}, nil
}
