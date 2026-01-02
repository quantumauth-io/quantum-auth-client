package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	utilsconfig "github.com/quantumauth-io/quantum-go-utils/config"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

type ClientSettings struct {
	LocalHost   string
	ServerURL   string
	Port        string
	DeviceLabel string
	Email       string
}

type DefaultAssetsConfig struct {
	Network map[string][]string `yaml:"Network" json:"network"`
}
type Config struct {
	ClientSettings *ClientSettings
	EthNetworks    *utilsEth.MultiConfig `mapstructure:"Ethereum"`
	DefaultAssets  DefaultAssetsConfig   `yaml:"DefaultAssets" json:"defaultAssets"`
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

func (c *Config) InjectInfuraKeyFromEnv() error {
	key := strings.TrimSpace(os.Getenv("INFURA_API_KEY"))
	if key == "" {
		return errors.New("INFURA_API_KEY is not set")
	}

	for netName, net := range c.EthNetworks.Networks {
		for i := range net.RPCs {
			rpc := &net.RPCs[i]

			if !strings.EqualFold(rpc.Name, "Infura") {
				continue
			}

			u := strings.TrimSpace(rpc.URL)
			if u == "" {
				return fmt.Errorf("empty Infura URL for network %q", netName)
			}

			// If URL already ends with the key, don't double-append.
			if strings.HasSuffix(u, "/"+key) {
				continue
			}

			// Basic validation + normalization
			parsed, err := url.Parse(u)
			if err != nil {
				return fmt.Errorf("invalid Infura URL for network %q: %w", netName, err)
			}

			// Ensure trailing slash before appending key
			if !strings.HasSuffix(parsed.Path, "/") {
				parsed.Path += "/"
			}
			parsed.Path += key

			rpc.URL = parsed.String()
		}

		// write back (since net is a copy when pulled from map)
		c.EthNetworks.Networks[netName] = net
	}

	return nil
}

func (c *Config) ApplyServerURLFromEnv() error {
	raw := strings.TrimSpace(os.Getenv("QA_ENV"))

	switch strings.ToLower(raw) {
	case "":
		// prod default
		c.ClientSettings.ServerURL = "https://api.quantumauth.io/quantum-auth/v1"

	case "prod", "production":
		c.ClientSettings.ServerURL = "https://api.quantumauth.io/quantum-auth/v1"

	case "local":
		c.ClientSettings.ServerURL = "http://localhost:1042/quantum-auth/v1"

	case "dev", "develop", "development":
		c.ClientSettings.ServerURL = "https://dev.api.quantumauth.io/quantum-auth/v1"

	default:
		return fmt.Errorf("invalid QA_ENV %q (allowed: local, develop, empty)", raw)
	}

	return nil
}

func (c *Config) NormalizeDefaultAssets() error {
	if c.DefaultAssets.Network == nil {
		c.DefaultAssets.Network = map[string][]string{}
		return nil
	}

	outByNet := make(map[string][]string, len(c.DefaultAssets.Network))

	for netKey, addrs := range c.DefaultAssets.Network {
		nk := strings.ToLower(strings.TrimSpace(netKey))
		if nk == "" {
			return fmt.Errorf("DefaultAssets.Network has empty network key")
		}

		seen := map[string]struct{}{}
		out := make([]string, 0, len(addrs))

		for _, raw := range addrs {
			a := strings.TrimSpace(raw)
			if a == "" {
				return fmt.Errorf("DefaultAssets.Network[%q] contains empty address", netKey)
			}
			if !strings.HasPrefix(a, "0x") && !strings.HasPrefix(a, "0X") {
				a = "0x" + a
			}
			a = strings.ToLower(a)

			if !common.IsHexAddress(a) {
				return fmt.Errorf("DefaultAssets.Network[%q] invalid address: %q", netKey, raw)
			}

			// canonical form: checksummed hex string
			canon := common.HexToAddress(a).Hex()

			if _, ok := seen[canon]; ok {
				continue
			}
			seen[canon] = struct{}{}
			out = append(out, canon)
		}

		outByNet[nk] = out
	}

	c.DefaultAssets.Network = outByNet
	return nil
}
