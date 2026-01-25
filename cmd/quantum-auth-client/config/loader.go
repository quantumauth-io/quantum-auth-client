package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	utilsconfig "github.com/quantumauth-io/quantum-go-utils/config"
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
	Networks       *chains.AllChainsConfig `mapstructure:"Ethereum"`
	DefaultAssets  DefaultAssetsConfig     `yaml:"DefaultAssets" json:"defaultAssets"`
}

var (
	loadOnce sync.Once
	baseCfg  *Config
	loadErr  error
)

func infuraRPC(chain string, key string) (string, string) {
	return fmt.Sprintf("https://%s.infura.io/v3/%s", chain, key),
		fmt.Sprintf("wss://%s.infura.io/ws/v3/%s", chain, key)
}

func Load() (*Config, error) {
	loadOnce.Do(func() {
		baseCfg, loadErr = loadImpl()
	})
	if loadErr != nil {
		return nil, loadErr
	}
	if baseCfg == nil {
		return nil, fmt.Errorf("config: nil base config")
	}
	return baseCfg.Clone(), nil
}

// existing Load body goes here
func loadImpl() (*Config, error) {
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(home, ".config", "quantum-auth-client"),
		filepath.Join(home, "config"),
		".",
	}
	return utilsconfig.ParseConfigWithEmbedded[Config](paths, EmbeddedConfigYAML)
}

func (c *Config) InjectInfuraKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("infura api key is empty")
	}

	for netName, net := range c.Networks.Networks {
		rpcURL, rpcWSS := infuraRPC(netName, key)

		// Ensure at least one RPC entry exists
		if len(net.RPCs) == 0 {
			net.RPCs = []chains.RPC{
				{
					Name: "Infura",
					URL:  rpcURL,
					WSS:  rpcWSS,
				},
			}
		} else {
			// Fill or overwrite the first RPC slot
			net.RPCs[0].Name = "Infura"
			net.RPCs[0].URL = rpcURL
			net.RPCs[0].WSS = rpcWSS
		}

		// IMPORTANT: write back (map value copy)
		c.Networks.Networks[netName] = net
	}

	return nil
}

func (c *Config) ApplyServerURLFromQAEnv(env string) error {
	raw := strings.TrimSpace(env)

	switch strings.ToLower(raw) {
	case "", "prod", "production":
		c.ClientSettings.ServerURL = "https://api.quantumauth.io/quantum-auth/v1"

	case "local":
		c.ClientSettings.ServerURL = "http://localhost:1042/quantum-auth/v1"

	case "dev", "develop", "development":
		c.ClientSettings.ServerURL = "https://dev.api.quantumauth.io/quantum-auth/v1"

	default:
		return fmt.Errorf("invalid QA environment %q", raw)
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
