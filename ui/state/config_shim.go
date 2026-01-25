package state

import (
	"fmt"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
)

func buildConfigShim(s GUISettings) (*config.Config, error) {

	cfg, err := config.Load()

	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("load config: nil config")
	}

	// Ensure required pointers exist (defensive)
	if cfg.ClientSettings == nil {
		cfg.ClientSettings = &config.ClientSettings{}
	}
	if cfg.Networks == nil {
		cfg.Networks = &chains.AllChainsConfig{
			Networks: map[string]chains.NetworkConfig{},
		}
	}
	if cfg.Networks.Networks == nil {
		cfg.Networks.Networks = map[string]chains.NetworkConfig{}
	}

	// ---- Apply GUI overrides ----

	// GUI chooses environment; derive ServerURL from QAEnv (source of truth)
	if err := cfg.ApplyServerURLFromQAEnv(s.QAEnv); err != nil {
		return nil, err
	}

	// Local server bind values
	if h := strings.TrimSpace(s.LocalHost); h != "" {
		cfg.ClientSettings.LocalHost = h
	}
	if p := strings.TrimSpace(s.Port); p != "" {
		cfg.ClientSettings.Port = p
	}

	// Device/email (if you still want them in config; optional)
	if e := strings.TrimSpace(s.Email); e != "" {
		cfg.ClientSettings.Email = e
	}
	if dl := strings.TrimSpace(s.DeviceLabel); dl != "" {
		cfg.ClientSettings.DeviceLabel = dl
	}

	// Network selection overrides (very important)
	if an := strings.TrimSpace(s.ActiveNetwork); an != "" {
		cfg.Networks.ActiveNetwork = an
	}
	if ar := strings.TrimSpace(s.ActiveRPC); ar != "" {
		cfg.Networks.ActiveRPC = ar
	}

	// Inject Infura key if provided (fills RPC URLs)
	if k := strings.TrimSpace(s.InfuraKey); k != "" {
		if err := cfg.InjectInfuraKey(k); err != nil {
			return nil, err
		}
	}

	// Normalize + validate
	cfg.Networks.Normalize()
	if err := cfg.NormalizeDefaultAssets(); err != nil {
		return nil, err
	}

	// Optional: fail fast if GUI picked a network not present in config
	if cfg.Networks.ActiveNetwork != "" {
		if _, ok := cfg.Networks.Networks[cfg.Networks.ActiveNetwork]; !ok {
			return nil, fmt.Errorf("active network %q not found in config", cfg.Networks.ActiveNetwork)
		}
	}

	return cfg, nil
}
