package tpm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/go-tpm/tpmutil"
	"github.com/quantumauth-io/quantum-auth-client/internal/securefile"
	"os"
	"runtime"
	"strings"

	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

type TPMKeyRef struct {
	HandleHex string `json:"handle_hex"`
}

func NewRuntimeTPM(ctx context.Context) (tpmdevice.Client, error) {
	switch runtime.GOOS {
	case "linux", "windows":
		return newRuntimeTPMWithHandleFile(ctx)
	case "darwin":
		return nil, fmt.Errorf("macOS TPM backend not implemented")

	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func newRuntimeTPMWithHandleFile(ctx context.Context) (tpmdevice.Client, error) {
	// Choose where to store the handle reference
	paths, err := securefile.ConfigPathCandidates("quantumauth", "tpm_keyref.json")
	if err != nil || len(paths) == 0 {
		return nil, fmt.Errorf("tpm: config path: %w", err)
	}
	path := paths[0]

	// Try to load an existing handle
	var loaded tpmutil.Handle
	if ref, err := securefile.ReadJSON[TPMKeyRef](path); err == nil {
		if h, err2 := parseTPMHandle(ref.HandleHex); err2 == nil && h != 0 {
			loaded = h
		}
	} else {
		// Ignore missing file; anything else should surface
		if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("tpm: read keyref: %w", err)
		}
	}

	cfg := tpmdevice.Config{
		Handle:    loaded, // 0 means "picker mode" in your utils
		ForceNew:  false,
		OwnerAuth: "",
		// Optional: reserve a QA range (recommended)
		HandleStart: tpmutil.Handle(0x8100A001),
		HandleCount: 32,
	}

	c, err := tpmdevice.NewWithConfig(ctx, cfg)
	if err != nil {
		// If the stored handle was bad/incompatible, you can optionally fall back once:
		// - clear handle and retry picker mode
		if loaded != 0 {
			cfg.Handle = 0
			c2, err2 := tpmdevice.NewWithConfig(ctx, cfg)
			if err2 == nil {
				_ = persistHandle(path, c2.Handle())
				return c2, nil
			}
		}
		return nil, err
	}

	// Persist chosen handle for next run
	if err := persistHandle(path, c.Handle()); err != nil {
		return nil, fmt.Errorf("tpm: persist keyref: %w", err)
	}
	return c, nil
}

func persistHandle(path string, h tpmutil.Handle) error {
	ref := TPMKeyRef{HandleHex: fmt.Sprintf("0x%x", uint32(h))}
	return securefile.WriteJSON(path, ref, 0o600, 0o700)
}

func parseTPMHandle(s string) (tpmutil.Handle, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty handle")
	}
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	// allow underscores like "8100_a001" if you ever want that style
	s = strings.ReplaceAll(s, "_", "")
	if len(s) > 8 {
		return 0, fmt.Errorf("handle too long")
	}
	// left-pad to even length for hex decode
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid hex: %w", err)
	}
	var v uint32
	for _, by := range b {
		v = (v << 8) | uint32(by)
	}
	return tpmutil.Handle(v), nil
}
