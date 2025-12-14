package tpm

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

func NewRuntimeTPM(ctx context.Context) (tpmdevice.Client, error) {
	switch runtime.GOOS {
	case "linux", "windows":
		cfg := tpmdevice.Config{
			Handle:   0,
			ForceNew: false,
			Logger:   log.New(os.Stderr, "", log.LstdFlags),
		}
		return tpmdevice.NewWithConfig(ctx, cfg)

	case "darwin":
		return nil, fmt.Errorf("macOS TPM backend not implemented")

	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
