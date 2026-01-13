package tpm

import (
	"fmt"
	"runtime"
)

type Provider interface {
	Open() error
	Close() error
}

func NewProvider() (Provider, error) {
	switch runtime.GOOS {
	case "linux":
		return &LinuxTPM{}, nil
	case "windows":
		return &WindowsTPM{}, nil
	case "darwin":
		return nil, fmt.Errorf("macOS has no TPM; use Secure Enclave flow")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
