package tpm

import (
	"fmt"
)

type WindowsTPM struct{}

func (t *WindowsTPM) Open() error {
	fmt.Println("Using Windows TPM API")
	return nil
}

func (t *WindowsTPM) Close() error { return nil }
