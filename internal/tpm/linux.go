package tpm

import (
	"fmt"
)

type LinuxTPM struct{}

func (t *LinuxTPM) Open() error {
	fmt.Println("Using Linux TPM: /dev/tpm0 or /dev/tpmrm0")
	return nil
}

func (t *LinuxTPM) Close() error { return nil }
