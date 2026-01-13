package ethdevice

// TPM seals/unseals a small secret (the DEK).
// Real TPM implementation can bind sealing to PCRs / policies internally.
type TPM interface {
	Seal(label string, dek []byte) (sealed []byte, err error)
	Unseal(label string, sealed []byte) (dek []byte, err error)
}
