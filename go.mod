module github.com/quantumauth-io/quantum-auth-client

replace github.com/quantumauth-io/quantum-auth => ../quantum-auth

go 1.25.4

require (
	github.com/cloudflare/circl v1.6.1
	github.com/quantumauth-io/quantum-auth v0.0.0
	github.com/quantumauth-io/quantum-go-utils v0.0.7
	golang.org/x/term v0.37.0
)

require (
	github.com/google/go-tpm v0.9.7 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
