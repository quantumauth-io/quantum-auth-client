#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Ensure abigen exists (IntelliJ often has a different PATH than your shell)
ABIGEN="$(command -v abigen || true)"

if [ -z "$ABIGEN" ]; then
  CANDIDATE="$(go env GOPATH)/bin/abigen"
  if [ -x "$CANDIDATE" ]; then
    ABIGEN="$CANDIDATE"
  fi
fi

if [ -z "$ABIGEN" ]; then
  echo "abigen not found."
  echo "Install with: go install github.com/ethereum/go-ethereum/cmd/abigen@v1.16.7"
  echo "Then ensure PATH includes: $(go env GOPATH)/bin"
  exit 1
fi

# Sanity: ensure artifacts exist
test -f abi/QuantumAuthAccount.abi.json
test -f bin/QuantumAuthAccount.bin
test -f abi/TPMVerifierSecp256k1.abi.json
test -f bin/TPMVerifierSecp256k1.bin
test -f abi/EntryPoint.abi.json
test -f bin/EntryPoint.bin
test -f abi/QAERC20.abi.json
test -f bin/QAERC20.bin

mkdir -p bindings/go/quantumauthaccount
mkdir -p bindings/go/tpmverifiersecp256k1
mkdir -p bindings/go/entrypoint
mkdir -p bindings/go/qaerc20

"$ABIGEN" \
  --abi abi/QuantumAuthAccount.abi.json \
  --bin bin/QuantumAuthAccount.bin \
  --pkg quantumauthaccount \
  --type QuantumAuthAccount \
  --out bindings/go/quantumauthaccount/quantumauthaccount.go

"$ABIGEN" \
  --abi abi/TPMVerifierSecp256k1.abi.json \
  --bin bin/TPMVerifierSecp256k1.bin \
  --pkg tpmverifiersecp256k1 \
  --type TPMVerifierSecp256k1 \
  --out bindings/go/tpmverifiersecp256k1/tpmverifiersecp256k1.go

"$ABIGEN" \
  --abi abi/EntryPoint.abi.json \
  --bin bin/EntryPoint.bin \
  --pkg entrypoint \
  --type EntryPoint \
  --out bindings/go/entrypoint/entrypoint.go

"$ABIGEN" \
  --abi abi/QAERC20.abi.json \
  --bin bin/QAERC20.bin \
  --pkg qaerc20 \
  --type QAERC20 \
  --out bindings/go/qaerc20/qaerc20.go