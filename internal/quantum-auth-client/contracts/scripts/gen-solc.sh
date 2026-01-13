#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Ensure forge exists (IDE may not inherit shell PATH)
FORGE="$(command -v forge || true)"
if [ -z "$FORGE" ] && [ -x "$HOME/.foundry/bin/forge" ]; then
  FORGE="$HOME/.foundry/bin/forge"
fi

if [ -z "$FORGE" ]; then
  echo "forge not found."
  echo "Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup"
  echo "Or add to PATH: export PATH=\$HOME/.foundry/bin:\$PATH"
  exit 1
fi

# Ensure jq exists
JQ="$(command -v jq || true)"
if [ -z "$JQ" ]; then
  echo "jq not found."
  echo "Install with: sudo apt-get install -y jq"
  exit 1
fi

# Build with Foundry (expects foundry.toml at repo root)
"$FORGE" --version
# IMPORTANT: ensure artifacts exist even if forge would "skip"
"$FORGE" clean --root "$ROOT"
"$FORGE" build --root "$ROOT"

mkdir -p abi bin

# Helper: copy ABI+BIN from Foundry out/ tree into stable locations
copy_artifact () {
  local contract="$1"   # output name (e.g. QuantumAuthAccount)
  local type_name="$2"  # contract type name in artifact json
  local out_dir="$3"    # e.g. out/account/QuantumAuthAccount.sol
  local json="$out_dir/$type_name.json"

  if [ ! -f "$json" ]; then
    echo "Missing Foundry artifact: $json"
    exit 1
  fi

  "$JQ" -c '.abi' "$json" > "abi/$contract.abi.json"
  "$JQ" -r '.bytecode.object' "$json" > "bin/$contract.bin"

  test -s "abi/$contract.abi.json"
  test -s "bin/$contract.bin"
}

copy_artifact "QuantumAuthAccount" "QuantumAuthAccount" "out/QuantumAuthAccount.sol"
copy_artifact "TPMVerifierSecp256k1" "TPMVerifierSecp256k1" "out/TPMVerifierSecp256k1.sol"
copy_artifact "QAERC20" "QAERC20" "out/QAERC20.sol"

# --- Compile EntryPoint (real contract) with solc in Docker for Go bindings ---
SOLC_IMAGE="${SOLC_IMAGE:-ghcr.io/argotorg/solc:0.8.28}"

mkdir -p build/solc

docker run --rm \
  -u "$(id -u)":"$(id -g)" \
  -v "$ROOT:/workspace" \
  -w /workspace \
  "$SOLC_IMAGE" \
  --base-path . \
  --include-path lib \
  --include-path contracts \
  --include-path lib/account-abstraction/contracts \
  --include-path lib/openzeppelin-contracts/contracts \
  --optimize --optimize-runs 200 \
  --abi --bin \
  --overwrite \
  -o build/solc \
  "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/" \
  "@account-abstraction/contracts/=lib/account-abstraction/contracts/" \
  lib/account-abstraction/contracts/core/EntryPoint.sol

cp -f build/solc/EntryPoint.abi abi/EntryPoint.abi.json
cp -f build/solc/EntryPoint.bin bin/EntryPoint.bin

test -s abi/EntryPoint.abi.json
test -s bin/EntryPoint.bin

echo "Artifacts:"
ls -la abi bin | sed -n '1,200p'
