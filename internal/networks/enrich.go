package networks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quantumauth-io/quantum-auth-client/internal/shared"
)

var chainDefaults = map[string]struct {
	Name     string
	Explorer string
}{
	// Ethereum
	"0x1":      {"mainnet", "https://etherscan.io"},
	"0xaa36a7": {"sepolia", "https://sepolia.etherscan.io"},
	"0x4268":   {"holesky", "https://holesky.etherscan.io"},

	// Layer 2s (Ethereum-aligned)
	"0xa4b1":  {"arbitrum", "https://arbiscan.io"},
	"0x66eed": {"arbitrum-sepolia", "https://sepolia.arbiscan.io"},

	"0xa":      {"optimism", "https://optimistic.etherscan.io"},
	"0xaa37dc": {"optimism-sepolia", "https://sepolia-optimistic.etherscan.io"},

	"0x2105":  {"base", "https://basescan.org"},
	"0x14a34": {"base-sepolia", "https://sepolia.basescan.org"},

	"0x89":    {"polygon", "https://polygonscan.com"},
	"0x13881": {"polygon-mumbai", "https://mumbai.polygonscan.com"},

	// zkEVM
	"0x44d": {"zkevm", "https://zkevm.polygonscan.com"},
	"0x5a2": {"zkevm-testnet", "https://testnet-zkevm.polygonscan.com"},

	// Scroll
	"0x82750": {"scroll", "https://scrollscan.com"},
	"0x8274f": {"scroll-sepolia", "https://sepolia.scrollscan.com"},
}

// v0.8.0 EntryPoint (validate by checking code)
const entryPointV080 = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"

func (m *Manager) ethGetCode(ctx context.Context, rpcURL, addr string) (string, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return "", fmt.Errorf("missing rpc url")
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("missing address")
	}

	client := &http.Client{Timeout: 7 * time.Second}

	body, _ := json.Marshal(rpcReq{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_getCode",
		Params:  []any{addr, "latest"},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var rr rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", fmt.Errorf("rpc decode: %w", err)
	}
	if rr.Error != nil {
		return "", fmt.Errorf("rpc eth_getCode error: %s", rr.Error.Message)
	}

	var code string
	if err := json.Unmarshal(rr.Result, &code); err != nil {
		return "", fmt.Errorf("rpc eth_getCode result: %w", err)
	}
	return strings.TrimSpace(strings.ToLower(code)), nil
}

func (m *Manager) detectEntryPointV080(ctx context.Context, rpcURL string) (string, bool, error) {
	code, err := m.ethGetCode(ctx, rpcURL, entryPointV080)
	if err != nil {
		return "", false, err
	}
	if code == "" || code == "0x" {
		return "", false, nil
	}
	return entryPointV080, true, nil
}

func (m *Manager) EnrichByChain(ctx context.Context, meta shared.NetworkMetadataOut) shared.NetworkMetadataOut {
	// 1) if in networks.json already, use it
	if strings.TrimSpace(meta.ChainIdHex) != "" {
		if n, found, _ := m.FindByChainIdHex(ctx, meta.ChainIdHex); found {
			if meta.Name == "" {
				meta.Name = n.Name
			}
			if meta.Explorer == "" {
				meta.Explorer = n.Explorer
			}
			if meta.EntryPoint == "" {
				meta.EntryPoint = n.EntryPoint
			}
		}
	}

	// 2) fallback to built-in mapping
	if meta.Name == "" || meta.Explorer == "" {
		if d, ok := chainDefaults[strings.ToLower(meta.ChainIdHex)]; ok {
			if meta.Name == "" {
				meta.Name = d.Name
			}
			if meta.Explorer == "" {
				meta.Explorer = d.Explorer
			}
		}
	}

	// 3) detect entrypoint v0.8.0 by checking code on-chain
	if meta.EntryPoint == "" && strings.TrimSpace(meta.RpcUrl) != "" {
		if ep, ok, err := m.detectEntryPointV080(ctx, meta.RpcUrl); err == nil && ok {
			meta.EntryPoint = ep
		}
		// If err != nil, we silently ignore here so the UI can still fill chainId/name/explorer.
		// If you prefer surfacing errors, return it in metadata handler instead.
	}

	return meta
}
