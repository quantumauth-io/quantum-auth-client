package networks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/helpers"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/shared"
)

func (m *Manager) ProbeRPC(ctx context.Context, rpcURL string) (shared.NetworkMetadataOut, error) {
	out := shared.NetworkMetadataOut{RpcUrl: strings.TrimSpace(rpcURL)}
	if out.RpcUrl == "" {
		return out, fmt.Errorf("missing rpcUrl")
	}

	u, err := url.Parse(out.RpcUrl)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return out, fmt.Errorf("invalid rpcUrl")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return out, fmt.Errorf("unsupported rpcUrl scheme: %s", u.Scheme)
	}

	// small timeout so UI feels snappy
	httpClient := &http.Client{Timeout: 7 * time.Second}

	call := func(method string, params any) (json.RawMessage, error) {
		body, _ := json.Marshal(rpcReq{
			JSONRPC: "2.0",
			ID:      1,
			Method:  method,
			Params:  params,
		})

		req, err := http.NewRequestWithContext(ctx, "POST", out.RpcUrl, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var rr rpcResp
		if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
			return nil, fmt.Errorf("rpc decode: %w", err)
		}
		if rr.Error != nil {
			return nil, fmt.Errorf("rpc %s error: %s", method, rr.Error.Message)
		}
		return rr.Result, nil
	}

	// eth_chainId (hex quantity)
	{
		raw, err := call("eth_chainId", []any{})
		if err != nil {
			return out, err
		}
		var chainHex string
		if err := json.Unmarshal(raw, &chainHex); err != nil {
			return out, fmt.Errorf("eth_chainId: %w", err)
		}
		chainHex = strings.ToLower(helpers.NormalizeHex0x(strings.TrimSpace(chainHex)))
		out.ChainIdHex = chainHex

		// convert to int64
		bi, ok := new(big.Int).SetString(strings.TrimPrefix(chainHex, "0x"), 16)
		if ok {
			out.ChainId = bi.Int64()
		}
	}

	// net_version (decimal string) – optional
	{
		raw, err := call("net_version", []any{})
		if err == nil {
			var decStr string
			if json.Unmarshal(raw, &decStr) == nil {
				if v, perr := strconv.ParseInt(strings.TrimSpace(decStr), 10, 64); perr == nil && out.ChainId == 0 {
					out.ChainId = v
				}
			}
		}
	}

	// web3_clientVersion – optional
	{
		raw, err := call("web3_clientVersion", []any{})
		if err == nil {
			var cv string
			if json.Unmarshal(raw, &cv) == nil {
				out.ClientVersion = strings.TrimSpace(cv)
			}
		}
	}

	// latest block – optional (good sanity)
	{
		raw, err := call("eth_getBlockByNumber", []any{"latest", false})
		if err == nil {
			var blk struct {
				Number string `json:"number"`
			}
			if json.Unmarshal(raw, &blk) == nil {
				out.LatestBlockHex = strings.ToLower(helpers.NormalizeHex0x(strings.TrimSpace(blk.Number)))
			}
		}
	}

	return out, nil
}
