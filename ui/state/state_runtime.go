package state

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

type vaultPairTokenProvider struct{ st *AppState }

type chainIDer interface {
	ChainID(ctx context.Context) (*big.Int, error)
}

func (p vaultPairTokenProvider) GetPairToken() (string, bool) {
	payload, ok := p.st.VaultPayloadCopy()
	if !ok {
		return "", false
	}
	tok := strings.TrimSpace(payload.PairToken)
	return tok, tok != ""
}

func ensureCanBind(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
	_ = l.Close()
	return nil
}

func buildDevKeysManager(ownerAuth string) (devkeys.Manager, error) {
	paths, err := securefile.ConfigPathCandidates(constants.AppName, "devkeys_index.json.enc")
	if err != nil {
		return nil, err
	}
	devKeysDir := filepath.Dir(paths[0])

	sealer := tpmdevice.NewSealer(strings.TrimSpace(ownerAuth))
	store := devkeys.NewSecureStore(devKeysDir, sealer, "qa.devkeys", time.Now)

	crypto, err := devkeys.NewCIRCLCryptoMLDSA65()
	if err != nil {
		return nil, err
	}
	return devkeys.New(store, crypto, time.Now), nil
}

func (r *walletRuntime) CloseAll(ctx context.Context) {
	_ = ctx
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.chains != nil {
			_ = r.chains.Close()
		}
	})
}
