package pages

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func WalletPage(ctx context.Context, st *state.AppState, refresh func()) fyne.CanvasObject {
	// Stable header widgets (do NOT recreate on refresh).
	netInfoLbl := widget.NewLabel("")
	netSelect := widget.NewSelect([]string{}, nil)

	header := container.NewVBox(
		widget.NewForm(widget.NewFormItem(st.T("wallet.network.label"), netSelect)),
		netInfoLbl,
		widget.NewSeparator(),
	)

	body := container.NewVBox()
	loader := newBalanceLoader()

	// Refresh ONLY rebuilds body; header stays stable -> Select popup stops being flaky.
	refresh = func() {
		body.Objects = []fyne.CanvasObject{
			buildWalletBody(ctx, st, loader, refresh),
		}
		body.Refresh()
	}

	root := container.NewVBox(header, body)

	// Init header once (async).
	go func() {
		// Ensure runtime so SnapshotWeb3 can succeed
		if err := st.EnsureWalletRuntime(ctx); err != nil {
			fyne.Do(refresh)
			return
		}

		web3, ok, err := st.SnapshotWeb3(ctx)
		if err != nil || !ok || web3.Chains == nil || web3.Networks == nil {
			fyne.Do(refresh)
			return
		}

		// Populate networks list
		nets, err := web3.Networks.ListFromFile(ctx)
		if err != nil {
			st.Log.Addf("networks list error: %v", err)
			fyne.Do(refresh)
			return
		}

		opts := make([]string, 0, len(nets))
		exists := make(map[string]struct{}, len(nets))
		for _, n := range nets {
			name := strings.TrimSpace(n.Name)
			if name == "" {
				name = fmt.Sprintf(st.T("wallet.network.fallback_chain"), n.ChainID)
			}
			opts = append(opts, name)
			exists[strings.ToLower(name)] = struct{}{}
		}
		if len(opts) == 0 {
			fyne.Do(refresh)
			return
		}

		// Default selection: active network if present, else first.
		selected := opts[0]
		if active, aerr := web3.Chains.ActiveNetwork(); aerr == nil && strings.TrimSpace(active) != "" {
			if _, ok := exists[strings.ToLower(active)]; ok {
				selected = active
			}
		}

		updateNetInfo := func() {
			netName, err := web3.Chains.ActiveNetwork()
			if err != nil || strings.TrimSpace(netName) == "" {
				netInfoLbl.SetText(st.T("wallet.network.active_none"))
				return
			}

			rc, rerr := web3.Chains.ResolveNetworkByName(netName)
			if rerr != nil {
				netInfoLbl.SetText(st.T("wallet.network.active_prefix") + netName)
				return
			}

			netInfoLbl.SetText(st.T("wallet.network.active_fmt", map[string]any{
				"network": rc.NetworkName,
				"chainId": rc.ChainID,
				"rpc":     rc.RPCName,
			}))
		}

		fyne.Do(func() {
			netSelect.Options = opts
			netSelect.Refresh()

			netSelect.OnChanged = func(choice string) {
				choice = strings.TrimSpace(choice)
				if choice == "" {
					return
				}

				// disable to avoid weird double taps
				netSelect.Disable()

				go func() {
					if err := web3.Chains.SwitchChain(ctx, choice); err != nil {
						st.Log.Addf("switch chain failed (%s): %v", choice, err)
						fyne.Do(func() { netSelect.Enable() })
						return
					}

					// Let the select popup settle before rebuilding widgets.
					time.Sleep(50 * time.Millisecond)

					fyne.Do(func() {
						netSelect.Enable()
						updateNetInfo()
						refresh()
					})
				}()
			}

			netSelect.SetSelected(selected)
			updateNetInfo()

			// Build body after header is ready.
			refresh()
		})
	}()

	return container.NewPadded(root)
}

func buildWalletBody(ctx context.Context, st *state.AppState, loader *balanceLoader, refresh func()) fyne.CanvasObject {
	// Keep init logic centralized here too; if user locks/unlocks, UI remains correct.
	if err := st.EnsureWalletRuntime(ctx); err != nil {
		switch {
		case errors.Is(err, state.ErrWalletsNotCreated):
			return WalletSetupCard(ctx, st, refresh)

		case errors.Is(err, state.ErrUnlockRequired) || strings.Contains(strings.ToLower(err.Error()), "unlock"):
			return widget.NewLabel(st.T("wallet.unlock_required"))

		default:
			st.Log.Addf("wallet runtime init failed: %v", err)
			return widget.NewLabel(st.T("wallet.runtime_error"))
		}
	}

	web3, ok, err := st.SnapshotWeb3(ctx)
	if err != nil {
		st.Log.Addf("web3 snapshot error: %v", err)
		return widget.NewLabel(st.T("wallet.web3_error"))
	}
	if !ok || web3.Chains == nil || web3.Assets == nil || web3.Networks == nil || web3.OnChain == nil || web3.CWStore == nil {
		return widget.NewLabel(st.T("wallet.web3_not_ready"))
	}
	if web3.OnChain.User == nil || web3.OnChain.Device == nil {
		return widget.NewLabel(st.T("wallet.wallets_not_ready"))
	}

	// Keep AA config aligned with active chain.
	_ = web3.OnChain.LoadContractForCurrentChain(ctx, web3.CWStore)

	userAddr := web3.OnChain.User.Address()
	deviceAddr := web3.OnChain.Device.Address()

	userBalLbl := widget.NewLabel(st.T("wallet.balance_loading"))
	deviceBalLbl := widget.NewLabel(st.T("wallet.balance_loading"))
	contractBalLbl := widget.NewLabel("")

	userCard := sectionCard(
		st.T("wallet.user.title"),
		[]fyne.CanvasObject{
			addrRow(st.T("wallet.address.label"), userAddr.Hex(), st),
			userBalLbl,
		},
	)

	deviceCard := sectionCard(
		st.T("wallet.device.title"),
		[]fyne.CanvasObject{
			addrRow(st.T("wallet.address.label"), deviceAddr.Hex(), st),
			deviceBalLbl,
		},
	)

	contractCard := buildContractSection(ctx, st, web3, contractBalLbl, refresh)

	userHandle := newBalanceHandle()
	deviceHandle := newBalanceHandle()
	contractHandle := newBalanceHandle()

	loader.LoadNative(ctx, st, web3, userHandle, userAddr, userBalLbl)
	loader.LoadNative(ctx, st, web3, deviceHandle, deviceAddr, deviceBalLbl)

	if addr, aerr := web3.OnChain.ContractAddress(); aerr == nil {
		loader.LoadNative(ctx, st, web3, contractHandle, addr, contractBalLbl)
	} else {
		fyne.Do(func() { contractBalLbl.SetText("") })
	}

	return container.NewVBox(
		userCard,
		widget.NewSeparator(),
		deviceCard,
		widget.NewSeparator(),
		contractCard,
	)
}

func buildContractSection(
	ctx context.Context,
	st *state.AppState,
	web3 clienthttp.Web3Snapshot,
	contractBal *widget.Label,
	refresh func(),
) fyne.CanvasObject {
	_ = web3.OnChain.LoadContractForCurrentChain(ctx, web3.CWStore)

	addr, err := web3.OnChain.ContractAddress()
	if err == nil {
		return sectionCard(
			st.T("wallet.contract.title"),
			[]fyne.CanvasObject{
				addrRow(st.T("wallet.contract.account"), addr.Hex(), st),
				widget.NewLabel(st.T("wallet.contract.status_configured")),
				contractBal,
				widget.NewButton(st.T("wallet.contract.validate_chain"), func() {
					if err := web3.OnChain.ValidateChain(ctx); err != nil {
						st.Log.Addf("AA validate chain failed: %v", err)
						return
					}
					st.Log.Addf("AA validate chain OK (account=%s)", addr.Hex())
				}),
			},
		)
	}

	if !errors.Is(err, contractwallet.ErrContractNotConfigured) {
		return sectionCard(
			st.T("wallet.contract.title"),
			[]fyne.CanvasObject{
				widget.NewLabel(st.T("wallet.contract.status_error")),
				widget.NewLabel(err.Error()),
			},
		)
	}

	recovery := widget.NewEntry()
	recovery.SetPlaceHolder(st.T("wallet.contract.recovery_placeholder"))
	recovery.Validator = func(s string) error {
		ss := strings.TrimSpace(s)
		if ss == "" {
			return errors.New("required")
		}
		if !common.IsHexAddress(ss) {
			return errors.New("invalid address")
		}
		return nil
	}

	activeNetLbl := widget.NewLabel(st.T("wallet.contract.network_loading"))

	if n, nerr := web3.Chains.ActiveNetwork(); nerr == nil && strings.TrimSpace(n) != "" {
		activeNetLbl.SetText(st.T("wallet.contract.network_prefix") + n)
	} else {
		activeNetLbl.SetText(st.T("wallet.contract.network_none"))
	}

	var busy bool
	var deployBtn *widget.Button

	deployBtn = widget.NewButton(st.T("wallet.contract.deploy_btn"), func() {
		if busy {
			return
		}
		if web3.Deployer == nil {
			st.Log.Addf("AA deploy error: deployer not available")
			return
		}
		if err := recovery.Validate(); err != nil {
			st.Log.Addf("AA deploy invalid recovery address: %v", err)
			return
		}

		netName, nerr := web3.Chains.ActiveNetwork()
		if nerr != nil || strings.TrimSpace(netName) == "" {
			st.Log.Addf("AA deploy error: no active network selected")
			return
		}

		rc, rerr := web3.Chains.ResolveNetworkByName(netName)
		if rerr != nil {
			st.Log.Addf("AA deploy error: resolve active network %q failed: %v", netName, rerr)
			return
		}
		chainHex := strings.TrimSpace(strings.ToLower(rc.ChainIDHex))
		if chainHex == "" {
			st.Log.Addf("AA deploy error: active network %q missing chainIdHex", netName)
			return
		}

		busy = true
		deployBtn.Disable()

		recoveryAddr := strings.TrimSpace(recovery.Text)

		go func() {
			res, derr := web3.Deployer.DeployAAOnChainIDHex(ctx, chainHex, recoveryAddr)

			fyne.Do(func() {
				busy = false
				deployBtn.Enable()

				if derr != nil {
					st.Log.Addf("AA deploy failed: %v", derr)
					return
				}

				_ = web3.OnChain.LoadContractForCurrentChain(ctx, web3.CWStore)

				if res.AlreadyDeployed {
					st.Log.Addf(
						"AA already deployed (network=%s chainIdHex=%s account=%s tpmVerifier=%s)",
						res.NetworkName,
						res.ChainIDHex,
						res.AccountAddress.Hex(),
						res.TPMVerifierAddress.Hex(),
					)
				} else {
					st.Log.Addf(
						"AA deployed (network=%s chainIdHex=%s account=%s accountTx=%s tpmVerifier=%s tpmTx=%s)",
						res.NetworkName,
						res.ChainIDHex,
						res.AccountAddress.Hex(),
						res.AccountTxHash.Hex(),
						res.TPMVerifierAddress.Hex(),
						res.TPMVerifierTxHash.Hex(),
					)
				}

				refresh()
			})
		}()
	})

	return sectionCard(
		st.T("wallet.contract.title"),
		[]fyne.CanvasObject{
			widget.NewLabel(st.T("wallet.contract.status_not_configured")),
			widget.NewLabel(st.T("wallet.contract.deploy_hint")),
			activeNetLbl,
			recovery,
			deployBtn,
		},
	)
}

// -------------------- Balance loading (stale-result safe, PER LABEL) --------------------

type balanceLoader struct{}

func newBalanceLoader() *balanceLoader { return &balanceLoader{} }

// balanceHandle is per-label "latest wins" state.
type balanceHandle struct {
	gen atomic.Uint64
}

func newBalanceHandle() *balanceHandle { return &balanceHandle{} }

func (b *balanceLoader) LoadNative(
	ctx context.Context,
	st *state.AppState,
	web3 clienthttp.Web3Snapshot,
	handle *balanceHandle,
	owner common.Address,
	lbl *widget.Label,
) {
	myGen := handle.gen.Add(1)

	fyne.Do(func() { lbl.SetText(st.T("wallet.balance_loading")) })

	go func() {
		time.Sleep(30 * time.Millisecond)

		netName, err := web3.Chains.ActiveNetwork()
		if err != nil || strings.TrimSpace(netName) == "" {
			if handle.gen.Load() != myGen {
				return
			}
			fyne.Do(func() { lbl.SetText(st.T("wallet.balance_no_active_network")) })
			return
		}

		wei, err := web3.Assets.BalanceOf(ctx, netName, common.HexToAddress(constants.NativeAddr), owner)
		if handle.gen.Load() != myGen {
			return
		}

		if err != nil {
			st.Log.Addf("balance fetch failed (net=%s owner=%s): %v", netName, owner.Hex(), err)
			fyne.Do(func() { lbl.SetText(st.T("wallet.balance_error")) })
			return
		}

		fyne.Do(func() {
			lbl.SetText(st.T("wallet.balance_fmt", map[string]any{
				"amount": formatEthFromWei(wei),
			}))
		})
	}()
}

func formatEthFromWei(wei *big.Int) string {
	if wei == nil || wei.Sign() == 0 {
		return "0"
	}
	r := new(big.Rat).SetInt(wei)
	den := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	r.Quo(r, den)
	return r.FloatString(6)
}

// -------------------- UI helpers --------------------

func sectionCard(title string, body []fyne.CanvasObject) fyne.CanvasObject {
	h := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	items := []fyne.CanvasObject{h}
	items = append(items, body...)
	return container.NewPadded(container.NewVBox(items...))
}

func addrRow(label, value string, st *state.AppState) fyne.CanvasObject {
	l := widget.NewLabel(label)
	v := widget.NewEntry()
	v.SetText(value)
	v.Disable()

	copyBtn := widget.NewButton(st.T("wallet.copy_btn"), func() {
		fyne.CurrentApp().Clipboard().SetContent(value)
	})

	return container.NewBorder(nil, nil, l, copyBtn, v)
}
