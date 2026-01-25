package pages

import (
	"context"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/ui/components"

	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

const (
	modeNew = "setup.register.mode.new"
	modeAdd = "setup.register.mode.add"
)

func SetupPage(ctx context.Context, st *state.AppState, refresh func()) fyne.CanvasObject {
	content := container.NewVBox()

	content.Objects = []fyne.CanvasObject{
		buildSetupContent(ctx, st, refresh),
	}

	return container.NewPadded(content)
}

func buildSetupContent(ctx context.Context, st *state.AppState, refresh func()) fyne.CanvasObject {
	payload, ok := st.VaultPayloadCopy()
	if !ok {
		return widget.NewLabel(st.T("setup.vault_not_loaded"))
	}

	// Case 4: both completed -> only pairing
	if payload.Flags.WalletCreated && payload.Flags.RegistrationCompleted {
		return extensionPairingCard(ctx, st, payload, refresh)
	}

	// Case 2: registration completed, wallet not -> wallet + pairing
	if payload.Flags.RegistrationCompleted && !payload.Flags.WalletCreated {
		return container.NewVBox(
			WalletSetupCard(ctx, st, refresh),
			extensionPairingCard(ctx, st, payload, refresh),
		)
	}

	// Case 3: wallet completed, registration not -> registration only
	if payload.Flags.WalletCreated && !payload.Flags.RegistrationCompleted {
		return container.NewVBox(
			registerSetupCard(ctx, st, payload, refresh),
		)
	}

	// Case 1: nothing completed -> wallet + registration
	return container.NewVBox(
		widget.NewLabelWithStyle(st.T("setup.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(st.T("setup.intro")),
		widget.NewSeparator(),
		WalletSetupCard(ctx, st, refresh),
		registerSetupCard(ctx, st, payload, refresh),
	)
}

func WalletSetupCard(ctx context.Context, st *state.AppState, refresh func()) fyne.CanvasObject {
	status := widget.NewLabel("")

	var btn *widget.Button

	btn = widget.NewButton(st.T("setup.wallet.button"), func() {
		btn.Disable()
		status.SetText(st.T("setup.wallet.creating"))

		go func() {
			pw := st.Password()
			if strings.TrimSpace(pw) == "" {
				fyne.Do(func() {
					btn.Enable()
					status.SetText(st.T("setup.wallet.unlock_missing"))
				})
				return
			}

			// Explicit wallet creation (user action)
			if err := st.CreateWallets(ctx); err != nil {
				st.Log.Addf("wallet create error: %v", err)
				fyne.Do(func() {
					btn.Enable()
					status.SetText(st.T("setup.wallet.error", map[string]any{"Error": err.Error()}))
				})
				return
			}

			st.Log.Addf("Wallet created")
			fyne.Do(func() {
				status.SetText(st.T("setup.wallet.created"))
				refresh()
			})
		}()
	})

	card := container.NewVBox(
		widget.NewLabelWithStyle(st.T("setup.wallet.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(st.T("setup.wallet.description")),
		btn,
		status,
	)
	return container.NewPadded(card)
}

func registerSetupCard(ctx context.Context, st *state.AppState, payload state.VaultPayload, refresh func()) fyne.CanvasObject {

	modeLabel := widget.NewLabelWithStyle(st.T("setup.register.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	help := widget.NewLabel(st.T("setup.register.help"))

	username := widget.NewEntry()
	username.SetPlaceHolder(st.T("setup.register.username_placeholder"))
	username.SetText(payload.Settings.Username)

	email := widget.NewEntry()
	email.SetPlaceHolder(st.T("setup.register.email_placeholder"))
	email.SetText(payload.Settings.Email)

	deviceLabel := widget.NewEntry()
	deviceLabel.SetPlaceHolder(st.T("setup.register.device_label_placeholder"))
	deviceLabel.SetText(payload.Settings.DeviceLabel)

	status := widget.NewLabel("")

	modeGroup := components.NewKeyedRadioGroup(
		[]string{modeNew, modeAdd},
		func(k string) string { return st.T(k) },
		func(_ string) { status.SetText("") },
	)
	modeGroup.Radio.Horizontal = true

	modeGroup.SetSelectedKey(modeNew)

	var submit *widget.Button
	submit = widget.NewButton(st.T("setup.register.continue"), func() {
		emailValue := strings.TrimSpace(email.Text)
		deviceLabelValue := strings.TrimSpace(deviceLabel.Text)
		usernameValue := strings.TrimSpace(username.Text)

		if emailValue == "" {
			status.SetText(st.T("setup.register.email_required"))
			return
		}

		if usernameValue == "" {
			status.SetText(st.T("setup.register.username_required"))
			return
		}

		if deviceLabelValue == "" {
			deviceLabelValue = "default-device"
		}

		submit.Disable()
		status.SetText(st.T("setup.register.registering"))

		go func() {
			// Persist settings right away (even if backend fails).
			_ = st.UpdateVault(func(p *state.VaultPayload) {
				p.Settings.Email = emailValue
				p.Settings.Username = usernameValue
				p.Settings.DeviceLabel = deviceLabelValue
			})

			var outUserID, outDeviceID string
			var err error

			switch modeGroup.SelectedKey {
			case modeNew:
				outUserID, outDeviceID, err = st.RegisterNewAccount(ctx, emailValue, usernameValue, deviceLabelValue)
			case modeAdd:
				outUserID, outDeviceID, err = st.AddDeviceToAccount(ctx, emailValue, deviceLabelValue)
			default:
				err = fmt.Errorf("unknown mode")
			}

			if err != nil {
				st.Log.Addf("registration failed: %v", err)
				fyne.Do(func() {
					submit.Enable()

					status.SetText(st.T("setup.register.failed", map[string]any{"Error": err.Error()}))
				})
				return
			}

			// Persist identity + flag in vault
			err = st.UpdateVault(func(p *state.VaultPayload) {
				p.Settings.Email = emailValue
				p.Settings.Username = usernameValue
				p.Settings.DeviceLabel = deviceLabelValue
				p.Identity = &state.VaultIdentity{UserID: outUserID, DeviceID: outDeviceID}
				p.Flags.RegistrationCompleted = true
			})
			if err != nil {
				st.Log.Addf("vault save error: %v", err)
				fyne.Do(func() {
					submit.Enable()

					status.SetText(st.T("setup.register.save_failed", map[string]any{"Error": err.Error()}))
				})
				return
			}

			st.Log.Addf("Registration completed (user=%s device=%s)", outUserID, outDeviceID)
			fyne.Do(func() {
				status.SetText(st.T("setup.register.done"))
				refresh()
			})
		}()
	})

	card := container.NewVBox(
		modeLabel,
		help,
		modeGroup.Radio,
		widget.NewSeparator(),
		username,
		email,
		deviceLabel,
		submit,
		status,
	)
	return container.NewPadded(card)
}

func extensionPairingCard(ctx context.Context, st *state.AppState, payload state.VaultPayload, refresh func()) fyne.CanvasObject {
	title := widget.NewLabelWithStyle(st.T("setup.pair.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	help := widget.NewLabel(st.T("setup.pair.help"))

	tokenEntry := widget.NewEntry()
	tokenEntry.SetPlaceHolder(st.T("setup.pair.token_placeholder"))
	tokenEntry.Disable()

	// Pre-fill if already generated
	if strings.TrimSpace(payload.PairToken) != "" {
		tokenEntry.SetText(payload.PairToken)
	}

	status := widget.NewLabel("")

	copyBtn := widget.NewButton(st.T("setup.pair.copy"), func() {
		tok := strings.TrimSpace(tokenEntry.Text)
		if tok == "" {
			status.SetText(st.T("setup.pair.no_token"))
			return
		}
		fyne.CurrentApp().Clipboard().SetContent(tok)
		status.SetText(st.T("setup.pair.copied"))
	})
	copyBtn.Disable()
	if strings.TrimSpace(tokenEntry.Text) != "" {
		copyBtn.Enable()
	}

	var genBtn *widget.Button

	genBtn = widget.NewButton(st.T("setup.pair.generate"), func() {
		genBtn.Disable()
		status.SetText(st.T("setup.pair.generating"))

		go func() {
			tok, err := state.GeneratePairToken()
			if err != nil {
				st.Log.Addf("pair token generate error: %v", err)
				fyne.Do(func() {
					genBtn.Enable()
					status.SetText(st.T("setup.pair.error", map[string]any{"Error": err.Error()}))
				})
				return
			}

			// Store in vault
			if err := st.UpdateVault(func(p *state.VaultPayload) {
				p.PairToken = tok
				p.Flags.PairTokenGenerated = true
			}); err != nil {
				st.Log.Addf("pair token save error: %v", err)
				fyne.Do(func() {
					genBtn.Enable()
					status.SetText(st.T("setup.pair.save_error", map[string]any{"Error": err.Error()}))
				})
				return
			}

			fyne.Do(func() {
				tokenEntry.SetText(tok)
				copyBtn.Enable()
				genBtn.Enable()
				status.SetText(st.T("setup.pair.generated"))
				refresh()
			})
		}()
	})

	// If token already exists, copy should be enabled and generate can be “Regenerate”
	if strings.TrimSpace(payload.PairToken) != "" {
		genBtn.SetText(st.T("setup.pair.regenerate"))
	}

	card := container.NewVBox(
		title,
		help,
		widget.NewSeparator(),
		tokenEntry,
		container.NewHBox(genBtn, copyBtn),
		status,
	)

	return container.NewPadded(card)
}
