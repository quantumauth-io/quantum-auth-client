package pages

import (
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func LockOrSetupScreen(st *state.AppState, onUnlocked func()) fyne.CanvasObject {
	exists, err := state.VaultExists()
	if err != nil {
		return container.NewCenter(
			widget.NewLabel(st.T("lock.vault.error", map[string]any{"Error": err.Error()})),
		)
	}
	if !exists {
		return SetupPasswordScreen(st, onUnlocked)
	}
	return UnlockScreen(st, onUnlocked)
}

func SetupPasswordScreen(st *state.AppState, onUnlocked func()) fyne.CanvasObject {

	osLang := state.DetectOSLanguage()

	pw1 := widget.NewPasswordEntry()
	pw1.SetPlaceHolder(st.T("lock.set_password.pw1"))
	pw2 := widget.NewPasswordEntry()
	pw2.SetPlaceHolder(st.T("lock.set_password.pw2"))

	status := widget.NewLabel("")

	create := func() {
		p1 := strings.TrimSpace(pw1.Text)
		p2 := strings.TrimSpace(pw2.Text)

		if p1 == "" || p2 == "" {
			status.SetText(st.T("error.password_required"))
			return
		}
		if p1 != p2 {
			status.SetText(st.T("error.password_mismatch"))
			return
		}

		settings := st.GUISettings
		settings.Language = osLang
		settings = state.NormalizeGUISettings(settings)

		payload, err := state.CreateVaultWithPayload(p1, state.VaultPayload{
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Settings:  settings,
		})
		if err != nil {
			status.SetText(err.Error())
			return
		}
		st.SetPassword(p1)
		pw1.SetText("")
		pw2.SetText("")
		status.SetText("")
		st.SetVaultPayload(payload)
		state.ApplyQAEnvToProcess(payload.Settings.QAEnv)
		onUnlocked()
	}

	btn := widget.NewButton(st.T("lock.set_password.cta"), create)
	pw2.OnSubmitted = func(_ string) { create() }

	card := container.NewVBox(
		widget.NewLabelWithStyle(st.T("lock.set_password.title"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel(st.T("lock.set_password.subtitle")),
		widget.NewSeparator(),
		pw1,
		pw2,
		btn,
		status,
	)

	return container.NewCenter(card)
}

func UnlockScreen(st *state.AppState, onUnlocked func()) fyne.CanvasObject {
	pw := widget.NewPasswordEntry()
	pw.SetPlaceHolder(st.T("lock.unlock.password_placeholder"))

	status := widget.NewLabel("")

	unlock := func() {
		p := strings.TrimSpace(pw.Text)
		if p == "" {
			status.SetText(st.T("error.password_required"))
			return
		}
		payload, err := state.UnlockVault(p)
		if err != nil {
			status.SetText(err.Error())
			return
		}

		st.SetPassword(p)
		st.SetVaultPayload(payload)
		_ = st.ApplyLanguage(payload.Settings.Language)
		fyne.CurrentApp().Preferences().SetString("language", payload.Settings.Language)
		state.ApplyQAEnvToProcess(payload.Settings.QAEnv)
		onUnlocked()
	}

	btn := widget.NewButton(st.T("lock.unlock.cta"), unlock)
	pw.OnSubmitted = func(_ string) { unlock() }

	card := container.NewVBox(
		widget.NewLabelWithStyle(st.T("lock.unlock.title"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		pw,
		btn,
		status,
	)

	return container.NewCenter(card)
}
