package pages

import (
	"context"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func SettingsPage(ctx context.Context, st *state.AppState, refresh func()) fyne.CanvasObject {

	s := st.GUISettings
	s = state.NormalizeGUISettings(s)

	langSelect := widget.NewSelect([]string{"English", "Français"}, func(_ string) {})
	if s.Language == "fr" {
		langSelect.SetSelected("Français")
	} else {
		langSelect.SetSelected("English")
	}

	server := widget.NewEntry()
	server.SetPlaceHolder(st.T("settings.placeholder.server_url"))
	server.SetText(s.ServerURL)

	qaEnv := widget.NewSelect([]string{"", "prod", "dev", "local"}, func(_ string) {})
	qaEnv.SetSelected(s.QAEnv)

	localHost := widget.NewEntry()
	localHost.SetPlaceHolder(st.T("settings.placeholder.local_host"))
	localHost.SetText(s.LocalHost)

	port := widget.NewEntry()
	port.SetPlaceHolder(st.T("settings.placeholder.port"))
	port.SetText(s.Port)

	email := widget.NewEntry()
	email.SetPlaceHolder(st.T("settings.placeholder.email"))
	email.SetText(s.Email)

	deviceLabel := widget.NewEntry()
	deviceLabel.SetPlaceHolder(st.T("settings.placeholder.device_label"))
	deviceLabel.SetText(s.DeviceLabel)

	infura := widget.NewEntry()
	infura.SetPlaceHolder(st.T("settings.placeholder.infura_key"))
	infura.SetText(s.InfuraKey)

	activeNetwork := widget.NewEntry()
	activeNetwork.SetPlaceHolder(st.T("settings.placeholder.active_network"))
	activeNetwork.SetText(s.ActiveNetwork)

	activeRPC := widget.NewEntry()
	activeRPC.SetPlaceHolder(st.T("settings.placeholder.active_rpc"))
	activeRPC.SetText(s.ActiveRPC)

	pqLabel := widget.NewEntry()
	pqLabel.SetPlaceHolder(state.DefaultPQLabel)
	pqLabel.SetText(s.PQLabel)

	tpmOwnerAuth := widget.NewPasswordEntry()
	tpmOwnerAuth.SetPlaceHolder(st.T("settings.placeholder.tpm_owner_auth"))
	tpmOwnerAuth.SetText(s.TPMOwnerAuth)

	status := widget.NewLabel("")

	// Live apply language when selection changes
	langSelect.OnChanged = func(selected string) {
		var code string
		if selected == "Français" {
			code = "fr"
		} else {
			code = "en"
		}
		// Persist in vault
		if err := st.UpdateVault(func(p *state.VaultPayload) {
			p.Settings.Language = code
			fyne.CurrentApp().Preferences().SetString("language", code)
		}); err != nil {
			status.SetText(st.T("settings.status.save_failed", map[string]any{"Error": err.Error()}))
			return
		}

		// Apply immediately (swap translator)
		if err := st.ApplyLanguage(code); err != nil {
			status.SetText(st.T("settings.status.init_failed", map[string]any{"Error": err.Error()}))
			return
		}

		// Rebuild this page so labels/placeholders update right now
		status.SetText(st.T("settings.status.saved"))
		refresh()
	}

	saveBtn := widget.NewButton(st.T("settings.button.save"), func() {
		// If vault isn’t loaded, UpdateVault will tell us.
		err := st.UpdateVault(func(p *state.VaultPayload) {
			p.Settings.ServerURL = strings.TrimSpace(server.Text)
			p.Settings.QAEnv = strings.TrimSpace(qaEnv.Selected)

			p.Settings.LocalHost = strings.TrimSpace(localHost.Text)
			p.Settings.Port = strings.TrimSpace(port.Text)

			p.Settings.Email = strings.TrimSpace(email.Text)
			p.Settings.DeviceLabel = strings.TrimSpace(deviceLabel.Text)

			p.Settings.InfuraKey = strings.TrimSpace(infura.Text)

			p.Settings.ActiveNetwork = strings.TrimSpace(activeNetwork.Text)
			p.Settings.ActiveRPC = strings.TrimSpace(activeRPC.Text)

			p.Settings.PQLabel = strings.TrimSpace(pqLabel.Text)
			p.Settings.TPMOwnerAuth = strings.TrimSpace(tpmOwnerAuth.Text)
		})

		if err != nil {
			status.SetText(st.T("settings.status.save_failed", map[string]any{"Error": err.Error()}))
			return
		}

		// reflect normalization back into UI
		ns := state.NormalizeGUISettings(st.GUISettings)
		server.SetText(ns.ServerURL)
		qaEnv.SetSelected(ns.QAEnv)
		localHost.SetText(ns.LocalHost)
		port.SetText(ns.Port)
		email.SetText(ns.Email)
		deviceLabel.SetText(ns.DeviceLabel)
		infura.SetText(ns.InfuraKey)
		activeNetwork.SetText(ns.ActiveNetwork)
		activeRPC.SetText(ns.ActiveRPC)
		pqLabel.SetText(ns.PQLabel)
		tpmOwnerAuth.SetText(ns.TPMOwnerAuth)

		status.SetText(st.T("settings.status.saved"))
		st.Log.Addf("Settings saved (env=%s pqLabel=%s)", ns.QAEnv, ns.PQLabel)
	})

	initBtn := widget.NewButton(st.T("settings.button.init_runtime"), func() {
		status.SetText(st.T("settings.status.initializing"))
		go func() {
			err := st.InitRuntime(ctx)
			if err != nil {
				st.Log.Addf("Init failed: %v", err)
				fyne.Do(func() { status.SetText(st.T("settings.status.init_failed", map[string]any{"Error": err.Error()})) })
				return
			}
			fyne.Do(func() { status.SetText(st.T("settings.status.runtime_ready")) })
		}()
	})

	form := widget.NewForm(
		widget.NewFormItem(st.T("settings.form.language"), langSelect),
		widget.NewFormItem(st.T("settings.form.qa_env"), qaEnv),
		widget.NewFormItem(st.T("settings.form.server_url"), server),
		widget.NewFormItem(st.T("settings.form.local_host"), localHost),
		widget.NewFormItem(st.T("settings.form.port"), port),

		widget.NewFormItem(st.T("settings.form.email"), email),
		widget.NewFormItem(st.T("settings.form.device_label"), deviceLabel),

		widget.NewFormItem(st.T("settings.form.infura_key"), infura),
		widget.NewFormItem(st.T("settings.form.active_network"), activeNetwork),
		widget.NewFormItem(st.T("settings.form.active_rpc"), activeRPC),

		widget.NewFormItem(st.T("settings.form.pq_label"), pqLabel),
		widget.NewFormItem(st.T("settings.form.tpm_owner_auth"), tpmOwnerAuth),
	)

	return container.NewVBox(
		form,
		container.NewHBox(saveBtn, initBtn),
		status,
	)
}
