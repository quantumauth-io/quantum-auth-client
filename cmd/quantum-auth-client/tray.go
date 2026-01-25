package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"

	"github.com/quantumauth-io/quantum-auth-client/ui/assets"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

type trayController struct {
	desk   desktop.App
	window fyne.Window
	state  *state.AppState

	showLocked func()
	showMain   func()

	statusItem *fyne.MenuItem
	openItem   *fyne.MenuItem
	lockItem   *fyne.MenuItem
	quitItem   *fyne.MenuItem
}

func newTrayController(a fyne.App, w fyne.Window, st *state.AppState) (*trayController, bool) {
	desk, ok := a.(desktop.App)
	if !ok {
		return nil, false
	}

	tc := &trayController{
		desk:   desk,
		window: w,
		state:  st,
	}

	desk.SetSystemTrayIcon(assets.ResourceLogoPng)
	desk.SetSystemTrayWindow(w)

	tc.statusItem = fyne.NewMenuItem("Status: locked", nil)
	tc.statusItem.Disabled = true

	tc.openItem = fyne.NewMenuItem("Open", func() {
		w.Show()
		w.RequestFocus()
	})

	tc.lockItem = fyne.NewMenuItem("Lock", func() {
		st.Lock()
		if tc.showLocked != nil {
			tc.showLocked()
		}
	})

	tc.quitItem = fyne.NewMenuItem("Quit", func() {
		w.Close()
	})

	// initial menu + state
	tc.Update()
	return tc, true
}

func (tc *trayController) BindHooks(showLocked func(), showMain func()) {
	tc.showLocked = showLocked
	tc.showMain = showMain
	tc.Update()
}

func (tc *trayController) buildMenu() *fyne.Menu {
	return fyne.NewMenu(
		"QuantumAuth",
		tc.statusItem,
		fyne.NewMenuItemSeparator(),
		tc.openItem,
		tc.lockItem,
		fyne.NewMenuItemSeparator(),
		tc.quitItem,
	)
}

func (tc *trayController) Update() {
	if tc == nil {
		return
	}

	locked := !tc.state.PasswordSet()

	if locked {
		tc.statusItem.Label = "Status: locked"
		tc.lockItem.Label = "Unlock…"
		tc.lockItem.Action = func() {
			if tc.showLocked != nil {
				tc.showLocked()
			} else {
				tc.window.Show()
				tc.window.RequestFocus()
			}
		}
	} else {
		tc.statusItem.Label = "Status: unlocked"
		tc.lockItem.Label = "Lock"
		tc.lockItem.Action = func() {
			tc.state.Lock()
			if tc.showLocked != nil {
				tc.showLocked()
			}
		}
	}

	// Re-set menu so label/action changes reflect immediately
	tc.desk.SetSystemTrayMenu(tc.buildMenu())
}
