package main

import (
	"context"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/quantumauth-io/quantum-auth-client/ui/assets"
	"github.com/quantumauth-io/quantum-auth-client/ui/i18n"
	"github.com/quantumauth-io/quantum-auth-client/ui/pages"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
	"github.com/quantumauth-io/quantum-auth-client/ui/theme"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

func replaceStackContent(c *fyne.Container, obj fyne.CanvasObject) {
	// Must run on UI thread
	c.RemoveAll()
	if obj != nil {
		c.Add(obj)
	}
	c.Refresh()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := app.NewWithID("io.quantumauth.client")
	a.SetIcon(assets.ResourceLogoPng)
	a.Settings().SetTheme(theme.New())

	w := a.NewWindow("QuantumAuth Client")
	w.SetIcon(assets.ResourceLogoPng)
	w.Resize(fyne.NewSize(980, 680))

	st := state.NewAppState(state.AppStateConfig{
		Now: func() time.Time { return time.Now() },
	})
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("close app state", "error", err)
		}
	}()

	var tray *trayController
	if tc, ok := newTrayController(a, w, st); ok {
		tray = tc
	}

	prefs := a.Preferences()
	lang := prefs.StringWithFallback("language", state.DetectOSLanguage())

	tr, err := i18n.NewTranslator(lang)
	if err != nil {
		log.Error("i18n init failed", "error", err)
	} else {
		st.SetTranslator(tr)
	}

	var showLocked func()
	var showMain func()

	setupBody := container.NewStack()
	settingsBody := container.NewStack()
	authBody := container.NewStack()
	walletBody := container.NewStack()
	devKeysBody := container.NewStack()
	logsBody := container.NewStack()
	aboutBody := container.NewStack()

	// A small in-tab loader placeholder
	tabLoading := func() fyne.CanvasObject {
		p := widget.NewProgressBarInfinite()
		p.Start()
		// Make it wide enough to visibly animate
		pWrap := container.NewGridWrap(fyne.NewSize(260, 18), p)

		return container.NewCenter(container.NewVBox(
			widget.NewLabel(st.T("common.loading")),
			pWrap,
		))
	}

	// A full-screen loader used immediately after unlock while we swap UI
	loadingScreen := func() fyne.CanvasObject {
		p := widget.NewProgressBarInfinite()
		p.Start()
		pWrap := container.NewGridWrap(fyne.NewSize(340, 18), p)

		return pages.WithQABackground(
			container.NewCenter(container.NewVBox(
				widget.NewLabel(st.T("common.loading")),
				pWrap,
			)),
		)
	}

	// --- lazy tabs machinery ---
	type tabKey string

	const (
		tabSetup    tabKey = "setup"
		tabSettings tabKey = "settings"
		tabAuth     tabKey = "auth"
		tabWallet   tabKey = "wallet"
		tabDevKeys  tabKey = "devkeys"
		tabLogs     tabKey = "logs"
		tabAbout    tabKey = "about"
	)

	loaded := map[tabKey]bool{
		tabSetup:    false,
		tabSettings: false,
		tabAuth:     false,
		tabWallet:   false,
		tabDevKeys:  false,
		tabLogs:     false,
		tabAbout:    false,
	}

	// current selected tab (used by refreshTabs)
	current := tabSetup

	// tabs pointer (set when UI built)
	var tabs *container.AppTabs

	// refresh callback passed to pages
	var refreshTabs func()

	// UI helper
	runUI := func(fn func()) {
		fyne.Do(fn)
	}

	// IMPORTANT: loadTabUI must be called on the UI thread ONLY.
	loadTabUI := func(k tabKey, force bool) {
		if !force && loaded[k] {
			return
		}
		loaded[k] = true

		// Some tabs may kick background work (never block UI)
		if k == tabWallet {
			go st.ReconcileWalletState(ctx)
		}

		switch k {
		case tabSetup:
			replaceStackContent(setupBody, pages.SetupPage(ctx, st, refreshTabs))
		case tabSettings:
			replaceStackContent(settingsBody, pages.SettingsPage(ctx, st, refreshTabs))
		case tabAuth:
			replaceStackContent(authBody, pages.AuthPage(ctx, st))
		case tabWallet:
			replaceStackContent(walletBody, pages.WalletPage(ctx, st, refreshTabs))
		case tabDevKeys:
			replaceStackContent(devKeysBody, pages.DevKeysPage(ctx, w, st))
		case tabLogs:
			replaceStackContent(logsBody, pages.LogsPage(st))
		case tabAbout:
			replaceStackContent(aboutBody, pages.AboutPage(st))
		default:
			replaceStackContent(setupBody, pages.SetupPage(ctx, st, refreshTabs))
		}
	}

	// Global refresh: mark dirty; reload current tab only.
	// Other tabs reload when clicked next.
	refreshTabs = func() {
		go st.ReconcileWalletState(ctx)

		for k := range loaded {
			loaded[k] = false
		}

		runUI(func() {
			// if tabs isn't built yet, just ignore
			if tabs == nil {
				return
			}
			loadTabUI(current, true)
		})
	}

	buildMainUI := func() fyne.CanvasObject {
		// placeholders (fast)
		replaceStackContent(setupBody, tabLoading())
		replaceStackContent(settingsBody, tabLoading())
		replaceStackContent(authBody, tabLoading())
		replaceStackContent(walletBody, tabLoading())
		replaceStackContent(devKeysBody, tabLoading())
		replaceStackContent(logsBody, tabLoading())
		replaceStackContent(aboutBody, tabLoading())

		tiSetup := container.NewTabItem(st.T("tabs.setup"), setupBody)
		tiSettings := container.NewTabItem(st.T("tabs.settings"), settingsBody)
		tiAuth := container.NewTabItem(st.T("tabs.auth"), authBody)
		tiWallet := container.NewTabItem(st.T("tabs.wallet"), walletBody)
		tiDevKeys := container.NewTabItem(st.T("tabs.devkeys"), devKeysBody)
		tiLogs := container.NewTabItem(st.T("tabs.logs"), logsBody)
		tiAbout := container.NewTabItem(st.T("tabs.about"), aboutBody)

		tabs = container.NewAppTabs(
			tiSetup,
			tiSettings,
			tiAuth,
			tiWallet,
			tiDevKeys,
			tiLogs,
			tiAbout,
		)

		tabs.OnSelected = func(ti *container.TabItem) {
			// OnSelected runs on UI thread, so call loadTabUI directly.
			switch ti {
			case tiSetup:
				current = tabSetup
			case tiSettings:
				current = tabSettings
			case tiAuth:
				current = tabAuth
			case tiWallet:
				current = tabWallet
			case tiDevKeys:
				current = tabDevKeys
			case tiLogs:
				current = tabLogs
			case tiAbout:
				current = tabAbout
			default:
				current = tabSetup
			}

			loadTabUI(current, false)
		}

		return pages.WithQABackground(
			pages.WithHeader(tabs, pages.HeaderOptions{
				OnLock: func() {
					st.Lock()
					showLocked()
					if tray != nil {
						tray.Update()
					}
				},
			}, st),
		)
	}

	showMain = func() {
		// Show loader immediately so it can animate.
		runUI(func() {
			w.SetContent(loadingScreen())
		})

		// Do warmups + server start off UI thread
		go func() {
			// Prewarm devkeys so the DevKeys tab opens faster
			// (ignore errors; tab will show them if needed)
			_, _, _ = st.SnapshotDevKeys(ctx)

			// Background reconcile (optional)
			go st.ReconcileWalletState(ctx)

			// Start HTTP server in background if registered
			if payload, ok := st.VaultPayloadCopy(); ok && payload.Flags.RegistrationCompleted {
				go func() {
					if err := st.StartHTTPServer(ctx); err != nil {
						st.Log.Addf("server start failed: %v", err)
					}
				}()
			}

			// Swap to main UI on UI thread
			runUI(func() {
				w.SetContent(buildMainUI())

				// Load default tab AFTER content is set (prevents nested UI churn)
				current = tabSetup
				loadTabUI(tabSetup, false)
			})

			if tray != nil {
				tray.Update()
			}
		}()
	}

	showLocked = func() {
		runUI(func() {
			w.SetContent(
				pages.WithQABackground(
					pages.WithHeader(
						pages.LockOrSetupScreen(st, showMain),
						pages.HeaderOptions{},
						st,
					),
				),
			)
		})
		if tray != nil {
			tray.Update()
		}
	}

	if tray != nil {
		tray.BindHooks(showLocked, showMain)
	}

	showLocked()

	w.SetCloseIntercept(func() {
		cancel()
		st.StopHTTPServer(context.Background())
		w.Close()
	})

	w.ShowAndRun()
}
