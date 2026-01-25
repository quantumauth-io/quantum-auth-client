package pages

import (
	"context"
	"errors"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
	"github.com/quantumauth-io/quantum-auth-client/ui/components"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func DevKeysPage(ctx context.Context, win fyne.Window, st *state.AppState) fyne.CanvasObject {

	title := widget.NewLabelWithStyle(st.T("devkeys.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	progress := widget.NewProgressBarInfinite()
	progressWrap := container.NewGridWrap(fyne.NewSize(260, 18), progress)

	loadingRow := container.NewHBox(
		widget.NewLabel(st.T("common.loading")),
		layout.NewSpacer(),
		progressWrap,
	)
	loadingRow.Hide()

	listBox := container.NewVBox()
	scroll := container.NewVScroll(listBox)
	scroll.SetMinSize(fyne.NewSize(760, 520))

	// Forward decl (used by create/delete)
	var refreshPage func()

	createBtn := widget.NewButton(st.T("devkeys.create"), func() {
		showCreateDevKeyDialog(ctx, win, st, refreshPage)
	})

	header := container.NewHBox(title, layout.NewSpacer(), createBtn)

	root := components.Surface(
		container.NewBorder(
			header,
			container.NewVBox(status, loadingRow),
			nil,
			nil,
			scroll,
		),
	)

	setLoading := func(on bool) {
		if on {
			status.SetText("")
			progress.Start()
			loadingRow.Show()
		} else {
			progress.Stop()
			loadingRow.Hide()
		}
	}

	// Only refresh THIS page.
	refreshPage = func() {
		if win == nil {
			// Still allow load without window, but dialogs won’t show.
		}

		fyne.Do(func() {
			setLoading(true)
			// Keep old list while loading? up to you.
			// If you prefer blank while loading:
			// listBox.Objects = nil
			// listBox.Refresh()
		})

		go func() {
			snap, ok, err := st.SnapshotDevKeys(ctx)
			if err != nil {
				fyne.Do(func() {
					status.SetText(fmt.Sprintf("%s: %v", st.T("common.error"), err))
					setLoading(false)
				})
				return
			}
			if !ok || snap.Manager == nil {
				fyne.Do(func() {
					status.SetText(st.T("devkeys.unlock_required"))
					setLoading(false)
				})
				return
			}

			keys, err := snap.Manager.List(ctx)
			if err != nil {
				fyne.Do(func() {
					status.SetText(fmt.Sprintf("%s: %v", st.T("common.error"), err))
					setLoading(false)
				})
				return
			}

			fyne.Do(func() {
				listBox.Objects = nil

				if len(keys) == 0 {
					listBox.Add(widget.NewLabel(st.T("devkeys.empty")))
				} else {
					for _, k := range keys {
						listBox.Add(devKeyCard(ctx, win, st, snap, k, refreshPage))
					}
				}

				listBox.Refresh()
				setLoading(false)
			})
		}()
	}

	// Initial load
	refreshPage()

	return root
}

func devKeyCard(
	ctx context.Context,
	win fyne.Window,
	st *state.AppState,
	snap clienthttp.DevKeysSnapshot,
	k devkeys.Key,
	refreshPage func(),
) fyne.CanvasObject {
	// Public key
	pubEntry := widget.NewMultiLineEntry()
	pubEntry.Wrapping = fyne.TextWrapBreak
	pubEntry.SetText(k.PQPublicKey)
	pubEntry.Disable()

	copyPub := widget.NewButton(st.T("common.copy"), func() {
		setClipboard(k.PQPublicKey)
	})

	meta := container.NewVBox(
		widget.NewLabelWithStyle(k.AppName, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("%s: %s", st.T("devkeys.app_id"), k.AppID)),
		widget.NewLabel(st.T("devkeys.public_key")),
	)

	pubRow := container.NewBorder(meta, nil, nil, copyPub, pubEntry)

	// Private key (lazy reveal)
	privEntry := widget.NewMultiLineEntry()
	privEntry.Wrapping = fyne.TextWrapBreak
	privEntry.Disable()

	copyPriv := widget.NewButton(st.T("common.copy"), func() {
		if privEntry.Text != "" {
			setClipboard(privEntry.Text)
		}
	})

	privBox := container.NewBorder(
		widget.NewLabel(st.T("devkeys.private_key")),
		nil,
		nil,
		copyPriv,
		privEntry,
	)
	privBox.Hide()

	cardStatus := widget.NewLabel("")
	cardStatus.Wrapping = fyne.TextWrapWord

	// IMPORTANT: non-nil callback at creation time
	var showPrivBtn *widget.Button
	showPrivBtn = widget.NewButton(st.T("devkeys.show_private"), func() {
		if win == nil {
			cardStatus.SetText(st.T("devkeys.unavailable"))
			return
		}

		// toggle hide
		if privBox.Visible() {
			privEntry.SetText("")
			privBox.Hide()
			cardStatus.SetText("")
			showPrivBtn.SetText(st.T("devkeys.show_private"))
			return
		}

		dialog.NewConfirm(
			st.T("devkeys.reveal_title"),
			st.T("devkeys.reveal_confirm"),
			func(ok bool) {
				if !ok {
					return
				}

				cardStatus.SetText(st.T("common.loading"))
				showPrivBtn.Disable()

				go func() {
					pk, err := snap.Manager.ExportPrivateKey(ctx, k.AppID)

					fyne.Do(func() {
						showPrivBtn.Enable()

						if err != nil {
							cardStatus.SetText(fmt.Sprintf("%s: %v", st.T("common.error"), err))
							return
						}

						cardStatus.SetText("")
						privEntry.SetText(pk)
						privBox.Show()
						showPrivBtn.SetText(st.T("devkeys.hide_private"))
					})
				}()
			},
			win,
		).Show()
	})

	deleteBtn := widget.NewButton(st.T("common.delete"), func() {
		if win == nil {
			cardStatus.SetText(st.T("devkeys.unavailable"))
			return
		}

		dialog.NewConfirm(
			st.T("devkeys.delete_title"),
			fmt.Sprintf(st.T("devkeys.delete_confirm_fmt"), k.AppName, k.AppID),
			func(ok bool) {
				if !ok {
					return
				}
				var deleteBtn *widget.Button
				// Do delete off UI thread (disk + index write)
				deleteBtn.Disable()
				showPrivBtn.Disable()
				cardStatus.SetText(st.T("common.loading"))

				go func() {
					err := snap.Manager.Delete(ctx, k.AppID)

					fyne.Do(func() {
						deleteBtn.Enable()
						showPrivBtn.Enable()

						if err != nil {
							dialog.ShowError(err, win)
							cardStatus.SetText("")
							return
						}

						cardStatus.SetText("")
						if refreshPage != nil {
							refreshPage()
						}
					})
				}()
			},
			win,
		).Show()
	})

	actions := container.NewHBox(showPrivBtn, layout.NewSpacer(), deleteBtn)

	content := container.NewVBox(pubRow, privBox, cardStatus, actions)
	return container.NewPadded(widget.NewCard("", "", content))
}

func showCreateDevKeyDialog(ctx context.Context, win fyne.Window, st *state.AppState, refreshPage func()) {
	if win == nil {
		return
	}

	snap, ok, err := st.SnapshotDevKeys(ctx)
	if err != nil {
		dialog.ShowError(err, win)
		return
	}
	if !ok || snap.Manager == nil {
		dialog.ShowInformation(st.T("common.error"), st.T("devkeys.unlock_required"), win)
		return
	}

	appID := widget.NewEntry()
	appID.SetPlaceHolder(st.T("devkeys.form.app_id_ph"))

	appName := widget.NewEntry()
	appName.SetPlaceHolder(st.T("devkeys.form.app_name_ph"))

	// We'll do create in background, but we want to close dialog immediately on OK.
	d := dialog.NewForm(
		st.T("devkeys.create_title"),
		st.T("common.create"),
		st.T("common.cancel"),
		[]*widget.FormItem{
			widget.NewFormItem(st.T("devkeys.app_id"), appID),
			widget.NewFormItem(st.T("devkeys.app_name"), appName),
		},
		func(ok bool) {
			if !ok {
				return
			}

			// Run create off UI thread (TPM + disk)
			go func(appIDVal, appNameVal string) {
				_, err := snap.Manager.Create(ctx, appIDVal, appNameVal)

				fyne.Do(func() {
					if err != nil {
						if errors.Is(err, devkeys.ErrConflict) {
							dialog.ShowInformation(st.T("common.error"), st.T("devkeys.err_conflict"), win)
							return
						}
						if errors.Is(err, devkeys.ErrInvalidInput) {
							dialog.ShowInformation(st.T("common.error"), st.T("devkeys.err_invalid"), win)
							return
						}
						dialog.ShowError(err, win)
						return
					}

					if refreshPage != nil {
						refreshPage()
					}
				})
			}(appID.Text, appName.Text)
		},
		win,
	)

	d.Resize(fyne.NewSize(560, 220))
	d.Show()
}

func setClipboard(s string) {
	if a := fyne.CurrentApp(); a != nil {
		a.Clipboard().SetContent(s)
	}
}
