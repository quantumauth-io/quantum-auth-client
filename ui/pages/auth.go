package pages

import (
	"context"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/ui/components"

	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func AuthPage(ctx context.Context, st *state.AppState) fyne.CanvasObject {
	status := widget.NewLabel("")

	keysBtn := widget.NewButton(st.T("auth.button.show_keys"), func() {
		go func() {
			tpm, pq, err := st.CryptoPublicKeys(ctx)
			if err != nil {
				st.Log.Addf("keys error: %v", err)
				fyne.Do(func() {
					status.SetText(st.T("auth.status.error", map[string]any{"Error": err.Error()}))
				})
				return
			}

			st.Log.Addf("TPM pub: %s...", safePrefix(tpm, 20))
			st.Log.Addf("PQ pub: %s...", safePrefix(pq, 20))

			fyne.Do(func() {
				status.SetText(st.T("auth.status.keys_fetched"))
			})
		}()
	})

	placeholder := widget.NewLabel(st.T("auth.placeholder.hint"))

	return components.Surface(container.NewVBox(keysBtn, placeholder, status))
}

func safePrefix(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
