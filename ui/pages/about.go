package pages

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/buildinfo"
	"github.com/quantumauth-io/quantum-auth-client/ui/components"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func AboutPage(st *state.AppState) fyne.CanvasObject {
	return components.Surface(container.NewVBox(
		widget.NewLabel(
			st.T("about.title", map[string]any{
				"Version": buildinfo.String(),
			}),
		),
		widget.NewLabel(st.T("about.subtitle")),
		widget.NewLabel(st.T("about.description")),
	))
}
