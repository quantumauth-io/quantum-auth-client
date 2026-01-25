package pages

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/ui/components"

	"github.com/quantumauth-io/quantum-auth-client/ui/state"
)

func LogsPage(st *state.AppState) fyne.CanvasObject {
	list := widget.NewListWithData(
		st.Log.Lines(),
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i binding.DataItem, o fyne.CanvasObject) {
			str, _ := i.(binding.String).Get()
			o.(*widget.Label).SetText(str)
		},
	)

	return components.Surface(container.NewBorder(
		widget.NewLabel(st.T("logs.title")),
		nil, nil, nil,
		list,
	))
}
