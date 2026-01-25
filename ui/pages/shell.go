package pages

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/quantumauth-io/quantum-auth-client/ui/state"

	"github.com/quantumauth-io/quantum-auth-client/ui/assets"
)

type HeaderOptions struct {
	OnLock func()
}

func WithQABackground(content fyne.CanvasObject) fyne.CanvasObject {
	// Base vertical gradient: bg-900 -> bg-950
	base := canvas.NewLinearGradient(
		color.NRGBA{R: 8, G: 16, B: 34, A: 255}, // bg-900
		color.NRGBA{R: 3, G: 7, B: 18, A: 255},  // bg-950
		90,                                      // downwards
	)

	// Radial glows approximating your CSS
	glow1 := canvas.NewRadialGradient(
		color.NRGBA{R: 56, G: 189, B: 248, A: 31}, // sky-400 @ 0.12-ish
		color.NRGBA{R: 0, G: 0, B: 0, A: 0},
	)
	glow2 := canvas.NewRadialGradient(
		color.NRGBA{R: 59, G: 130, B: 246, A: 31}, // blue-500 @ 0.12-ish
		color.NRGBA{R: 0, G: 0, B: 0, A: 0},
	)

	// Make glows “feel” positioned by using different sizes.
	// (Fyne doesn’t anchor gradients like CSS, but size gives a similar effect.)
	glow1.Resize(fyne.NewSize(1200, 700))
	glow2.Resize(fyne.NewSize(900, 600))

	// Fyne draws objects in stack order: earlier = back
	return container.NewStack(
		base,
		// Put glows above the base. They’ll be centered; sizing creates the illusion.
		glow1,
		glow2,
		content,
	)
}

func WithHeader(content fyne.CanvasObject, opts HeaderOptions, st *state.AppState) fyne.CanvasObject {
	logo := canvas.NewImageFromResource(assets.ResourceLogoPng)
	logo.SetMinSize(fyne.NewSize(22, 22))
	logo.FillMode = canvas.ImageFillContain

	title := widget.NewLabelWithStyle(st.T("app.title"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	spacer := layout.NewSpacer()

	var right fyne.CanvasObject = layout.NewSpacer()
	if opts.OnLock != nil {
		lockBtn := widget.NewButton(st.T("header.lock"), opts.OnLock)
		right = lockBtn
	}

	header := container.NewHBox(
		logo,
		title,
		spacer,
		right,
	)

	return container.NewBorder(
		container.NewPadded(header),
		nil, nil, nil,
		container.NewPadded(content),
	)
}
