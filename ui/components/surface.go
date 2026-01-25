package components

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
)

func Surface(child fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 15})     // ~0.06
	border := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 36}) // ~0.14
	border.StrokeColor = color.NRGBA{R: 255, G: 255, B: 255, A: 36}
	border.StrokeWidth = 1
	border.FillColor = color.NRGBA{R: 0, G: 0, B: 0, A: 0} // outline only

	// Stack: bg -> border -> padded child
	return container.NewStack(
		bg,
		border,
		container.NewPadded(child),
	)
}
