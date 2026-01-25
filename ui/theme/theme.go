package theme

import (
	"image/color"

	"fyne.io/fyne/v2"
	fynetheme "fyne.io/fyne/v2/theme"
)

type QATheme struct{}

func New() fyne.Theme { return &QATheme{} }

// Tailwind tokens (converted to NRGBA)
var (
	qaPrimary600 = color.NRGBA{R: 2, G: 132, B: 199, A: 255}  // --color-qa-primary-600
	qaPrimary500 = color.NRGBA{R: 14, G: 165, B: 233, A: 255} // --color-qa-primary-500
	qaPrimary400 = color.NRGBA{R: 56, G: 189, B: 248, A: 255} // --color-qa-primary-400

	qaAccent600 = color.NRGBA{R: 37, G: 99, B: 235, A: 255}  // --color-qa-accent-600
	qaAccent500 = color.NRGBA{R: 59, G: 130, B: 246, A: 255} // --color-qa-accent-500

	qaBg950 = color.NRGBA{R: 3, G: 7, B: 18, A: 255}  // --color-qa-bg-950
	qaBg900 = color.NRGBA{R: 8, G: 16, B: 34, A: 255} // --color-qa-bg-900

	qaText   = color.NRGBA{R: 255, G: 255, B: 255, A: 235} // ~0.92
	qaMuted  = color.NRGBA{R: 255, G: 255, B: 255, A: 179} // ~0.70
	qaSubtle = color.NRGBA{R: 255, G: 255, B: 255, A: 140} // ~0.55

	qaBorder = color.NRGBA{R: 255, G: 255, B: 255, A: 36} // ~0.14
	qaHover  = color.NRGBA{R: 255, G: 255, B: 255, A: 23} // ~0.09
)

// A slightly “glass” button bg; keeps contrast on dark
var qaButton = color.NRGBA{R: 255, G: 255, B: 255, A: 18}

func (t *QATheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {

	// Accent (buttons, selection, progress, etc.)
	case fynetheme.ColorNamePrimary:
		return qaPrimary500
	case fynetheme.ColorNameFocus:
		// your focus ring: rgba(56,189,248,0.45)
		return color.NRGBA{R: 56, G: 189, B: 248, A: 115}

	// Backgrounds / surfaces
	case fynetheme.ColorNameBackground:
		// app background (we’ll also paint gradients behind content)
		return qaBg950
	case fynetheme.ColorNameInputBackground:
		// input fields etc.
		return qaButton
	case fynetheme.ColorNameButton:
		return qaButton
	case fynetheme.ColorNameHover:
		return qaHover

	// Text
	case fynetheme.ColorNameForeground:
		return qaText
	case fynetheme.ColorNameDisabled:
		return qaSubtle
	case fynetheme.ColorNameDisabledButton:
		return color.NRGBA{R: 255, G: 255, B: 255, A: 10}

	// Fyne uses “placeholders” and separators in a few widgets
	case fynetheme.ColorNamePlaceHolder:
		return qaMuted
	case fynetheme.ColorNameSeparator:
		return qaBorder

	// Error/success states — keep defaults unless you want to brand them too
	case fynetheme.ColorNameError:
		// slightly softened red on dark
		return color.NRGBA{R: 239, G: 68, B: 68, A: 255}
	case fynetheme.ColorNameSuccess:
		return color.NRGBA{R: 34, G: 197, B: 94, A: 255}

	// Selection highlight sometimes pulls “primary” already,
	// but some widgets also consult “shadow” colors.
	case fynetheme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 115}
	}

	return fynetheme.DefaultTheme().Color(name, variant)
}

func (t *QATheme) Font(style fyne.TextStyle) fyne.Resource {
	return fynetheme.DefaultTheme().Font(style)
}

func (t *QATheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return fynetheme.DefaultTheme().Icon(name)
}

func (t *QATheme) Size(name fyne.ThemeSizeName) float32 {
	// Optional: slightly roomier UI, closer to your 14px/16px vibe
	switch name {
	case fynetheme.SizeNamePadding:
		return fynetheme.DefaultTheme().Size(name) + 2
	}
	return fynetheme.DefaultTheme().Size(name)
}
