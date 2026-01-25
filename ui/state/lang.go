package state

import (
	"strings"

	"fyne.io/fyne/v2/lang"
)

func DetectOSLanguage() string {
	// Examples: "en", "en-US", "fr-CA"
	tag := strings.TrimSpace(lang.SystemLocale().LanguageString())
	if strings.HasPrefix(strings.ToLower(tag), "fr") {
		return "fr"
	}
	return "en"
}
