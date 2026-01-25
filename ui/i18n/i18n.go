package i18n

import (
	"embed"
	"encoding/json"
	"fmt"

	goi18n "github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed *.json
var localesFS embed.FS

var bundle *goi18n.Bundle

func Init() error {
	if bundle != nil {
		return nil
	}

	b := goi18n.NewBundle(language.English)
	b.RegisterUnmarshalFunc("json", json.Unmarshal)

	// Load embedded message files
	for _, name := range []string{"en.json", "fr.json"} {
		data, err := localesFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if _, err := b.ParseMessageFileBytes(data, name); err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}
	}

	bundle = b
	return nil
}

type Translator struct {
	loc *goi18n.Localizer
}

func NewTranslator(langTag string) (*Translator, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	// For now, we only ship en.json, but we still accept a langTag.
	// Later we’ll add fr.json and pass ("fr") etc.
	loc := goi18n.NewLocalizer(bundle, langTag, "en")
	return &Translator{loc: loc}, nil
}

func (t *Translator) T(id string, data ...map[string]any) string {
	cfg := &goi18n.LocalizeConfig{MessageID: id}
	if len(data) > 0 {
		cfg.TemplateData = data[0]
	}
	s, err := t.loc.Localize(cfg)
	if err != nil {
		// Fail safe: show key if missing (better than blank UI)
		return id
	}
	return s
}
