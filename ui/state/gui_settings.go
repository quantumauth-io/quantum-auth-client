package state

import "strings"

const DefaultPQLabel = "qa.client.pq"

// NormalizeGUISettings applies defaults and trims fields.
// Call this whenever you load settings from vault or before saving.
func NormalizeGUISettings(in GUISettings) GUISettings {
	in.LocalHost = strings.TrimSpace(in.LocalHost)
	in.Port = strings.TrimSpace(in.Port)

	in.Email = strings.TrimSpace(in.Email)
	in.DeviceLabel = strings.TrimSpace(in.DeviceLabel)
	in.InfuraKey = strings.TrimSpace(in.InfuraKey)

	in.ActiveNetwork = strings.TrimSpace(in.ActiveNetwork)
	in.ActiveRPC = strings.TrimSpace(in.ActiveRPC)

	in.QAEnv = strings.TrimSpace(in.QAEnv)

	in.PQLabel = strings.TrimSpace(in.PQLabel)
	in.TPMOwnerAuth = strings.TrimSpace(in.TPMOwnerAuth)

	// Defaults
	if in.LocalHost == "" {
		in.LocalHost = "127.0.0.1"
	}
	if in.Port == "" {
		in.Port = "6137"
	}
	if in.DeviceLabel == "" {
		in.DeviceLabel = "default-device"
	}
	if in.PQLabel == "" {
		in.PQLabel = DefaultPQLabel
	}

	// Language default
	if in.Language == "" {
		in.Language = "en"
	}
	in.Language = normalizeLanguage(in.Language)

	// Derive ServerURL from QAEnv (UI chooses env, not URL)
	if url, err := ResolveServerURL(in.QAEnv); err == nil {
		in.ServerURL = url
	} else {
		// keep it empty so callers fail fast with a clear error
		in.ServerURL = ""
	}

	return in
}

func normalizeLanguage(tag string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	if strings.HasPrefix(t, "fr") {
		return "fr"
	}
	return "en"
}
