package state

import (
	"os"
	"strings"
)

// TODO DELETE ME EVENTUALLY

func ApplyQAEnvToProcess(raw string) {
	v := strings.TrimSpace(raw)
	if v == "" || strings.EqualFold(v, "prod") || strings.EqualFold(v, "production") {
		// prod default: best is to clear it
		_ = os.Unsetenv("QA_ENV")
		return
	}

	// keep whatever user picked (local/dev)
	_ = os.Setenv("QA_ENV", v)
}
