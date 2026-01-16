package helpers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/quantumauth-io/quantum-go-utils/log"
	"golang.org/x/term"
)

func PromptInfuraAPIKey() (string, error) {
	fmt.Println()
	fmt.Println("=== Ethereum RPC Provider Setup ===")
	fmt.Println("QuantumAuth uses Infura for default Ethereum RPC access.")
	fmt.Println()
	fmt.Println("Create a free Infura account and API key here:")
	fmt.Println("👉 https://www.infura.io/register")
	fmt.Println()

	for {
		key := PromptLineWithDefault("Enter your Infura API Key", "")
		key = strings.TrimSpace(key)

		if key == "" {
			log.Warn(
				"QA Client",
				"event", "infura_api_key_validation_failed",
				"reason", "empty",
			)
			continue
		}

		if len(key) != 32 {
			log.Warn(
				"QA Client",
				"event", "infura_api_key_validation_failed",
				"reason", "invalid_length",
			)
			continue
		}

		if !isHexString(key) {
			log.Warn(
				"QA Client",
				"event", "infura_api_key_validation_failed",
				"reason", "invalid_format",
			)
			continue
		}

		return key, nil
	}
}

func isHexString(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func PromptLineWithDefault(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return def
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func PromptPassword(prompt string) ([]byte, error) {
	for {
		_, _ = fmt.Fprint(os.Stderr, prompt)

		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr) // newline after hidden input

		if err != nil {
			ZeroBytes(pw)
			log.Warn(
				"QA Client",
				"event", "password_read_failed",
				"reason", err.Error(),
			)
			return nil, fmt.Errorf("password input failed: %w", err)
		}

		if len(pw) == 0 {
			ZeroBytes(pw)
			log.Warn(
				"QA Client",
				"event", "password_validation_failed",
				"reason", "empty",
			)
			continue
		}

		if len(pw) < 8 {
			ZeroBytes(pw)
			log.Warn(
				"QA Client",
				"event", "password_validation_failed",
				"reason", "too_short",
			)
			continue
		}

		valid := true
		for _, b := range pw {
			if !IsAllowedPasswordChar(b) {
				valid = false
				break
			}
		}
		if !valid {
			ZeroBytes(pw)
			log.Warn(
				"QA Client",
				"event", "password_validation_failed",
				"reason", "invalid_characters",
			)
			continue
		}

		return pw, nil
	}
}
