package helpers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
			fmt.Println("❌ Infura API key cannot be empty.")
			continue
		}

		if len(key) != 32 {
			fmt.Println("❌ Invalid Infura API key length. Expected 32 hexadecimal characters.")
			continue
		}

		if !isHexString(key) {
			fmt.Println("❌ Invalid Infura API key format. Only hexadecimal characters (0-9, a-f) are allowed.")
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
	_, _ = fmt.Fprint(os.Stderr, prompt)

	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr) // best-effort newline

	if err != nil {
		ZeroBytes(pw)
		return nil, fmt.Errorf("password input failed: %w", err)
	}

	if len(pw) < 8 {
		ZeroBytes(pw)
		return nil, fmt.Errorf("password must be at least 8 characters long")
	}

	for _, b := range pw {
		if !IsAllowedPasswordChar(b) {
			ZeroBytes(pw)
			return nil, fmt.Errorf(
				"password contains invalid characters (use letters, numbers, and special characters only)",
			)
		}
	}

	return pw, nil
}
