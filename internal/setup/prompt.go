package setup

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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
			fmt.Println("Infura API key cannot be empty.")
			continue
		}

		return key, nil
	}
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
