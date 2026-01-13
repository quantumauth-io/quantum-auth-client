package utils

import (
	"math/big"
	"strings"
)

// formatUnitsTrim converts a token balance to a human string:
// - divides by 10^decimals
// - trims to maxFrac decimal places
// - removes trailing zeros
//
// Examples:
//
//	balance=1234500000000000000, decimals=18 -> "1.2345"
//	balance=1000000000000000000, decimals=18 -> "1"
//	balance=1, decimals=18 -> "0.000000000000000001"
func FormatUnitsTrim(amount *big.Int, decimals uint8, maxFrac int) string {
	if amount == nil || amount.Sign() == 0 {
		return "0"
	}

	ten := big.NewInt(10)
	base := new(big.Int).Exp(ten, big.NewInt(int64(decimals)), nil)

	intPart := new(big.Int).Div(amount, base)
	fracPart := new(big.Int).Mod(amount, base)

	if fracPart.Sign() == 0 || maxFrac <= 0 {
		return intPart.String()
	}

	// Left-pad fractional part to `decimals`
	fracStr := fracPart.String()
	if len(fracStr) < int(decimals) {
		fracStr = strings.Repeat("0", int(decimals)-len(fracStr)) + fracStr
	}

	// Trim to maxFrac
	if len(fracStr) > maxFrac {
		fracStr = fracStr[:maxFrac]
	}

	// Trim trailing zeros
	fracStr = strings.TrimRight(fracStr, "0")
	if fracStr == "" {
		return intPart.String()
	}

	return intPart.String() + "." + fracStr
}
