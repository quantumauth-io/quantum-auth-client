package utils

import (
	"math/big"
	"strings"
)

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

	fracStr := fracPart.String()
	if len(fracStr) < int(decimals) {
		fracStr = strings.Repeat("0", int(decimals)-len(fracStr)) + fracStr
	}

	if len(fracStr) > maxFrac {
		fracStr = fracStr[:maxFrac]
	}

	fracStr = strings.TrimRight(fracStr, "0")
	if fracStr == "" {
		return intPart.String()
	}

	return intPart.String() + "." + fracStr
}
