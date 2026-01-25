package walletsigner

import (
	"strconv"

	"golang.org/x/crypto/sha3"
)

func EIP191HashPersonalMessage(message []byte) []byte {
	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message))
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(prefix))
	h.Write(message)
	return h.Sum(nil)
}
