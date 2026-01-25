package http

// PairTokenProvider returns the current extension pairing token.
// ok=false means "no token configured yet".
type PairTokenProvider interface {
	GetPairToken() (string, bool)
}
