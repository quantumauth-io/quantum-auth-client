package assets

type Asset struct {
	Address  string `json:"address"` // checksummed (or whatever your normalize picks)
	Symbol   string `json:"symbol"`
	Decimals uint8  `json:"decimals"`
	Name     string `json:"name,omitempty"`

	// Optional: for UI logos later
	LogoURI string `json:"logoUri,omitempty"`
}

type Store struct {
	// network -> address -> asset
	Networks map[string]map[string]Asset `json:"networks"`
	Schema   int                         `json:"schema"` // bump if you change format
}
