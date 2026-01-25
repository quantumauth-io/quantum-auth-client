package state

type GUISettings struct {
	Language  string `json:"language"`
	ServerURL string `json:"serverUrl"`
	LocalHost string `json:"localHost"`
	Port      string `json:"port"`

	Email        string `json:"email"`
	Username     string `json:"username"`
	DeviceLabel  string `json:"deviceLabel"`
	InfuraKey    string `json:"infuraKey"`
	PQLabel      string `json:"pqLabel"`
	TPMOwnerAuth string `json:"tpmOwnerAuth"`

	ActiveNetwork string `json:"activeNetwork"`
	ActiveRPC     string `json:"activeRpc"`

	QAEnv string `json:"qaEnv"`
}
