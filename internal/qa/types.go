package qa

import (
	"time"
)

// -------- Signed message (must match server) --------

type SignedMessage struct {
	ChallengeID string `json:"challenge_id"`
	DeviceID    string `json:"device_id"`
	Nonce       int64  `json:"nonce"`
	Purpose     string `json:"purpose"`
}

// -------- HTTP DTOs --------

type registerUserRequest struct {
	UserName    string `json:"username"`
	Email       string `json:"email"`
	PasswordB64 string `json:"password_b64"`
}

type getUserRequest struct {
	Email       string `json:"email"`
	PasswordB64 string `json:"password_b64"`
}

type registerUserResponse struct {
	UserID string `json:"user_id"`
}

type getUserResponse struct {
	UserID string `json:"user_id"`
}

type registerDeviceRequest struct {
	UserEmail    string `json:"user_email"`
	PasswordB64  string `json:"password_b64"`
	DeviceLabel  string `json:"device_label"`
	TPMPublicKey string `json:"tpm_public_key"`
	PQPublicKey  string `json:"pq_public_key"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
}

type authChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       int64     `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type qaChallengeRequest struct {
	Method      string `json:"method"      binding:"required"`
	Path        string `json:"path"        binding:"required"`
	BackendHost string `json:"backend_host" binding:"required"`
}

type qaChallengeResponse struct {
	Headers map[string]string `json:"headers"`
}

type authVerifyRequest struct {
	ChallengeID  string `json:"challenge_id"`
	DeviceID     string `json:"device_id"`
	PasswordB64  string `json:"password_b64"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
}

type fullLoginRequest struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	PasswordB64  string `json:"password_b64"`
	MessageB64   string `json:"message_b64"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}
