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
	UserName string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerUserResponse struct {
	UserID string `json:"user_id"`
}

type registerDeviceRequest struct {
	UserID       string `json:"user_id"`
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

type authVerifyRequest struct {
	ChallengeID  string `json:"challenge_id"`
	DeviceID     string `json:"device_id"`
	Password     string `json:"password"`
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
	Password     string `json:"password"`
	Message      string `json:"message"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}
