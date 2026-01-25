package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-go-utils/cryptoctx"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa/headers"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"

	"io"
	"net/http"
	"time"
)

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
	UserID   string `json:"user_id"`
}

type authChallengeRequest struct {
	DeviceID string `json:"device_id"`
	AppID    string `json:"app_id"`
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       int64     `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type fullLoginRequest struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	PasswordB64  string `json:"password_b64"`
	MessageB64   string `json:"message_b64"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type SignedHeaders map[headers.HeaderKey]string

type SignedFields struct {
	AppID       string
	Aud         string
	TS          int64
	ChallengeID string
	UserID      string
	DeviceID    string
	Version     string
	BodySHA256  string
}
type Client struct {
	httpClient *http.Client
	crypto     cryptoctx.Runtime
	BaseURL    string
}

type ClientConfig struct {
	BaseURL     string
	HTTPTimeout time.Duration
	Crypto      cryptoctx.Runtime
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("baseURL is empty")
	}
	if cfg.Crypto == nil {
		return nil, fmt.Errorf("cryptoctx runtime is nil")
	}
	if cfg.Crypto.TPMPublicKeyB64() == "" {
		return nil, fmt.Errorf("cryptoctx TPM public key unavailable")
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		BaseURL:    cfg.BaseURL,
		crypto:     cfg.Crypto,
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.crypto == nil {
		return nil
	}
	return c.crypto.Close()
}

func (c *Client) RegisterUser(ctx context.Context, email string, password []byte, username string) (string, error) {
	pwB64 := base64.RawStdEncoding.EncodeToString(password)
	reqBody := registerUserRequest{Email: email, PasswordB64: pwB64, UserName: username}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("registerUser: marshal: %w", err)
	}

	url := c.BaseURL + "/users/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusCreated {
		var out registerUserResponse
		if err = json.Unmarshal(bodyBytes, &out); err != nil {
			return "", fmt.Errorf("registerUser: decode response: %w", err)
		}
		return out.UserID, nil
	}

	return "", fmt.Errorf("registerUser: status %d: %s", resp.StatusCode, string(bodyBytes))
}

func (c *Client) GetUserByEmailAndPassword(ctx context.Context, email string, password []byte) (string, error) {
	pwB64 := base64.RawStdEncoding.EncodeToString(password)
	reqBody := getUserRequest{Email: email, PasswordB64: pwB64}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("getUser: marshal: %w", err)
	}

	url := c.BaseURL + "/users/me"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var out getUserResponse
		if err = json.Unmarshal(bodyBytes, &out); err != nil {
			return "", fmt.Errorf("getUser: decode response: %w", err)
		}
		return out.UserID, nil
	}

	return "", fmt.Errorf("getUser: status %d: %s", resp.StatusCode, string(bodyBytes))
}

func (c *Client) RegisterDevice(ctx context.Context, userEmail string, password []byte, label string) (string, string, error) {

	tpmPubB64 := c.crypto.TPMPublicKeyB64()
	if tpmPubB64 == "" {
		return "", "", fmt.Errorf("registerDevice: TPM public key unavailable")
	}
	pqPubB64, err := c.crypto.PQPublicKeyB64(ctx)
	if err != nil {
		return "", "", fmt.Errorf("registerDevice: PQ public key: %w", err)
	}

	pwB64 := base64.RawStdEncoding.EncodeToString(password)
	reqBody := registerDeviceRequest{
		UserEmail:    userEmail,
		PasswordB64:  pwB64,
		DeviceLabel:  label,
		TPMPublicKey: tpmPubB64,
		PQPublicKey:  pqPubB64,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("registerDevice: marshal: %w", err)
	}

	url := c.BaseURL + "/devices/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("registerDevice: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out registerDeviceResponse
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("registerDevice: decode response: %w", err)
	}

	if strings.TrimSpace(out.UserID) == "" || strings.TrimSpace(out.DeviceID) == "" {
		return "", "", fmt.Errorf("registerDevice: response missing user_id or device_id")
	}

	return out.DeviceID, out.UserID, nil
}

func (c *Client) RequestChallenge(ctx context.Context, deviceID, appID string) (string, error) {
	reqBody := authChallengeRequest{DeviceID: deviceID, AppID: appID}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("requestChallenge: marshal: %w", err)
	}

	url := c.BaseURL + "/auth/challenge"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("requestChallenge: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out authChallengeResponse
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("requestChallenge: decode response: %w", err)
	}
	return out.ChallengeID, nil
}

func (c *Client) SignRequestAndReturnHeaders(ctx context.Context, method string, path string, appID string, host string, userID string,
	deviceID string, challengeID string, body []byte) (map[string]string, error) {

	sum := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(sum[:])

	ts := time.Now().Unix()

	normalizedMethod, err := requests.NormalizeAndValidateMethod(method)
	if err != nil {
		return nil, err
	}

	normalizedPath, err := requests.NormalizeAndValidatePath(path, requests.PathNormalizeOptions{
		CollapseSlashes: false,
	})
	if err != nil {
		return nil, err
	}

	normalizedAud := requests.NormalizeBackendHost(host)
	if normalizedAud == "" {
		return nil, fmt.Errorf("missing/invalid backend host")
	}

	validatedAppID, err := requests.ValidateUUIDv4(appID)
	if err != nil {
		return nil, fmt.Errorf("missing/invalid app id: %s", appID)
	}

	validatedChallengeID, err := requests.ValidateUUIDv4(challengeID)
	if err != nil {
		return nil, fmt.Errorf("missing/invalid challenge id: %s", challengeID)
	}

	validatedUserID, err := requests.ValidateUUIDv4(userID)
	if err != nil {
		return nil, fmt.Errorf("missing/invalid user id: %s", userID)
	}

	validatedDeviceID, err := requests.ValidateUUIDv4(deviceID)
	if err != nil {
		return nil, fmt.Errorf("missing/invalid device id: %s", deviceID)
	}

	canonical, err := requests.CanonicalString(requests.CanonicalInput{
		Method:        normalizedMethod,
		Path:          normalizedPath,
		AppID:         validatedAppID,
		BackendHost:   normalizedAud,
		TS:            ts,
		ChallengeID:   validatedChallengeID,
		UserID:        validatedUserID,
		DeviceID:      validatedDeviceID,
		BodySHA256Hex: bodyHex,
	})

	sum2 := sha256.Sum256([]byte(canonical))
	log.Debug("qa sign canonical",
		"canonicalSha256", hex.EncodeToString(sum2[:]),
		"method", normalizedMethod,
		"path", normalizedPath,
		"aud", normalizedAud,
		"ts", ts,
		"challengeId", validatedChallengeID,
	)

	msg := []byte(canonical)

	tpmSig, err := c.crypto.SignTPMB64(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	pqSig, err := c.crypto.SignPQB64(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("pq sign: %w", err)
	}

	qaHeaders := BuildSignedHeaders(SignedFields{
		AppID:       validatedAppID,
		Aud:         normalizedAud,
		TS:          ts,
		ChallengeID: validatedChallengeID,
		UserID:      validatedUserID,
		DeviceID:    validatedDeviceID,
		Version:     constants.QAHeaderSigVersion,
		BodySHA256:  bodyHex,
	}, tpmSig, pqSig)

	return qaHeaders.ToStringMap(), nil
}

func (c *Client) FullLogin(ctx context.Context, userID string, deviceID string, password []byte) error {
	msg := struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
		Purpose  string `json:"purpose"`
		TS       int64  `json:"ts"`
	}{
		UserID:   userID,
		DeviceID: deviceID,
		Purpose:  "client-login",
		TS:       time.Now().Unix(),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("fullLogin: marshal message: %w", err)
	}

	pqSigB64, err := c.crypto.SignPQB64(ctx, msgBytes)
	if err != nil {
		return fmt.Errorf("fullLogin: PQ sign: %w", err)
	}

	tpmSigB64, err := c.crypto.SignTPMB64(ctx, msgBytes)
	if err != nil {
		return fmt.Errorf("fullLogin: TPM sign: %w", err)
	}

	pwB64 := base64.RawStdEncoding.EncodeToString(password)

	reqBody := fullLoginRequest{
		UserID:       userID,
		DeviceID:     deviceID,
		PasswordB64:  pwB64,
		MessageB64:   base64.StdEncoding.EncodeToString(msgBytes),
		TPMSignature: tpmSigB64,
		PQSignature:  pqSigB64,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("fullLogin: marshal request: %w", err)
	}

	url := c.BaseURL + "/auth/full-login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("fullLogin: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fullLogin: do request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fullLogin: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func BuildSignedHeaders(fields SignedFields, tpmSig, pqSig string) SignedHeaders {
	h := SignedHeaders{
		// Signatures go in Authorization
		headers.HeaderAuthorization: fmt.Sprintf(
			`%s sig_tpm="%s", sig_pq="%s"`,
			headers.HeaderQuantumAuth,
			tpmSig,
			pqSig,
		),

		// Required fields for canonical reconstruction
		headers.HeaderQAAppID:       fields.AppID,
		headers.HeaderQAAudience:    fields.Aud,
		headers.HeaderQATimestamp:   fmt.Sprintf("%d", fields.TS),
		headers.HeaderQAChallengeID: fields.ChallengeID,
		headers.HeaderQAUserID:      fields.UserID,
		headers.HeaderQADeviceID:    fields.DeviceID,
		headers.HeaderQAVersion:     fields.Version,
		headers.HeaderQABodySHA256:  fields.BodySHA256,
	}

	return h
}

func (h SignedHeaders) ToStringMap() map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[string(k)] = v
	}
	return out
}
