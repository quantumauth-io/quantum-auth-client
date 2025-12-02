package qa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"

	qacrypto "github.com/Madeindreams/quantum-auth/pkg/qa/crypto"
	qareq "github.com/Madeindreams/quantum-auth/pkg/qa/requests"
	"github.com/Madeindreams/quantum-auth/pkg/tpmdevice"
)

// ===== PQ scheme =====

var pqScheme sign.Scheme

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		log.Fatal("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

type Client struct {
	httpClient *http.Client
	baseURL    string

	tpm tpmdevice.Client
	pk  sign.PublicKey
	sk  sign.PrivateKey

	tpmPubB64 string
	pqPubB64  string
}

// NewClient initialises TPM + PQ keys and an HTTP client.
func NewClient(ctx context.Context, baseURL string, tpmClient tpmdevice.Client) (*Client, error) {
	if tpmClient == nil {
		return nil, fmt.Errorf("tpm client is nil")
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	tpmPub := tpmClient.PublicKeyB64()
	log.Println("TPM public key (b64, trunc):", truncate(tpmPub))

	pk, sk, err := pqScheme.GenerateKey()
	if err != nil {
		_ = tpmClient.Close()
		return nil, fmt.Errorf("PQ keygen failed: %w", err)
	}
	pqPubBytes, err := pk.MarshalBinary()
	if err != nil {
		_ = tpmClient.Close()
		return nil, fmt.Errorf("PQ pub marshal failed: %w", err)
	}
	pqPub := base64.RawStdEncoding.EncodeToString(pqPubBytes)
	log.Println("PQ public key (b64, trunc):", truncate(pqPub))

	return &Client{
		httpClient: httpClient,
		tpm:        tpmClient,
		baseURL:    baseURL,
		pk:         pk,
		sk:         sk,
		tpmPubB64:  tpmPub,
		pqPubB64:   pqPub,
	}, nil
}

func (c *Client) Close() error {
	return c.tpm.Close()
}

// Expose public keys for device registration.
func (c *Client) TPMPublicKey() string { return c.tpmPubB64 }
func (c *Client) PQPublicKey() string  { return c.pqPubB64 }

// ===== high-level flow methods =====

// RegisterUser wraps POST /users/register on the quantum-auth server.
func (c *Client) RegisterUser(ctx context.Context, email, password, username string) (string, error) {
	reqBody := registerUserRequest{Email: email, Password: password, UserName: username}
	b, _ := json.Marshal(reqBody)

	url := c.baseURL + "/users/register"
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
	log.Println("RegisterUser raw body:", string(bodyBytes))

	if resp.StatusCode == http.StatusCreated {
		var out registerUserResponse
		if err := json.Unmarshal(bodyBytes, &out); err != nil {
			return "", fmt.Errorf("decode registerUser response: %w", err)
		}
		return out.UserID, nil
	}

	return "", fmt.Errorf("registerUser: status %d: %s", resp.StatusCode, string(bodyBytes))
}

// RegisterDevice wraps POST /devices/register.
func (c *Client) RegisterDevice(ctx context.Context, userID, label string) (string, error) {
	reqBody := registerDeviceRequest{
		UserID:       userID,
		DeviceLabel:  label,
		TPMPublicKey: c.tpmPubB64,
		PQPublicKey:  c.pqPubB64,
	}
	b, _ := json.Marshal(reqBody)

	url := c.baseURL + "/devices/register"
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
		return "", fmt.Errorf("registerDevice: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out registerDeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.DeviceID, nil
}

// RequestChallenge wraps POST /auth/challenge.
func (c *Client) RequestChallenge(ctx context.Context, deviceID string) (string, int64, error) {
	reqBody := authChallengeRequest{DeviceID: deviceID}
	b, _ := json.Marshal(reqBody)

	url := c.baseURL + "/auth/challenge"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("requestChallenge: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out authChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	return out.ChallengeID, out.Nonce, nil
}

// BuildSignedMessage creates the JSON message used for challenge signatures.
func (c *Client) BuildSignedMessage(chID, devID string, nonce int64) ([]byte, error) {
	msg := SignedMessage{
		ChallengeID: chID,
		DeviceID:    devID,
		Nonce:       nonce,
		Purpose:     "auth",
	}
	return json.Marshal(msg)
}

// CompleteChallenge builds + signs message and calls /auth/verify.
func (c *Client) CompleteChallenge(
	ctx context.Context,
	chID, devID string,
	nonce int64,
	password string,
) (bool, string, error) {

	// message
	msgBytes, err := c.BuildSignedMessage(chID, devID, nonce)
	if err != nil {
		return false, "", fmt.Errorf("buildSignedMessage: %w", err)
	}

	// PQ sign
	pqSigBytes := pqScheme.Sign(c.sk, msgBytes, nil)
	if pqSigBytes == nil {
		return false, "", fmt.Errorf("PQ sign failed")
	}
	pqSigB64 := base64.RawStdEncoding.EncodeToString(pqSigBytes)

	// TPM sign
	tpmSigB64, err := c.tpm.SignB64(msgBytes)
	if err != nil {
		return false, "", fmt.Errorf("TPM sign failed: %w", err)
	}

	return c.verifyAuth(ctx, chID, devID, password, tpmSigB64, pqSigB64)
}

// verifyAuth POSTs /auth/verify.
func (c *Client) verifyAuth(
	ctx context.Context,
	chID, devID, password, tpmSig, pqSig string,
) (bool, string, error) {

	reqBody := authVerifyRequest{
		ChallengeID:  chID,
		DeviceID:     devID,
		Password:     password,
		TPMSignature: tpmSig,
		PQSignature:  pqSig,
	}
	b, _ := json.Marshal(reqBody)

	url := c.baseURL + "/auth/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var out authVerifyResponse
		if err := json.Unmarshal(bodyBytes, &out); err != nil {
			return false, "", err
		}
		return out.Authenticated, out.UserID, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		var out authVerifyResponse
		_ = json.Unmarshal(bodyBytes, &out)
		return out.Authenticated, out.UserID, nil
	}

	return false, "", fmt.Errorf("verifyAuth: status %d: %s", resp.StatusCode, string(bodyBytes))
}

// SignRequest builds QuantumAuth headers for an arbitrary request.
func (c *Client) SignRequest(
	method, path, host, userID, deviceID string,
	body []byte,
) (map[string]string, error) {

	nonceStr, err := qacrypto.RandomBase64(16)
	if err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ts := time.Now().Unix()

	canonical := qareq.CanonicalString(qareq.CanonicalInput{
		Method:   method,
		Path:     path,
		Host:     host,
		TS:       ts,
		Nonce:    nonceStr,
		UserID:   userID,
		DeviceID: deviceID,
		Body:     body,
	})

	// TPM sign
	tpmSig, err := c.tpm.SignB64([]byte(canonical))
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	// PQ sign
	sigBytes := pqScheme.Sign(c.sk, []byte(canonical), nil)
	if sigBytes == nil {
		return nil, fmt.Errorf("pq sign failed")
	}
	pqSig := base64.RawStdEncoding.EncodeToString(sigBytes)

	headers := map[string]string{
		"Authorization": fmt.Sprintf(
			`QuantumAuth user="%s", device="%s", ts="%d", nonce="%s", sig_tpm="%s", sig_pq="%s"`,
			userID, deviceID, ts, nonceStr, tpmSig, pqSig,
		),
	}

	return headers, nil
}

// SecurePing calls the upstream /api/secure-ping using signed headers.
func (c *Client) SecurePing(ctx context.Context, userID, deviceID string) (int, string, error) {
	path := "/api/secure-ping"
	host := hostOnly(c.baseURL)

	headers, err := c.SignRequest(http.MethodGet, path, host, userID, deviceID, nil)
	if err != nil {
		return 0, "", err
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(bodyBytes), nil
}

// ===== helpers =====

func truncate(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "..."
}

func hostOnly(baseURL string) string {
	// Very small helper to extract host:port from http://host:port/...
	// Good enough for local dev; feel free to improve with net/url.
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return baseURL
	}
	withoutScheme := strings.SplitN(baseURL, "://", 2)[1]
	parts := strings.SplitN(withoutScheme, "/", 2)
	return parts[0]
}
