package qa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	qareq "github.com/quantumauth-io/quantum-auth/pkg/qa/requests"
	"github.com/quantumauth-io/quantum-auth/pkg/tpmdevice"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

var pqScheme sign.Scheme

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		log.Fatal("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

type Client struct {
	httpClient *http.Client
	BaseURL    string

	tpm tpmdevice.Client
	pk  sign.PublicKey
	sk  sign.PrivateKey

	tpmPubB64 string
	pqPubB64  string

	userID   string
	deviceID string

	ctx context.Context
}

func (c *Client) SetAuthContext(userID, deviceID string) {
	c.userID = userID
	c.deviceID = deviceID
}

// NewClient initialises TPM + PQ keys and an HTTP client.
func NewClient(baseURL string, tpmClient tpmdevice.Client) (*Client, error) {
	if tpmClient == nil {
		return nil, fmt.Errorf("tpm client is nil")
	}
	log.Info("Creating new QA client", "baseURL", baseURL)

	httpClient := &http.Client{Timeout: 10 * time.Second}

	tpmPub := tpmClient.PublicKeyB64()

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

	return &Client{
		httpClient: httpClient,
		tpm:        tpmClient,
		BaseURL:    baseURL,
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
	log.Info("RegisterUser raw body:", "body", string(bodyBytes))

	if resp.StatusCode == http.StatusCreated {
		var out registerUserResponse
		if err = json.Unmarshal(bodyBytes, &out); err != nil {
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

	url := c.BaseURL + "/devices/register"
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
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.DeviceID, nil
}

// RequestChallenge wraps POST /auth/challenge.
func (c *Client) RequestChallenge(ctx context.Context, deviceID string) (string, error) {
	reqBody := authChallengeRequest{DeviceID: deviceID}
	b, _ := json.Marshal(reqBody)

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
		return "", err
	}
	return out.ChallengeID, nil
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

	url := c.BaseURL + "/auth/verify"
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
	method string, path string, host string, userID, deviceID, challengeId string,
	body []byte,
) (map[string]string, error) {

	ts := time.Now().Unix()

	canonical := qareq.CanonicalString(qareq.CanonicalInput{
		Method:      method,
		Path:        path,
		Host:        host,
		TS:          ts,
		ChallengeID: challengeId,
		UserID:      userID,
		DeviceID:    deviceID,
		Body:        body,
	})

	msg := []byte(canonical)

	// TPM sign
	tpmSig, err := c.tpm.SignB64(msg)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	// PQ sign
	sigBytes := pqScheme.Sign(c.sk, msg, nil)
	if sigBytes == nil {
		return nil, fmt.Errorf("pq sign failed")
	}
	pqSig := base64.RawStdEncoding.EncodeToString(sigBytes)

	// base64 canonical so it is safe as a single-line header
	canonicalB64 := base64.StdEncoding.EncodeToString(msg)

	headers := map[string]string{
		"Authorization": fmt.Sprintf(
			`QuantumAuth sig_tpm="%s", sig_pq="%s"`,
			tpmSig, pqSig,
		),
		"X-QuantumAuth-Canonical-B64": canonicalB64,
	}

	return headers, nil
}

// FullLogin performs a one-shot full authentication against the QA server.
// It proves: password + TPM key + PQ key for the given user/device.
func (c *Client) FullLogin(ctx context.Context, userID, deviceID, password string) error {
	// message bound to this user/device & purpose
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

	// PQ sign
	pqSigBytes := pqScheme.Sign(c.sk, msgBytes, nil)
	if pqSigBytes == nil {
		return fmt.Errorf("fullLogin: PQ sign failed")
	}
	pqSigB64 := base64.RawStdEncoding.EncodeToString(pqSigBytes)

	// TPM sign
	tpmSigB64, err := c.tpm.SignB64(msgBytes)
	if err != nil {
		return fmt.Errorf("fullLogin: TPM sign failed: %w", err)
	}

	reqBody := fullLoginRequest{
		UserID:       userID,
		DeviceID:     deviceID,
		Password:     password,
		MessageB64:   base64.StdEncoding.EncodeToString(msgBytes),
		TPMSignature: tpmSigB64,
		PQSignature:  pqSigB64,
	}
	b, _ := json.Marshal(reqBody)

	// adjust path if you want a different route name
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

// ExportPQKeys returns the PQ public key (already in base64 in the client)
// and the PQ private key in base64, suitable for storing in the creds file.
func (c *Client) ExportPQKeys() (pubB64, privB64 string, err error) {
	skBytes, err := c.sk.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("PQ private key marshal failed: %w", err)
	}
	privB64 = base64.RawStdEncoding.EncodeToString(skBytes)
	return c.pqPubB64, privB64, nil
}

// LoadPQKeys replaces the current PQ keypair in the client with the given pair.
func (c *Client) LoadPQKeys(pubB64, privB64 string) error {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("decode PQ pub key: %w", err)
	}
	privBytes, err := base64.RawStdEncoding.DecodeString(privB64)
	if err != nil {
		return fmt.Errorf("decode PQ priv key: %w", err)
	}

	pk, err := pqScheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("unmarshal PQ pub key: %w", err)
	}
	sk, err := pqScheme.UnmarshalBinaryPrivateKey(privBytes)
	if err != nil {
		return fmt.Errorf("unmarshal PQ priv key: %w", err)
	}

	c.pk = pk
	c.sk = sk
	c.pqPubB64 = pubB64

	return nil
}
