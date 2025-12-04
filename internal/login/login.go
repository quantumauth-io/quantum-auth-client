// internal/login/login.go
package login

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Madeindreams/quantum-auth-client/internal/qa"
	"github.com/Madeindreams/quantum-go-utils/log"
	"golang.org/x/term"
)

type fileData struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	Email        string `json:"email,omitempty"`
	DeviceLabel  string `json:"device_label,omitempty"`
	PQPubKeyB64  string `json:"pq_pub_key_b64,omitempty"`
	PQPrivKeyB64 string `json:"pq_priv_key_b64,omitempty"`
}

// State is kept in memory while the client runs.
type State struct {
	UserID   string
	DeviceID string
	Password []byte
}

// EnsureLogin is called on client startup.
//
//   - If the creds file does NOT exist: runs interactive first-time setup
//     (register user + device) and writes the file.
//   - If it DOES exist: loads user/device and prompts once for password.
func EnsureLogin(
	ctx context.Context,
	qaClient *qa.Client,
	defaultEmail string,
	defaultDeviceLabel string,
) (*State, error) {

	path, err := credsFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("no QuantumAuth credentials file found, running first-time setup",
				"path", path)
			return firstTimeSetup(ctx, qaClient, path, defaultEmail, defaultDeviceLabel)
		}
		return nil, fmt.Errorf("read creds file: %w", err)
	}

	var fd fileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return nil, fmt.Errorf("parse creds file %s: %w", path, err)
	}

	log.Info("loaded QuantumAuth identity",
		"user_id", truncate(fd.UserID),
		"device_id", truncate(fd.DeviceID),
		"path", path,
	)

	// NEW: restore PQ keys into the client so signatures match what server has
	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
			return nil, fmt.Errorf("load PQ keys from creds file: %w", err)
		}
	} else {
		log.Info("creds file has no PQ keys; continuing with ephemeral PQ keypair (full login will likely fail)")
	}

	pwd, err := promptPassword("QuantumAuth password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	state := &State{
		UserID:   fd.UserID,
		DeviceID: fd.DeviceID,
		Password: []byte(pwd),
	}

	// verify with server before starting client
	if err := qaClient.FullLogin(ctx, state.UserID, state.DeviceID, string(state.Password)); err != nil {
		log.Error("full login failed", "error", err)
		return nil, err
	}

	return state, nil
}

// First-time flow: ask for details, register user + device, write file, return state.
func firstTimeSetup(
	ctx context.Context,
	qaClient *qa.Client,
	path string,
	defaultEmail string,
	defaultDeviceLabel string,
) (*State, error) {

	fmt.Println("=== QuantumAuth first-time setup ===")

	email := promptLineWithDefault("Email", defaultEmail)
	username := promptLineWithDefault("Username", guessUsername(email))
	deviceLabel := promptLineWithDefault("Device label", defaultDeviceLabel)
	password, err := promptPassword("Choose a password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	log.Info("registering QuantumAuth user")
	userID, err := qaClient.RegisterUser(ctx, email, password, username)
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}
	log.Info("user registered", "user_id", truncate(userID))

	log.Info("registering QuantumAuth device")
	deviceID, err := qaClient.RegisterDevice(ctx, userID, deviceLabel)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	log.Info("device registered", "device_id", truncate(deviceID))

	// NEW: export PQ keys from the QA client so we can reuse them next run
	pqPubB64, pqPrivB64, err := qaClient.ExportPQKeys()
	if err != nil {
		return nil, fmt.Errorf("export PQ keys: %w", err)
	}

	if err := writeCredsFile(path, fileData{
		UserID:       userID,
		DeviceID:     deviceID,
		Email:        email,
		DeviceLabel:  deviceLabel,
		PQPubKeyB64:  pqPubB64,
		PQPrivKeyB64: pqPrivB64,
	}); err != nil {
		return nil, err
	}
	log.Info("saved QuantumAuth credentials file", "path", path)

	return &State{
		UserID:   userID,
		DeviceID: deviceID,
		Password: []byte(password),
	}, nil
}

func credsFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("UserConfigDir: %w", err)
	}
	base := filepath.Join(dir, "quantumauth")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", base, err)
	}
	return filepath.Join(base, "client_identity.json"), nil
}

func writeCredsFile(path string, fd fileData) error {
	b, err := json.MarshalIndent(fd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal creds: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write creds file: %w", err)
	}
	return nil
}

func promptLineWithDefault(label, def string) string {
	reader := bufio.NewReader(os.Stdin)
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptPassword(label string) (string, error) {
	fmt.Print(label)
	// no echo
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func guessUsername(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func truncate(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "..."
}

// Clear zeroes the password when you logout/shutdown.
func (s *State) Clear() {
	if s == nil {
		return
	}
	for i := range s.Password {
		s.Password[i] = 0
	}
	s.Password = nil
}
