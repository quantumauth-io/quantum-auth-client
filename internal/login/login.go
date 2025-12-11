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

	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	"github.com/quantumauth-io/quantum-go-utils/log"
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
func EnsureLogin(
	ctx context.Context,
	qaClient *qa.Client,
	defaultEmail string,
	defaultDeviceLabel string,
) (*State, error) {

	paths, err := credsFilePathCandidates()
	if err != nil {
		return nil, err
	}

	var (
		path string
		data []byte
	)

	// Try all known locations (real HOME first, then legacy)
	for _, p := range paths {
		d, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read creds file %s: %w", p, err)
		}
		path = p
		data = d
		break
	}

	if path == "" {
		// No creds anywhere: run first-time setup, writing to primary path
		primaryPath := paths[0]
		log.Info("no QuantumAuth credentials file found, running first-time setup",
			"path", primaryPath)
		return firstTimeSetup(ctx, qaClient, primaryPath, defaultEmail, defaultDeviceLabel)
	}

	var fd fileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return nil, fmt.Errorf("parse creds file %s: %w", path, err)
	}

	// Restore PQ keys
	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
			return nil, fmt.Errorf("load PQ keys from creds file: %w", err)
		}
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

	if err := qaClient.FullLogin(ctx, state.UserID, state.DeviceID, string(state.Password)); err != nil {
		log.Error("full login failed", "error", err)
		return nil, err
	}

	log.Info("successfully logged in", "user", state.UserID)

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

	userID, err := qaClient.RegisterUser(ctx, email, password, username)
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}
	log.Info("user registered", "user_id", truncate(userID))

	deviceID, err := qaClient.RegisterDevice(ctx, userID, deviceLabel)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

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

// credsFilePathCandidates returns config paths to try, in priority order.
func credsFilePathCandidates() ([]string, error) {
	var paths []string

	// 1) Real home when running as a snap
	if realHome := os.Getenv("SNAP_REAL_HOME"); realHome != "" {
		paths = append(paths,
			filepath.Join(realHome, ".config", "quantumauth", "client_identity.json"))
	}

	// 2) Plain HOME (non-snap, or snap but still valid)
	if home := os.Getenv("HOME"); home != "" {
		p := filepath.Join(home, ".config", "quantumauth", "client_identity.json")
		if len(paths) == 0 || paths[len(paths)-1] != p {
			paths = append(paths, p)
		}
	}

	// 3) Legacy location (whatever UserConfigDir resolves to)
	if dir, err := os.UserConfigDir(); err == nil {
		p := filepath.Join(dir, "quantumauth", "client_identity.json")
		if len(paths) == 0 || paths[len(paths)-1] != p {
			paths = append(paths, p)
		}
	} else if len(paths) == 0 {
		// nothing else to fall back to
		return nil, fmt.Errorf("UserConfigDir: %w", err)
	}

	return paths, nil
}

func writeCredsFile(path string, fd fileData) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

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
