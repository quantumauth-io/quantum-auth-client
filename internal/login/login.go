package login

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type QAClientLoginService struct {
	ctx                context.Context
	qaClient           *qa.Client
	path               string // canonical write path
	defaultEmail       string
	defaultDeviceLabel string
	State              *State
}

func NewQAClientLoginService(
	ctx context.Context,
	qaClient *qa.Client,
	defaultEmail string,
	defaultDeviceLabel string,
) *QAClientLoginService {
	return &QAClientLoginService{
		ctx:                ctx,
		qaClient:           qaClient,
		defaultEmail:       defaultEmail,
		defaultDeviceLabel: defaultDeviceLabel,
	}
}

// EnsureLogin is called on client startup.
func (qas *QAClientLoginService) EnsureLogin() (*State, error) {
	paths, err := credsFilePathCandidates()
	if err != nil {
		return nil, fmt.Errorf("get credential paths: %w", err)
	}

	// Canonical write location (always)
	if len(paths) > 0 {
		qas.path = paths[0]
	}

	var (
		foundPath string
		data      []byte
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
		foundPath = p
		data = d
		break
	}

	if foundPath == "" {
		log.Info(
			"no QuantumAuth credentials file found, running first-time setup",
			"write_path", qas.path,
		)
		state, err := qas.handleMissingCreds()
		if err != nil {
			return nil, err
		}
		qas.State = state
		return state, nil
	}

	var fd fileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return nil, fmt.Errorf("parse creds file %s: %w", foundPath, err)
	}

	// Restore PQ keys
	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qas.qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
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

	if err := qas.qaClient.FullLogin(
		qas.ctx,
		state.UserID,
		state.DeviceID,
		string(state.Password),
	); err != nil {
		log.Error("full login failed", "error", err)
		state.Clear()
		return nil, err
	}

	qas.State = state
	log.Info("successfully logged in", "user", state.UserID)
	return state, nil
}

// When no credentials file exists, offer the user two paths:
// 1) Create a new account (first-time setup)
// 2) Add this device to an existing account
func (qas *QAClientLoginService) handleMissingCreds() (*State, error) {
	fmt.Println("No QuantumAuth credentials were found for this device.")
	fmt.Println()
	fmt.Println("Please choose an option:")
	fmt.Println("  1) Create a new QuantumAuth account")
	fmt.Println("  2) Add this device to my existing account")
	fmt.Println()

	var choice string
	for {
		fmt.Print("Enter 1 or 2: ")
		if _, err := fmt.Scanln(&choice); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, err
			}
			continue
		}

		choice = strings.TrimSpace(choice)
		switch {
		case choice == "1" || strings.EqualFold(choice, "create"):
			return qas.firstTimeSetup()
		case choice == "2" || strings.EqualFold(choice, "add"):
			return qas.addDeviceToExistingAccount()
		default:
			fmt.Println("Invalid choice, please enter 1 or 2.")
		}
	}
}

// First-time flow: ask for details, register user + device, write file, return state.
func (qas *QAClientLoginService) firstTimeSetup() (*State, error) {
	fmt.Println("=== QuantumAuth first-time setup ===")

	email := promptLineWithDefault("Email", qas.defaultEmail)
	username := promptLineWithDefault("Username", guessUsername(email))
	deviceLabel := promptLineWithDefault("Device label", qas.defaultDeviceLabel)

	password, err := promptPassword("Choose a password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	userID, err := qas.qaClient.RegisterUser(qas.ctx, email, password, username)
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}

	deviceID, err := qas.registerDevice(userID, deviceLabel)
	if err != nil {
		return nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, password)
}

// Existing-account flow: ask email+password, then add device, write file, return state.
func (qas *QAClientLoginService) addDeviceToExistingAccount() (*State, error) {
	fmt.Println("=== Add this device to your QuantumAuth account ===")

	email := promptLineWithDefault("Email", qas.defaultEmail)
	deviceLabel := promptLineWithDefault("Device label", qas.defaultDeviceLabel)

	password, err := promptPassword("Account password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	userID, err := qas.qaClient.GetUserByEmailAndPassword(qas.ctx, email, password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	deviceID, err := qas.registerDevice(userID, deviceLabel)
	if err != nil {
		return nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, password)
}

func (qas *QAClientLoginService) registerDevice(userID, deviceLabel string) (string, error) {
	deviceID, err := qas.qaClient.RegisterDevice(qas.ctx, userID, deviceLabel)
	if err != nil {
		return "", fmt.Errorf("register device: %w", err)
	}
	return deviceID, nil
}

// Helper: shared logic for exporting PQ keys, writing creds file, and returning State.
func (qas *QAClientLoginService) persistCredsAndState(
	userID, deviceID, email, deviceLabel, password string,
) (*State, error) {

	pqPubB64, pqPrivB64, err := qas.qaClient.ExportPQKeys()
	if err != nil {
		return nil, fmt.Errorf("export PQ keys: %w", err)
	}

	if err := writeCredsFile(qas.path, fileData{
		UserID:       userID,
		DeviceID:     deviceID,
		Email:        email,
		DeviceLabel:  deviceLabel,
		PQPubKeyB64:  pqPubB64,
		PQPrivKeyB64: pqPrivB64,
	}); err != nil {
		return nil, err
	}

	state := &State{
		UserID:   userID,
		DeviceID: deviceID,
		Password: []byte(password),
	}

	qas.State = state
	log.Info("saved QuantumAuth credentials file", "path", qas.path)
	return state, nil
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
	log.Info("writing credentials file", "path", path)
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

func (qas *QAClientLoginService) Clear() {
	if qas == nil || qas.State == nil {
		return
	}
	qas.State.Clear()
	qas.State = nil
}

func (qas *QAClientLoginService) SetCredsPath(path string) {
	if path == "" {
		log.Error("SetCredsPath called with nil path", "path", path)
		return
	}
	qas.path = path
}
