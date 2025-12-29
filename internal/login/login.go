package login

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/ethdevice"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/userwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	"github.com/quantumauth-io/quantum-auth-client/internal/securefile"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
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
}

type encFile struct {
	Version int `json:"version"`

	// KDF params (tune per device class)
	ArgonTime    uint32 `json:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory"`  // KiB
	ArgonThreads uint8  `json:"argon_threads"` // parallelism
	ArgonKeyLen  uint32 `json:"argon_key_len"`

	SaltB64  string `json:"salt_b64"`
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

// Reasonable defaults for desktop/laptop.
// Memory is KiB: 64*1024 = 64 MiB.
var defaultKDF = encFile{
	Version:      1,
	ArgonTime:    3,
	ArgonMemory:  64 * 1024,
	ArgonThreads: 2,
	ArgonKeyLen:  32,
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
func (qas *QAClientLoginService) EnsureLoginWithPassword(pwd []byte) (*State, error) {
	paths, err := securefile.ConfigPathCandidates("quantumauth", "client_identity.json")
	if err != nil {
		return nil, err
	}

	// Canonical path for this env
	qas.path = paths[0]

	// Strict: only look in this env’s candidates (snap/home/userconfigdir),
	// but NEVER prod fallback
	foundPath := ""
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		} else if os.IsNotExist(err) {
			continue
		} else {
			return nil, fmt.Errorf("stat creds file %s: %w", p, err)
		}
	}

	if foundPath == "" {
		log.Info("no QuantumAuth credentials file found, running first-time setup", "write_path", qas.path)
		state, err := qas.handleMissingCreds()
		if err != nil {
			return nil, err
		}
		qas.State = state
		return state, nil
	}

	// Found in this env; use it for read/decrypt
	qas.path = foundPath
	log.Info("found QuantumAuth credentials file", "path", qas.path)

	store, err := userwallet.NewStore()
	if err != nil {
		return nil, err
	}

	_, err = store.Ensure(pwd)
	if err != nil {
		return nil, err
	}

	sealer := tpmdevice.NewSealer("") // owner auth usually ""
	devStore, err := ethdevice.NewStore(sealer)
	if err != nil {
		return nil, err
	}

	_, err = devStore.Ensure(qas.ctx)
	if err != nil {
		return nil, err
	}

	fd, err := securefile.ReadEncryptedJSON[fileData](
		foundPath,
		pwd,
		securefile.Options{
			AADFunc: func(_ string) []byte { return []byte("quantumauth:client_identity:v1") },
		},
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt creds file %s: %w", foundPath, err)
	}

	// Optional: migrate to canonical path if we loaded from legacy path
	// if foundPath != qas.path { _ = securefile.WriteEncryptedJSON(qas.path, fd, pwd, ...) }

	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qas.qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
			return nil, fmt.Errorf("load PQ keys from creds file: %w", err)
		}
	}

	state := &State{UserID: fd.UserID, DeviceID: fd.DeviceID}

	if err := qas.qaClient.FullLogin(qas.ctx, state.UserID, state.DeviceID, pwd); err != nil {
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

	pwd, err := PromptPassword("Choose a password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	defer Zero(pwd)

	userID, err := qas.qaClient.RegisterUser(qas.ctx, email, pwd, username)
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}

	deviceID, err := qas.registerDevice(email, pwd, deviceLabel)
	if err != nil {
		return nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, pwd)
}

// Existing-account flow: ask email+password, then add device, write file, return state.
func (qas *QAClientLoginService) addDeviceToExistingAccount() (*State, error) {
	fmt.Println("=== Add this device to your QuantumAuth account ===")

	email := promptLineWithDefault("Email", qas.defaultEmail)
	deviceLabel := promptLineWithDefault("Device label", qas.defaultDeviceLabel)

	password, err := PromptPassword("Account password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	userID, err := qas.qaClient.GetUserByEmailAndPassword(qas.ctx, email, password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	deviceID, err := qas.registerDevice(email, password, deviceLabel)
	if err != nil {
		return nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, password)
}

func (qas *QAClientLoginService) registerDevice(userEmail string, userPasswordB64 []byte, deviceLabel string) (string, error) {
	deviceID, err := qas.qaClient.RegisterDevice(qas.ctx, userEmail, userPasswordB64, deviceLabel)
	if err != nil {
		return "", fmt.Errorf("register device: %w", err)
	}
	return deviceID, nil
}

// Helper: shared logic for exporting PQ keys, writing creds file, and returning State.
func (qas *QAClientLoginService) persistCredsAndState(
	userID, deviceID, email, deviceLabel string, password []byte,
) (*State, error) {

	pqPubB64, pqPrivB64, err := qas.qaClient.ExportPQKeys()
	if err != nil {
		return nil, fmt.Errorf("export PQ keys: %w", err)
	}

	if err := securefile.WriteEncryptedJSON(qas.path, fileData{
		UserID:       userID,
		DeviceID:     deviceID,
		Email:        email,
		DeviceLabel:  deviceLabel,
		PQPubKeyB64:  pqPubB64,
		PQPrivKeyB64: pqPrivB64,
	}, password, securefile.Options{
		AADFunc: func(_ string) []byte { return []byte("quantumauth:client_identity:v1") },
	}); err != nil {
		return nil, err
	}

	state := &State{
		UserID:   userID,
		DeviceID: deviceID,
	}

	qas.State = state
	log.Info("saved QuantumAuth credentials file", "path", qas.path)
	return state, nil
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

func PromptPassword(prompt string) ([]byte, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)

	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr) // best-effort newline

	if err != nil {
		for i := range pw {
			pw[i] = 0
		}
		return nil, fmt.Errorf("password input failed: %w", err)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	return pw, nil
}

func guessUsername(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// Clear zeroes the password when you logout/shutdown.
func (s *State) Clear() {
	if s == nil {
		return
	}
	s = nil
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

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
