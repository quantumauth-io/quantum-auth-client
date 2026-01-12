package login

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
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
	InfuraAPIKey string `json:"infura_api_key"`
}

// State is kept in memory while the client runs.
type State struct {
	UserID       string
	DeviceID     string
	InfuraAPIKey string
}

type PreflightInputs struct {
	Email       string
	Username    string
	DeviceLabel string
	InfuraKey   string
	Password    []byte
}

type PreflightFunc func(ctx context.Context, in PreflightInputs) error

type QAClientLoginService struct {
	ctx                context.Context
	qaClient           *qa.Client
	path               string // canonical write path
	defaultEmail       string
	defaultDeviceLabel string
	State              *State
	preflight          PreflightFunc
}

func (qas *QAClientLoginService) SetPreflight(fn PreflightFunc) {
	qas.preflight = fn
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
// It only prompts for a password if an existing identity file is found.
func (qas *QAClientLoginService) EnsureLogin() (*State, []byte, error) {
	paths, err := securefile.ConfigPathCandidates(constants.AppName, constants.ClientIdentityFile)
	if err != nil {
		return nil, nil, err
	}

	// Canonical write path for this env
	qas.path = paths[0]

	// Find an existing identity file (strict env only)
	foundPath := ""
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		} else if os.IsNotExist(err) {
			continue
		} else {
			return nil, nil, fmt.Errorf("stat creds file %s: %w", p, err)
		}
	}

	// No file => first-time setup (no password prompt yet)
	if foundPath == "" {
		log.Info("no QuantumAuth credentials file found, running first-time setup", "write_path", qas.path)
		state, pwd, err := qas.handleMissingCreds() // this should set password as part of setup
		if err != nil {
			return nil, nil, err
		}
		qas.State = state
		return state, pwd, nil
	}

	// File exists => prompt + decrypt
	qas.path = foundPath

	pwd, err := PromptPassword("QuantumAuth password: ")
	if err != nil {
		return nil, nil, err
	}

	return qas.EnsureLoginWithPassword(pwd)
}

// EnsureLoginWithPassword is called on client startup.
func (qas *QAClientLoginService) EnsureLoginWithPassword(password []byte) (*State, []byte, error) {
	paths, err := securefile.ConfigPathCandidates(constants.AppName, constants.ClientIdentityFile)
	if err != nil {
		return nil, nil, err
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
			return nil, nil, fmt.Errorf("stat creds file %s: %w", p, err)
		}
	}

	if foundPath == "" {
		log.Info("no QuantumAuth credentials file found, running first-time setup", "write_path", qas.path)
		state, pwd, err := qas.handleMissingCreds()
		if err != nil {
			return nil, nil, err
		}
		qas.State = state
		return state, pwd, nil
	}

	// Found in this env; use it for read/decrypt
	qas.path = foundPath
	log.Info("found QuantumAuth credentials file", "path", qas.path)

	store, err := userwallet.NewStore()
	if err != nil {
		return nil, nil, err
	}

	_, err = store.Ensure(password)
	if err != nil {
		return nil, nil, err
	}

	sealer := tpmdevice.NewSealer("")
	devStore, err := ethdevice.NewStore(sealer)
	if err != nil {
		return nil, nil, err
	}

	_, err = devStore.Ensure(qas.ctx)
	if err != nil {
		return nil, nil, err
	}

	sealer = tpmdevice.NewSealer("")
	fd, err := securefile.ReadEncryptedJSONAuto[fileData](qas.ctx, foundPath, password, securefile.Options{
		TPMSealer: sealer,
		TPMLabel:  "quantumauth:client_identity:dek:v1",
		AADFunc:   func(_ string) []byte { return []byte("quantumauth:client_identity:v2") },
	})
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt creds file %s: %w", foundPath, err)
	}

	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qas.qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
			return nil, nil, fmt.Errorf("load PQ keys from creds file: %w", err)
		}
	}

	state := &State{UserID: fd.UserID, DeviceID: fd.DeviceID, InfuraAPIKey: fd.InfuraAPIKey}

	// FullLogin is for backend authentication/session.
	// If it fails (network/back-end unreachable), do NOT block local wallet usage.
	if err := qas.qaClient.FullLogin(qas.ctx, state.UserID, state.DeviceID, password); err != nil {
		// Keep creds + PQ keys loaded; just warn that backend features are unavailable.
		log.Warn("backend login unavailable; continuing in offline mode (wallet still usable)", "error", err)
	} else {
		log.Info("successfully logged in to backend", "user", state.UserID)
	}

	qas.State = state
	return state, password, nil
}

// When no credentials file exists, offer the user two paths:
// 1) Create a new account (first-time setup)
// 2) Add this device to an existing account
func (qas *QAClientLoginService) handleMissingCreds() (*State, []byte, error) {
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
				return nil, nil, err
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
func (qas *QAClientLoginService) firstTimeSetup() (*State, []byte, error) {
	fmt.Println("=== QuantumAuth first-time setup ===")

	email := promptLineWithDefault("Email", qas.defaultEmail)
	username := promptLineWithDefault("Username", guessUsername(email))
	deviceLabel := promptLineWithDefault("Device label", qas.defaultDeviceLabel)

	pwd, err := PromptPassword("Choose a password: ")
	if err != nil {
		return nil, nil, fmt.Errorf("read password: %w", err)
	}

	infuraKey, err := promptInfuraAPIKey()
	if err != nil {
		return nil, nil, fmt.Errorf("read infura api key: %w", err)
	}
	// ✅ PRE-FLIGHT: run all local/chain checks BEFORE creating remote user/email
	if qas.preflight != nil {
		if err := qas.preflight(qas.ctx, PreflightInputs{
			Email:       email,
			Username:    username,
			DeviceLabel: deviceLabel,
			InfuraKey:   infuraKey,
			Password:    pwd,
		}); err != nil {
			return nil, nil, fmt.Errorf("preflight failed: %w", err)
		}
	}

	userID, err := qas.qaClient.RegisterUser(qas.ctx, email, pwd, username)
	if err != nil {
		return nil, nil, fmt.Errorf("register user: %w", err)
	}

	deviceID, err := qas.registerDevice(email, pwd, deviceLabel)
	if err != nil {
		return nil, nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, pwd, infuraKey)
}

// Existing-account flow: ask email+password, then add device, write file, return state.
func (qas *QAClientLoginService) addDeviceToExistingAccount() (*State, []byte, error) {
	fmt.Println("=== Add this device to your QuantumAuth account ===")

	email := promptLineWithDefault("Email", qas.defaultEmail)
	deviceLabel := promptLineWithDefault("Device label", qas.defaultDeviceLabel)

	password, err := PromptPassword("Account password: ")
	if err != nil {
		return nil, nil, fmt.Errorf("read password: %w", err)
	}

	infuraKey, err := promptInfuraAPIKey()
	if err != nil {
		return nil, nil, fmt.Errorf("read infura api key: %w", err)
	}

	userID, err := qas.qaClient.GetUserByEmailAndPassword(qas.ctx, email, password)
	if err != nil {
		return nil, nil, fmt.Errorf("login failed: %w", err)
	}

	deviceID, err := qas.registerDevice(email, password, deviceLabel)
	if err != nil {
		return nil, nil, err
	}

	return qas.persistCredsAndState(userID, deviceID, email, deviceLabel, password, infuraKey)
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
	userID, deviceID, email, deviceLabel string, password []byte, infuraKey string) (*State, []byte, error) {

	pqPubB64, pqPrivB64, err := qas.qaClient.ExportPQKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("export PQ keys: %w", err)
	}

	sealer := tpmdevice.NewSealer("")
	err = securefile.WriteEncryptedJSONAuto(qas.ctx, qas.path, fileData{
		UserID:       userID,
		DeviceID:     deviceID,
		Email:        email,
		DeviceLabel:  deviceLabel,
		PQPubKeyB64:  pqPubB64,
		PQPrivKeyB64: pqPrivB64,
		InfuraAPIKey: infuraKey}, password, securefile.Options{
		TPMSealer: sealer,
		TPMLabel:  "quantumauth:client_identity:dek:v1",
		AADFunc:   func(_ string) []byte { return []byte("quantumauth:client_identity:v2") },
	})

	if err != nil {
		return nil, nil, fmt.Errorf("write state: %w", err)
	}

	state := &State{
		UserID:       userID,
		DeviceID:     deviceID,
		InfuraAPIKey: infuraKey,
	}

	qas.State = state
	log.Info("saved QuantumAuth credentials file", "path", qas.path)
	return state, password, nil
}

func promptInfuraAPIKey() (string, error) {
	fmt.Println()
	fmt.Println("=== Ethereum RPC Provider Setup ===")
	fmt.Println("QuantumAuth uses Infura for default Ethereum RPC access.")
	fmt.Println()
	fmt.Println("Create a free Infura account and API key here:")
	fmt.Println("👉 https://www.infura.io/register")
	fmt.Println()

	for {
		key := promptLineWithDefault("Enter your Infura API Key", "")

		key = strings.TrimSpace(key)
		if key == "" {
			fmt.Println("Infura API key cannot be empty.")
			continue
		}

		return key, nil
	}
}

func promptLineWithDefault(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return def
	}

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
