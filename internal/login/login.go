package login

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
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
func (qas *QAClientLoginService) EnsureLogin() (*State, error) {
	// after you set qas.path = paths[0] (canonical write location)

	paths, err := credsFilePathCandidates()
	if err != nil {
		return nil, fmt.Errorf("get credential paths: %w", err)
	}
	if len(paths) > 0 {
		qas.path = paths[0]
	}

	// Find any existing creds file path (we’ll decrypt, not read raw json)
	var foundPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		} else if !os.IsNotExist(err) {
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

	pwd, err := promptPassword("QuantumAuth password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	defer zero(pwd)

	fd, err := readCredsFileEncrypted(foundPath, pwd)
	if err != nil {
		return nil, fmt.Errorf("decrypt creds file %s: %w", foundPath, err)
	}

	if fd.PQPubKeyB64 != "" && fd.PQPrivKeyB64 != "" {
		if err := qas.qaClient.LoadPQKeys(fd.PQPubKeyB64, fd.PQPrivKeyB64); err != nil {
			return nil, fmt.Errorf("load PQ keys from creds file: %w", err)
		}
	}

	state := &State{
		UserID:   fd.UserID,
		DeviceID: fd.DeviceID,
	}

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
	userID, deviceID, email, deviceLabel string, password []byte,
) (*State, error) {

	pqPubB64, pqPrivB64, err := qas.qaClient.ExportPQKeys()
	if err != nil {
		return nil, fmt.Errorf("export PQ keys: %w", err)
	}

	if err := writeCredsFileEncrypted(qas.path, fileData{
		UserID:       userID,
		DeviceID:     deviceID,
		Email:        email,
		DeviceLabel:  deviceLabel,
		PQPubKeyB64:  pqPubB64,
		PQPrivKeyB64: pqPrivB64,
	}, password); err != nil {
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

func writeCredsFileEncrypted(path string, fd fileData, password []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	plain, err := json.MarshalIndent(fd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal creds: %w", err)
	}

	// salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("rand salt: %w", err)
	}

	k := argon2.IDKey(password, salt,
		defaultKDF.ArgonTime,
		defaultKDF.ArgonMemory,
		defaultKDF.ArgonThreads,
		defaultKDF.ArgonKeyLen,
	)

	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return fmt.Errorf("aead: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand nonce: %w", err)
	}

	// Optional: bind encryption to the file path (acts as associated data).
	// If you move the file, decryption will fail. If you don't want that, set aad=nil.
	var aad []byte = nil

	ct := aead.Seal(nil, nonce, plain, aad)

	out := defaultKDF
	out.SaltB64 = base64.StdEncoding.EncodeToString(salt)
	out.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	out.CTB64 = base64.StdEncoding.EncodeToString(ct)

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enc file: %w", err)
	}

	// Atomic write: tmp -> rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write tmp creds file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename creds file: %w", err)
	}
	return nil
}

func readCredsFileEncrypted(path string, password []byte) (fileData, error) {
	var ef encFile
	b, err := os.ReadFile(path)
	if err != nil {
		return fileData{}, fmt.Errorf("read creds file: %w", err)
	}
	if err := json.Unmarshal(b, &ef); err != nil {
		return fileData{}, fmt.Errorf("unmarshal enc file: %w", err)
	}
	if ef.Version != 1 {
		return fileData{}, fmt.Errorf("unsupported creds file version: %d", ef.Version)
	}

	salt, err := base64.StdEncoding.DecodeString(ef.SaltB64)
	if err != nil {
		return fileData{}, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ef.NonceB64)
	if err != nil {
		return fileData{}, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ef.CTB64)
	if err != nil {
		return fileData{}, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := argon2.IDKey(password, salt, ef.ArgonTime, ef.ArgonMemory, ef.ArgonThreads, ef.ArgonKeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fileData{}, fmt.Errorf("aead: %w", err)
	}

	var aad []byte = nil // no path
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		// Keep this error generic; don't leak whether password was "close".
		return fileData{}, errors.New("invalid password or corrupted creds file")
	}

	var fd fileData
	if err := json.Unmarshal(plain, &fd); err != nil {
		return fileData{}, fmt.Errorf("unmarshal creds: %w", err)
	}
	return fd, nil
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

func promptPassword(prompt string) ([]byte, error) {
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

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
