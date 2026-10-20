// Package pairing implements short-lived, one-time pairing credentials.
//
// Only a salted SHA-256 verifier is retained by Manager.  The plaintext code
// returned by Create is intended to be shown once to the target-machine user
// and kept in memory by the caller; it is never included in model.Pairing or
// connection/plan JSON.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/model"
)

const (
	// DefaultTTL is the lifetime required by the project security boundary.
	DefaultTTL = 10 * time.Minute
	// DefaultCodeLength gives enough entropy for a code that can be typed by a
	// user while remaining practical to read from a console.
	DefaultCodeLength = 8
	// DefaultMaxAttempts limits online guessing of a pairing code.
	DefaultMaxAttempts = 5
)

var (
	ErrNotFound      = errors.New("pairing not found")
	ErrInvalidCode   = errors.New("invalid pairing code")
	ErrExpired       = errors.New("pairing code expired")
	ErrConsumed      = errors.New("pairing code already consumed")
	ErrRevoked       = errors.New("pairing code revoked")
	ErrLocked        = errors.New("pairing code locked")
	ErrInvalidOption = errors.New("invalid pairing option")
	ErrInvalidID     = errors.New("invalid pairing id")
)

// Options controls generated pairing credentials.  A zero Options value is
// replaced with the secure defaults.
type Options struct {
	TTL         time.Duration
	CodeLength  int
	MaxAttempts int
}

// DefaultOptions returns a copy of the default pairing policy.
func DefaultOptions() Options {
	return Options{
		TTL:         DefaultTTL,
		CodeLength:  DefaultCodeLength,
		MaxAttempts: DefaultMaxAttempts,
	}
}

func (o Options) withDefaults() (Options, error) {
	d := DefaultOptions()
	if o.TTL == 0 {
		o.TTL = d.TTL
	}
	if o.CodeLength == 0 {
		o.CodeLength = d.CodeLength
	}
	if o.MaxAttempts == 0 {
		o.MaxAttempts = d.MaxAttempts
	}
	if o.TTL <= 0 || o.CodeLength < 6 || o.CodeLength > 32 || o.MaxAttempts < 1 || o.MaxAttempts > 100 {
		return Options{}, ErrInvalidOption
	}
	return o, nil
}

// Credential is returned exactly once by Manager.Create.  Code is deliberately
// omitted from JSON so accidentally marshaling this value cannot persist a
// plaintext credential.  Use Code directly only for the one-time display or
// handoff to a live CLI process.
type Credential struct {
	Pairing model.Pairing `json:"pairing"`
	Code    string        `json:"-"`
}

// Manager is an in-memory pairing store.  Production callers can persist the
// model.Pairing values in a protected store, but must preserve the same atomic
// consume semantics.
type Manager struct {
	mu      sync.Mutex
	options Options
	items   map[string]*model.Pairing
}

// NewManager creates an empty pairing store.
func NewManager(options Options) (*Manager, error) {
	options, err := options.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Manager{options: options, items: make(map[string]*model.Pairing)}, nil
}

// New is a concise alias for NewManager.
func New(options Options) (*Manager, error) { return NewManager(options) }

// Options returns the immutable policy used by this manager.
func (m *Manager) Options() Options {
	if m == nil {
		return Options{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.options
}

// Create generates and stores a new pairing credential for deviceID.  The
// returned code is the only plaintext representation produced by this call.
func (m *Manager) Create(deviceID string, now time.Time) (Credential, error) {
	if m == nil {
		return Credential{}, ErrInvalidOption
	}
	if strings.TrimSpace(deviceID) == "" {
		return Credential{}, fmt.Errorf("%w: device id is empty", ErrInvalidID)
	}
	code, err := GenerateCode(m.options.CodeLength)
	if err != nil {
		return Credential{}, fmt.Errorf("generate pairing code: %w", err)
	}
	salt, err := randomBytes(16)
	if err != nil {
		return Credential{}, fmt.Errorf("generate pairing salt: %w", err)
	}
	idBytes, err := randomBytes(12)
	if err != nil {
		return Credential{}, fmt.Errorf("generate pairing id: %w", err)
	}
	item := model.Pairing{
		ID:          "pair_" + hex.EncodeToString(idBytes),
		DeviceID:    deviceID,
		CodeHash:    HashCodeWithSalt(code, hex.EncodeToString(salt)),
		CodeSalt:    hex.EncodeToString(salt),
		Status:      model.PairingStatusPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.options.TTL),
		MaxAttempts: m.options.MaxAttempts,
	}
	m.mu.Lock()
	m.items[item.ID] = &item
	m.mu.Unlock()
	return Credential{Pairing: item, Code: code}, nil
}

// CreatePairing is an explicit alias useful to command implementations.
func (m *Manager) CreatePairing(deviceID string, now time.Time) (Credential, error) {
	return m.Create(deviceID, now)
}

// Get returns a copy of a stored pairing record.  It never returns the
// plaintext code.
func (m *Manager) Get(id string) (model.Pairing, bool) {
	if m == nil {
		return model.Pairing{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return model.Pairing{}, false
	}
	return *item, true
}

// Verify checks a code without consuming it.  Failed checks count towards the
// attempt limit, so callers should normally call Consume directly when an
// authorization is actually being established.
func (m *Manager) Verify(id, code string, now time.Time) error {
	if m == nil {
		return ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return ErrNotFound
	}
	return validateAndMaybeConsume(item, code, now, false)
}

// Consume atomically verifies and marks a code as used.  A second call, even
// with the correct code, returns ErrConsumed.
func (m *Manager) Consume(id, code string, now time.Time) error {
	if m == nil {
		return ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return ErrNotFound
	}
	return validateAndMaybeConsume(item, code, now, true)
}

// Revoke invalidates a code immediately.  It is idempotent for an already
// revoked code and returns ErrConsumed for a code that has already been used.
func (m *Manager) Revoke(id string, now time.Time) error {
	if m == nil {
		return ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return ErrNotFound
	}
	if item.Status == model.PairingStatusConsumed {
		return ErrConsumed
	}
	if item.Status == model.PairingStatusRevoked {
		return nil
	}
	item.Status = model.PairingStatusRevoked
	if item.RevokedAt == nil {
		t := now
		item.RevokedAt = &t
	}
	return nil
}

// GenerateCode returns a cryptographically random decimal code.  Rejection
// sampling avoids the modulo bias that would otherwise favor some digits.
func GenerateCode(length int) (string, error) {
	if length < 6 || length > 32 {
		return "", ErrInvalidOption
	}
	const alphabet = "0123456789"
	const limit = byte(250) // largest multiple of 10 below 256
	result := make([]byte, length)
	buf := make([]byte, length)
	for filled := 0; filled < length; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			result[filled] = alphabet[int(b)%len(alphabet)]
			filled++
			if filled == length {
				break
			}
		}
	}
	return string(result), nil
}

// NormalizeCode removes visual separators and surrounding whitespace.  Codes
// otherwise consist only of ASCII decimal digits.
func NormalizeCode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

// HashCode computes an unsalted SHA-256 verifier for callers that need a
// deterministic digest.  Manager-generated records use HashCodeWithSalt.
func HashCode(code string) string { return HashCodeWithSalt(code, "") }

// HashPairingCode is a descriptive alias for HashCode.
func HashPairingCode(code string) string { return HashCode(code) }

// HashCodeWithSalt computes the stored verifier.  Salt is treated as an
// opaque string so it can be represented safely in JSON.
func HashCodeWithSalt(code, salt string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(salt))
	_, _ = h.Write([]byte(NormalizeCode(code)))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHash checks an unsalted digest using a constant-time comparison.
// Manager-generated records should be checked through Manager.Verify so their
// salt and attempt counter are applied.
func VerifyHash(storedHash, code string) bool {
	want := HashCode(code)
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(storedHash))), []byte(want)) == 1
}

// VerifyHashWithSalt checks a salted digest using a constant-time comparison.
func VerifyHashWithSalt(storedHash, code, salt string) bool {
	want := HashCodeWithSalt(code, salt)
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(storedHash))), []byte(want)) == 1
}

// VerifyCode is a code-first alias for VerifyHash.
func VerifyCode(code, storedHash string) bool { return VerifyHash(storedHash, code) }

// Validate checks a standalone model.Pairing and mutates its attempt/status
// fields when an invalid code is presented.  Manager methods are preferred
// when multiple goroutines may consume the same pairing.
func Validate(item *model.Pairing, code string, now time.Time) error {
	return validateAndMaybeConsume(item, code, now, false)
}

// Consume validates and consumes a standalone model.Pairing.  This helper is
// useful when a caller owns persistence and can save the updated record after
// this function returns.
func Consume(item *model.Pairing, code string, now time.Time) error {
	return validateAndMaybeConsume(item, code, now, true)
}

func validateAndMaybeConsume(item *model.Pairing, code string, now time.Time, consume bool) error {
	if item == nil || item.ID == "" {
		return ErrNotFound
	}
	switch item.Status {
	case model.PairingStatusConsumed:
		return ErrConsumed
	case model.PairingStatusRevoked:
		return ErrRevoked
	case model.PairingStatusLocked:
		return ErrLocked
	case model.PairingStatusExpired:
		return ErrExpired
	}
	if !now.Before(item.ExpiresAt) {
		item.Status = model.PairingStatusExpired
		return ErrExpired
	}
	if item.MaxAttempts > 0 && item.Attempts >= item.MaxAttempts {
		item.Status = model.PairingStatusLocked
		return ErrLocked
	}
	want := HashCodeWithSalt(code, item.CodeSalt)
	if subtle.ConstantTimeCompare([]byte(want), []byte(item.CodeHash)) != 1 {
		item.Attempts++
		if item.MaxAttempts > 0 && item.Attempts >= item.MaxAttempts {
			item.Status = model.PairingStatusLocked
		}
		return ErrInvalidCode
	}
	if consume {
		item.Status = model.PairingStatusConsumed
		t := now
		item.UsedAt = &t
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
