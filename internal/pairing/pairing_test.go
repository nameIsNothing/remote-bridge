package pairing

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"remote-bridge/internal/model"
)

func TestCreateAndConsumeIsOneTime(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Create("device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(credential.Code) != DefaultCodeLength {
		t.Fatalf("code length = %d, want %d", len(credential.Code), DefaultCodeLength)
	}
	if strings.Trim(credential.Code, "0123456789") != "" {
		t.Fatalf("code is not decimal: %q", credential.Code)
	}
	if credential.Pairing.ExpiresAt.Sub(now) != DefaultTTL {
		t.Fatalf("TTL = %s, want %s", credential.Pairing.ExpiresAt.Sub(now), DefaultTTL)
	}
	if err := manager.Consume(credential.Pairing.ID, credential.Code, now.Add(time.Second)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := manager.Consume(credential.Pairing.ID, credential.Code, now.Add(2*time.Second)); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume = %v, want ErrConsumed", err)
	}
	stored, ok := manager.Get(credential.Pairing.ID)
	if !ok || stored.Status != model.PairingStatusConsumed || stored.UsedAt == nil {
		t.Fatalf("stored pairing not consumed: %#v", stored)
	}
}

func TestPairingExpiryAndAttemptLock(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(Options{TTL: time.Minute, CodeLength: 6, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Create("device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(credential.Pairing.ID, "000000", now); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("first bad code = %v", err)
	}
	if err := manager.Consume(credential.Pairing.ID, "111111", now); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second bad code = %v", err)
	}
	if err := manager.Consume(credential.Pairing.ID, credential.Code, now); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked pairing = %v", err)
	}
	stored, _ := manager.Get(credential.Pairing.ID)
	if stored.Status != model.PairingStatusLocked || stored.Attempts != 2 {
		t.Fatalf("lock state = %#v", stored)
	}

	expired, err := manager.Create("device-2", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(expired.Pairing.ID, expired.Code, now.Add(time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("exact expiry = %v", err)
	}
	stored, _ = manager.Get(expired.Pairing.ID)
	if stored.Status != model.PairingStatusExpired {
		t.Fatalf("expiry status = %s", stored.Status)
	}
}

func TestPairingCodeNormalizationAndCredentialJSON(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(Options{CodeLength: 6})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Create("device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	formatted := credential.Code[:3] + "-" + credential.Code[3:]
	if err := manager.Consume(credential.Pairing.ID, " "+formatted+" ", now); err != nil {
		t.Fatalf("formatted code: %v", err)
	}
	data, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["code"]; present {
		t.Fatalf("credential JSON leaked plaintext code: %s", data)
	}
}

func TestConcurrentConsumeOnlyOneWins(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Create("device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.Consume(credential.Pairing.ID, credential.Code, now); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("successful consumes = %d, want 1", wins)
	}
}

func TestGenerateCodeRejectsUnsafeLength(t *testing.T) {
	if _, err := GenerateCode(5); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("short code error = %v", err)
	}
	if _, err := NewManager(Options{CodeLength: 33}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("long code option error = %v", err)
	}
}

func TestHashVerificationUsesConstantTimeDigestPath(t *testing.T) {
	code := "12345678"
	hash := HashCode(code)
	if !VerifyHash(hash, code) || !VerifyCode(code, hash) {
		t.Fatal("valid unsalted code did not verify")
	}
	if VerifyHash(hash, "87654321") {
		t.Fatal("wrong code verified")
	}
	salted := HashCodeWithSalt(code, "salt")
	if !VerifyHashWithSalt(salted, code, "salt") || VerifyHashWithSalt(salted, code, "other") {
		t.Fatal("salted verification mismatch")
	}
}

func TestRevokeIsIdempotentAndRecordsTime(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Create("device-1", now)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := now.Add(30 * time.Second)
	if err := manager.Revoke(credential.Pairing.ID, revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke(credential.Pairing.ID, revokedAt.Add(time.Second)); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	stored, _ := manager.Get(credential.Pairing.ID)
	if stored.Status != model.PairingStatusRevoked || stored.RevokedAt == nil || !stored.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revocation state = %#v", stored)
	}
}
