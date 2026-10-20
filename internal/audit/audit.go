// Package audit writes small local JSONL lifecycle records.  It deliberately
// stores command digests and step IDs rather than command text or output, so a
// diagnostic command cannot accidentally turn the audit file into a secret
// store.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"remote-bridge/internal/model"
)

// DefaultPath returns a per-user, metadata-only audit path.  It does not
// create the directory; Append does that only when an operation is recorded.
func DefaultPath() string {
	if cache, err := os.UserCacheDir(); err == nil && strings.TrimSpace(cache) != "" {
		return filepath.Join(cache, "RemoteBridge", "audit.jsonl")
	}
	return "remote-bridge-audit.jsonl"
}

// Append appends one audit event with restrictive file permissions.  The
// caller should treat a write failure as a warning for this experimental
// client, not as permission to persist credentials elsewhere.
func Append(path string, event model.AuditEvent) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("audit path is empty")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(data, '\n'))
	return err
}

// Digest returns a stable non-secret identifier for command text.  It lets
// operators correlate repeated commands without copying passwords or tokens
// from a command line into an audit file.
func Digest(command string) string {
	hash := sha256.Sum256([]byte(command))
	return hex.EncodeToString(hash[:])
}
