// Package diagnostic writes bounded, metadata-only troubleshooting logs.
// Callers supply lifecycle events, never commands, arguments or output.
package diagnostic

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Directory, Filename, Version, Mode string
	MaxBytes                           int64
}

type Event struct {
	Level      string `json:"level"`
	Event      string `json:"event"`
	Step       string `json:"step,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Instance   string `json:"instance,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
}

type Logger struct {
	mu                  sync.Mutex
	path, version, mode string
	maxBytes            int64
	secrets             []string
}

var filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$`)

func New(options Options) (*Logger, error) {
	if !filenamePattern.MatchString(options.Filename) || filepath.Base(options.Filename) != options.Filename {
		return nil, errors.New("invalid diagnostic filename")
	}
	if strings.TrimSpace(options.Directory) == "" {
		return nil, errors.New("diagnostic directory is empty")
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, err
	}
	if err := validatePath(directory, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, options.Filename)
	if err := validatePath(path, false); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	maxBytes := options.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	return &Logger{path: path, version: options.Version, mode: options.Mode, maxBytes: maxBytes}, nil
}

func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// AddSecret registers a program-generated secret in memory only. It is never
// serialized; exact occurrences are removed before formatting a log record.
func (l *Logger) AddSecret(secret string) {
	if l == nil || secret == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, secret)
}

// Sanitize uses the same known-secret filter for visible diagnostics.
func (l *Logger) Sanitize(value string) string {
	if l == nil {
		return Sanitize(value)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sanitize(value)
}

func (l *Logger) sanitize(value string) string {
	value = decodePowerShellError(value)
	for _, secret := range l.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return sanitizeDecoded(value)
}

func (l *Logger) Log(event Event) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sanitize := l.sanitize
	event.Level, event.Event = sanitize(event.Level), sanitize(event.Event)
	event.Step, event.Phase, event.Instance = sanitize(event.Step), sanitize(event.Phase), sanitize(event.Instance)
	event.Message, event.Error = sanitize(event.Message), sanitize(event.Error)
	if event.Level == "" {
		event.Level = "info"
	}
	record := struct {
		Time    string `json:"time"`
		PID     int    `json:"pid"`
		Version string `json:"version"`
		Mode    string `json:"mode"`
		Event
	}{Time: time.Now().UTC().Format(time.RFC3339Nano), PID: os.Getpid(), Version: sanitize(l.version), Mode: sanitize(l.mode), Event: event}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := validatePath(l.path, false); err != nil {
		return err
	}
	if info, err := os.Stat(l.path); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil && info.Size() > 0 && info.Size()+int64(len(data)) > l.maxBytes {
		backup := l.path + ".1"
		if err := validatePath(backup, false); err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(l.path, backup); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

// Reject links, Windows junctions and unexpected file types rather than
// following a user-supplied log location during an elevated configuration.
func validatePath(path string, directory bool) error {
	leaf := true
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if pathIsLink(current, info) {
				return fmt.Errorf("diagnostic path is a link or reparse point: %s", current)
			}
			if !leaf || directory {
				if !info.IsDir() {
					return fmt.Errorf("diagnostic parent is not a directory: %s", current)
				}
			} else if !info.Mode().IsRegular() {
				return fmt.Errorf("diagnostic file is not regular: %s", current)
			}
		}
		if filepath.Dir(current) == current {
			return nil
		}
		leaf = false
	}
}
