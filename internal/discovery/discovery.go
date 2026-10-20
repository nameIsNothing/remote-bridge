// Package discovery implements the small, LAN-only UDP discovery protocol
// used by Remote Bridge. Discovery packets contain connection metadata only;
// credentials and state paths are deliberately not part of the wire format.
package discovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	Version = 1

	// DefaultPort is the UDP port used by the target responder and manager
	// discovery listener. It is intentionally separate from WinRM's port.
	DefaultPort = 37020

	QueryType        = "discover"
	AnnouncementType = "announce"
	PairRequestType  = "pair_request"
	PairResponseType = "pair_response"

	DefaultDiscoverTimeout = 2 * time.Second
	MaxPacketSize          = 16 * 1024
)

var (
	ErrInvalidMessage = errors.New("invalid discovery message")
	ErrInvalidAddress = errors.New("invalid discovery address")
)

// Query is a manager-to-target broadcast request. RequestNonce binds
// responses to one discovery attempt and prevents replaying an old response.
type Query struct {
	V            int    `json:"v"`
	Type         string `json:"type"`
	RequestNonce string `json:"request_nonce"`
}

// PairRequest asks a visible target to authorize one management-machine SSH
// public key. The public key is not a secret; the corresponding private key
// remains on the manager. A target must still apply its local authorization
// policy before writing the key to authorized_keys.
type PairRequest struct {
	V               int       `json:"v"`
	Type            string    `json:"type"`
	InstanceID      string    `json:"instance_id"`
	RequestNonce    string    `json:"request_nonce"`
	ManagerID       string    `json:"manager_id"`
	ManagerHostname string    `json:"manager_hostname"`
	PublicKey       string    `json:"public_key"`
	ConfirmUntil    time.Time `json:"confirm_until,omitempty"`
}

// PairResponse contains only public connection metadata and the target host
// public key. It never contains a password or private key.
type PairResponse struct {
	V            int       `json:"v"`
	Type         string    `json:"type"`
	InstanceID   string    `json:"instance_id"`
	RequestNonce string    `json:"request_nonce"`
	Accepted     bool      `json:"accepted"`
	Reason       string    `json:"reason,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	Port         int       `json:"port,omitempty"`
	Username     string    `json:"username,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	HostKey      string    `json:"host_key,omitempty"`
}

// PairHandler is called by a target responder after a valid pair request is
// received. The handler owns authorization and key installation; returning a
// response with Accepted=false declines the request.
type PairHandler func(context.Context, PairRequest, *net.UDPAddr) PairResponse

// Announcement is target metadata returned to the manager. Never add a
// password, token, state path, or command/script field to this structure.
type Announcement struct {
	V            int       `json:"v"`
	Type         string    `json:"type"`
	InstanceID   string    `json:"instance_id"`
	Hostname     string    `json:"hostname"`
	Addresses    []string  `json:"addresses"`
	Port         int       `json:"port"`
	Transport    string    `json:"transport"`
	Username     string    `json:"username"`
	ExpiresAt    time.Time `json:"expires_at"`
	RequestNonce string    `json:"request_nonce"`
}

// NewQuery creates a query with a cryptographically random nonce.
func NewQuery() (Query, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Query{}, fmt.Errorf("generate discovery nonce: %w", err)
	}
	q := Query{V: Version, Type: QueryType, RequestNonce: hex.EncodeToString(b)}
	return q, nil
}

func (q Query) Validate() error {
	if q.V != Version || q.Type != QueryType || !validNonce(q.RequestNonce) {
		return fmt.Errorf("%w: invalid query", ErrInvalidMessage)
	}
	return nil
}

func (r PairRequest) Validate() error {
	if r.V != Version || r.Type != PairRequestType || !validNonce(r.RequestNonce) {
		return fmt.Errorf("%w: invalid pair request header", ErrInvalidMessage)
	}
	if !validText(r.InstanceID, 128) || !validText(r.ManagerID, 128) || !validText(r.ManagerHostname, 255) {
		return fmt.Errorf("%w: missing pair request identity", ErrInvalidMessage)
	}
	if !validPublicKeyText(r.PublicKey) {
		return fmt.Errorf("%w: invalid pair public key", ErrInvalidMessage)
	}
	return nil
}

func (r PairResponse) Validate() error {
	if r.V != Version || r.Type != PairResponseType || !validNonce(r.RequestNonce) {
		return fmt.Errorf("%w: invalid pair response header", ErrInvalidMessage)
	}
	if !validText(r.InstanceID, 128) {
		return fmt.Errorf("%w: missing pair response identity", ErrInvalidMessage)
	}
	if r.Accepted {
		if !validText(r.Hostname, 255) || r.Port < 1 || r.Port > 65535 || !validText(r.Username, 256) || r.ExpiresAt.IsZero() || !validPublicKeyText(r.HostKey) {
			return fmt.Errorf("%w: accepted pair response is incomplete", ErrInvalidMessage)
		}
	} else if r.Reason != "" && !validText(r.Reason, 512) {
		return fmt.Errorf("%w: invalid pair response reason", ErrInvalidMessage)
	}
	return nil
}

func (a Announcement) Validate() error {
	if a.V != Version || a.Type != AnnouncementType {
		return fmt.Errorf("%w: invalid announcement header", ErrInvalidMessage)
	}
	if !validText(a.InstanceID, 128) || !validText(a.Hostname, 255) || !validText(a.Username, 256) {
		return fmt.Errorf("%w: missing announcement identity", ErrInvalidMessage)
	}
	if len(a.Addresses) == 0 || len(a.Addresses) > 32 {
		return fmt.Errorf("%w: announcement addresses are invalid", ErrInvalidMessage)
	}
	for _, raw := range a.Addresses {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("%w: announcement address %q is invalid", ErrInvalidMessage, raw)
		}
	}
	if a.Port < 1 || a.Port > 65535 || !validText(a.Transport, 32) || strings.ContainsAny(a.Transport, " \t\r\n") {
		return fmt.Errorf("%w: announcement endpoint is invalid", ErrInvalidMessage)
	}
	if a.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: announcement expiry is required", ErrInvalidMessage)
	}
	if a.RequestNonce != "" && !validNonce(a.RequestNonce) {
		return fmt.Errorf("%w: announcement nonce is invalid", ErrInvalidMessage)
	}
	return nil
}

// Expired reports whether an announcement can still be used at now.
func (a Announcement) Expired(now time.Time) bool {
	return !now.Before(a.ExpiresAt)
}

func MarshalQuery(q Query) ([]byte, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(q)
}

func MarshalPairRequest(r PairRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func UnmarshalPairRequest(data []byte) (PairRequest, error) {
	var r PairRequest
	if err := decode(data, &r); err != nil {
		return PairRequest{}, err
	}
	if err := r.Validate(); err != nil {
		return PairRequest{}, err
	}
	return r, nil
}

func MarshalPairResponse(r PairResponse) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func UnmarshalPairResponse(data []byte) (PairResponse, error) {
	var r PairResponse
	if err := decode(data, &r); err != nil {
		return PairResponse{}, err
	}
	if err := r.Validate(); err != nil {
		return PairResponse{}, err
	}
	return r, nil
}

func UnmarshalQuery(data []byte) (Query, error) {
	var q Query
	if err := decode(data, &q); err != nil {
		return Query{}, err
	}
	if err := q.Validate(); err != nil {
		return Query{}, err
	}
	return q, nil
}

func MarshalAnnouncement(a Announcement) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

func UnmarshalAnnouncement(data []byte) (Announcement, error) {
	var a Announcement
	if err := decode(data, &a); err != nil {
		return Announcement{}, err
	}
	if err := a.Validate(); err != nil {
		return Announcement{}, err
	}
	return a, nil
}

func decode(data []byte, out any) error {
	if len(data) == 0 || len(data) > MaxPacketSize {
		return fmt.Errorf("%w: packet size", ErrInvalidMessage)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidMessage)
	}
	return nil
}

// ParseBroadcastAddress validates an IPv4 broadcast/directed-broadcast
// address and returns the destination used by Discover.
func ParseBroadcastAddress(address string, port int) (*net.UDPAddr, error) {
	if strings.TrimSpace(address) == "" {
		address = "255.255.255.255"
	}
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || ip.To4() == nil || ip.IsMulticast() || ip.IsUnspecified() {
		return nil, fmt.Errorf("%w: %q must be an IPv4 broadcast address", ErrInvalidAddress, address)
	}
	if port == 0 {
		port = DefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port is invalid", ErrInvalidAddress)
	}
	return &net.UDPAddr{IP: ip.To4(), Port: port}, nil
}

// ServeResponder reads queries from conn and replies to each valid query's
// source address. The caller owns conn; cancellation stops the loop without
// closing it.
func ServeResponder(ctx context.Context, conn *net.UDPConn, announcement Announcement) error {
	return ServeResponderWithPairing(ctx, conn, announcement, nil)
}

// ServeResponderWithPairing serves discovery and optional SSH pairing
// requests on the same visible, short-lived UDP socket. Pairing is disabled
// when handler is nil, preserving the original metadata-only responder.
func ServeResponderWithPairing(ctx context.Context, conn *net.UDPConn, announcement Announcement, handler PairHandler) error {
	if conn == nil {
		return errors.New("discovery responder: nil connection")
	}
	if announcement.RequestNonce != "" {
		announcement.RequestNonce = ""
	}
	if err := announcement.Validate(); err != nil {
		return err
	}
	buf := make([]byte, MaxPacketSize)
	pairPending := make(chan struct{}, 1)
	for {
		if err := setReadDeadline(ctx, conn, 500*time.Millisecond); err != nil {
			return err
		}
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		messageType, err := packetType(buf[:n])
		if err != nil {
			continue
		}
		switch messageType {
		case QueryType:
			q, err := UnmarshalQuery(buf[:n])
			if err != nil {
				continue
			}
			response := announcement
			response.RequestNonce = q.RequestNonce
			payload, err := MarshalAnnouncement(response)
			if err != nil {
				return err
			}
			if _, err := conn.WriteToUDP(payload, source); err != nil && ctx.Err() != nil {
				return nil
			}
		case PairRequestType:
			if handler == nil {
				continue
			}
			request, err := UnmarshalPairRequest(buf[:n])
			if err != nil || request.InstanceID != announcement.InstanceID {
				continue
			}
			select {
			case pairPending <- struct{}{}:
				// One bounded confirmation may be pending. Discovery remains
				// responsive while the target user is reading the dialog.
				go func(request PairRequest, source *net.UDPAddr) {
					defer func() { <-pairPending }()
					response := handler(ctx, request, source)
					response.V, response.Type, response.InstanceID, response.RequestNonce = Version, PairResponseType, announcement.InstanceID, request.RequestNonce
					if payload, err := MarshalPairResponse(response); err == nil && ctx.Err() == nil {
						_, _ = conn.WriteToUDP(payload, source)
					}
				}(request, source)
			default:
				response := PairResponse{V: Version, Type: PairResponseType, InstanceID: announcement.InstanceID, RequestNonce: request.RequestNonce, Reason: "目标机正在确认另一条连接请求，请稍后重试"}
				if payload, err := MarshalPairResponse(response); err == nil {
					_, _ = conn.WriteToUDP(payload, source)
				}
			}
		}
	}
}

// Pair sends one pairing request to a discovered target and waits for the
// response matching its nonce and instance ID.
func Pair(ctx context.Context, conn *net.UDPConn, target *net.UDPAddr, request PairRequest) (PairResponse, error) {
	if conn == nil || target == nil {
		return PairResponse{}, errors.New("pair: nil connection or target")
	}
	if err := request.Validate(); err != nil {
		return PairResponse{}, err
	}
	payload, err := MarshalPairRequest(request)
	if err != nil {
		return PairResponse{}, err
	}
	if _, err := conn.WriteToUDP(payload, target); err != nil {
		return PairResponse{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultDiscoverTimeout)
		defer cancel()
	}
	buf := make([]byte, MaxPacketSize)
	for {
		if err := setReadDeadline(ctx, conn, 250*time.Millisecond); err != nil {
			return PairResponse{}, err
		}
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				if ctx.Err() != nil {
					return PairResponse{}, ctx.Err()
				}
				continue
			}
			return PairResponse{}, err
		}
		if !source.IP.Equal(target.IP) || source.Port != target.Port {
			continue
		}
		response, err := UnmarshalPairResponse(buf[:n])
		if err != nil || response.InstanceID != request.InstanceID || response.RequestNonce != request.RequestNonce {
			continue
		}
		return response, nil
	}
}

// Discover broadcasts one query and collects valid announcements until ctx
// expires. Results are deduplicated by instance ID and sorted for stable CLI
// output. If ctx has no deadline, DefaultDiscoverTimeout is used.
func Discover(ctx context.Context, conn *net.UDPConn, broadcastAddress string, port int) ([]Announcement, error) {
	if conn == nil {
		return nil, errors.New("discovery: nil connection")
	}
	destination, err := ParseBroadcastAddress(broadcastAddress, port)
	if err != nil {
		return nil, err
	}
	query, err := NewQuery()
	if err != nil {
		return nil, err
	}
	payload, err := MarshalQuery(query)
	if err != nil {
		return nil, err
	}
	if err := conn.SetWriteBuffer(MaxPacketSize); err != nil {
		return nil, err
	}
	if _, err := conn.WriteToUDP(payload, destination); err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultDiscoverTimeout)
		defer cancel()
	}
	results := make(map[string]Announcement)
	buf := make([]byte, MaxPacketSize)
	for {
		if err := setReadDeadline(ctx, conn, 250*time.Millisecond); err != nil {
			return nil, err
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				if ctx.Err() != nil {
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						return sortedAnnouncements(results), nil
					}
					return sortedAnnouncements(results), ctx.Err()
				}
				continue
			}
			return nil, err
		}
		a, err := UnmarshalAnnouncement(buf[:n])
		if err != nil || a.RequestNonce != query.RequestNonce || a.Expired(time.Now()) {
			continue
		}
		if _, exists := results[a.InstanceID]; !exists {
			results[a.InstanceID] = a
		}
	}
}

func sortedAnnouncements(items map[string]Announcement) []Announcement {
	result := make([]Announcement, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].InstanceID < result[j].InstanceID })
	return result
}

func setReadDeadline(ctx context.Context, conn *net.UDPConn, poll time.Duration) error {
	deadline := time.Now().Add(poll)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetReadDeadline(deadline)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func validNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validText(value string, max int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= max && !strings.ContainsAny(value, "\r\n")
}

func validPublicKeyText(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 16*1024 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	parts := strings.Fields(value)
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	if parts[0] != "ssh-ed25519" && parts[0] != "ssh-rsa" && !strings.HasPrefix(parts[0], "ecdsa-sha2-") {
		return false
	}
	// A strict base64 decode here prevents shell syntax from entering an
	// authorized_keys line; cryptographic key-type validation remains the
	// responsibility of sshd/ssh-keygen on the target.
	_, err := base64.StdEncoding.DecodeString(parts[1])
	return err == nil
}

func packetType(data []byte) (string, error) {
	var header struct {
		Type string `json:"type"`
	}
	if len(data) == 0 || len(data) > MaxPacketSize {
		return "", fmt.Errorf("%w: packet size", ErrInvalidMessage)
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", err
	}
	if header.Type == QueryType || header.Type == PairRequestType {
		return header.Type, nil
	}
	return "", fmt.Errorf("%w: unsupported packet type", ErrInvalidMessage)
}
