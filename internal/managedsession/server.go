package managedsession

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AuditFunc func(kind, command string, code int, success bool) error

type Server struct {
	mu                             sync.Mutex
	info                           Info
	clientToken, workerToken       string
	fingerprint                    string
	server                         *http.Server
	listener                       net.Listener
	work                           chan Work
	pending                        map[string]chan WorkerMessage
	ready, closing, done           chan struct{}
	readyOnce, closeOnce, doneOnce sync.Once
	audit                          AuditFunc
}

func RandomID(prefix string, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func NewServer(info Info, audit AuditFunc) (*Server, error) {
	now := time.Now()
	if !IDPattern.MatchString(info.ID) || info.InstanceID == "" || info.Target == "" || info.Hostname == "" || info.Username == "" ||
		!info.ExpiresAt.After(now) || !validTransport(info, now) {
		return nil, errors.New("托管会话绑定或有效期无效")
	}
	token, err := RandomID("", 32)
	if err != nil {
		return nil, err
	}
	workerToken, err := RandomID("", 32)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	certificate, fingerprint, err := localCertificate(info.ExpiresAt)
	if err != nil {
		listener.Close()
		return nil, err
	}
	info.State, info.CreatedAt = "connecting", now.UTC()
	s := &Server{info: info, clientToken: token, workerToken: workerToken, fingerprint: fingerprint, listener: listener, audit: audit,
		work: make(chan Work, 1), pending: make(map[string]chan WorkerMessage), ready: make(chan struct{}), closing: make(chan struct{}), done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/call", s.call)
	mux.HandleFunc("/v1/worker", s.worker)
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 130 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		_ = s.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}))
	}()
	go func() {
		timer := time.NewTimer(time.Until(info.ExpiresAt))
		defer timer.Stop()
		select {
		case <-timer.C:
			s.BeginClose("会话已到期")
		case <-s.done:
		}
	}()
	return s, nil
}

func validTransport(info Info, now time.Time) bool {
	switch info.Transport {
	case "", "winrm":
		return (info.Port == 5985 || info.Port == 5986) && info.Shell == "" && info.UID == "" && !info.ExpiresAt.After(now.Add(MaxLifetime))
	case "ssh":
		return info.Port > 0 && info.Port <= 65535 && info.Shell == "posix" && ValidUnixUID(info.UID) && info.SID == "" && !info.ExpiresAt.After(now.Add(MaxSSHLifetime))
	default:
		return false
	}
}

// ValidUnixUID accepts a canonical, non-root Unix account identity.
func ValidUnixUID(value string) bool {
	uid, err := strconv.ParseUint(value, 10, 32)
	return err == nil && uid > 0 && strconv.FormatUint(uid, 10) == value
}

// Ready binds an authenticated worker to the endpoint and account selected
// before the local API was opened. The in-process SSH worker and the external
// WinRM worker share this transition and all subsequent command checks.
func (s *Server) Ready(info Info) error {
	s.mu.Lock()
	valid := s.info.State == "connecting" && info.InstanceID == s.info.InstanceID &&
		time.Now().Before(info.ExpiresAt) && !info.ExpiresAt.After(s.info.ExpiresAt)
	if s.info.Transport == "ssh" {
		valid = valid && info.ID == s.info.ID && info.Target == s.info.Target && info.Port == s.info.Port &&
			info.Transport == "ssh" && info.Shell == "posix" && info.Hostname == s.info.Hostname && info.Username == s.info.Username &&
			ValidUnixUID(info.UID) && info.UID == s.info.UID && info.SID == ""
	} else {
		valid = valid && strings.EqualFold(info.Hostname, s.info.Hostname) && strings.EqualFold(info.Username, s.info.Username) &&
			strings.HasPrefix(info.SID, "S-1-") && info.UID == "" && info.Shell == "" && info.Transport == s.info.Transport &&
			(info.ID == "" || info.ID == s.info.ID) && (info.Target == "" || info.Target == s.info.Target) && (info.Port == 0 || info.Port == s.info.Port)
	}
	if valid {
		s.info.SID, s.info.UID = info.SID, info.UID
		s.info.ExpiresAt, s.info.State = info.ExpiresAt, "connected"
	}
	s.mu.Unlock()
	if !valid {
		s.BeginClose("认证身份、实例或期限不匹配")
		return errors.New("binding mismatch")
	}
	s.readyOnce.Do(func() { close(s.ready) })
	return nil
}

// NextWork is used by the manager-owned SSH worker. Only local code can call
// it; external workers must authenticate through the loopback HTTPS endpoint.
func (s *Server) NextWork(ctx context.Context) Work {
	select {
	case <-s.closing:
		return Work{Operation: "close"}
	default:
	}
	select {
	case <-s.closing:
		return Work{Operation: "close"}
	case work := <-s.work:
		return work
	case <-ctx.Done():
		return Work{Operation: "idle"}
	}
}

func (s *Server) CompleteWork(id string, result *Result, err error) {
	message := WorkerMessage{ID: id, Result: result}
	if err != nil {
		message.Error = err.Error()
	}
	s.mu.Lock()
	ch := s.pending[id]
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- message:
		default:
		}
	}
}

func localCertificate(expiry time.Time) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Remote Bridge local session"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	hash := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(hash[:]), nil
}
func (s *Server) Endpoint() string    { return "https://" + s.listener.Addr().String() }
func (s *Server) WorkerToken() string { return s.workerToken }
func (s *Server) Info() Info          { s.mu.Lock(); defer s.mu.Unlock(); return s.info }
func (s *Server) Record() Record {
	return Record{Info: s.Info(), Endpoint: s.Endpoint(), Token: s.clientToken, Fingerprint: s.fingerprint}
}
func (s *Server) Done() <-chan struct{}    { return s.done }
func (s *Server) Closing() <-chan struct{} { return s.closing }
func (s *Server) WaitReady(ctx context.Context) error {
	select {
	case <-s.ready:
		if s.Info().State != "connected" {
			return ErrClosed
		}
		return nil
	case <-s.done:
		return fmt.Errorf("%w：%s", ErrClosed, s.Info().Reason)
	case <-ctx.Done():
		s.BeginClose("连接已取消或超时")
		return ctx.Err()
	}
}
func (s *Server) BeginClose(reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.info.State, s.info.Reason = "closing", reason
		s.mu.Unlock()
		close(s.closing)
	})
}
func (s *Server) Finish(reason string) {
	s.doneOnce.Do(func() {
		s.BeginClose(reason)
		s.mu.Lock()
		s.info.State = "closed"
		if reason != "" {
			s.info.Reason = reason
		}
		for _, ch := range s.pending {
			select {
			case ch <- WorkerMessage{Error: ErrClosed.Error()}:
			default:
			}
		}
		s.mu.Unlock()
		close(s.done)
	})
}
func (s *Server) Shutdown() { s.Finish(""); _ = s.server.Close() }

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, token string) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || r.Host != s.listener.Addr().String() {
		http.Error(w, "local clients only", http.StatusForbidden)
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "POST application/json required", http.StatusMethodNotAllowed)
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return true
}
func readJSON(w http.ResponseWriter, r *http.Request, out any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func (s *Server) reply(w http.ResponseWriter, result *Result, err error) {
	response := Response{Info: s.Info(), Result: result}
	if err != nil {
		response.Error = err.Error()
	}
	_ = json.NewEncoder(w).Encode(response)
}
func (s *Server) call(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.clientToken) {
		return
	}
	var request Request
	if err := readJSON(w, r, &request, 6*MaxCommand+2048); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	switch request.Operation {
	case "status":
		s.reply(w, nil, nil)
	case "close":
		s.BeginClose("管理端已结束会话")
		select {
		case <-s.done:
			s.reply(w, nil, nil)
		case <-time.After(6 * time.Second):
			s.reply(w, nil, errors.New("已停止接受命令，正在等待连接清理"))
		}
	case "exec":
		result, err := s.execute(r.Context(), request)
		s.reply(w, result, err)
	default:
		s.reply(w, nil, errors.New("不支持的会话操作"))
	}
}
func (s *Server) execute(ctx context.Context, request Request) (result *Result, returnErr error) {
	if strings.TrimSpace(request.Command) == "" || len(request.Command) > MaxCommand || strings.ContainsRune(request.Command, 0) {
		return nil, errors.New("命令为空、过长或包含 NUL")
	}
	if request.Timeout == 0 {
		request.Timeout = 30
	}
	if request.Timeout < 1 || request.Timeout > 120 {
		return nil, errors.New("命令超时必须为 1–120 秒")
	}
	s.mu.Lock()
	if s.info.State != "connected" || !time.Now().Before(s.info.ExpiresAt) {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.pending) > 0 {
		s.mu.Unlock()
		return nil, ErrBusy
	}
	id, err := RandomID("", 12)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	ch := make(chan WorkerMessage, 1)
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock() }()
	if s.audit != nil {
		if err := s.audit("manager.session.command.started", request.Command, 0, false); err != nil {
			return nil, fmt.Errorf("无法记录命令审计，未执行：%w", err)
		}
	}
	defer func() {
		if s.audit != nil {
			code := -1
			if result != nil {
				code = result.ExitCode
			}
			if err := s.audit("manager.session.command.finished", request.Command, code, returnErr == nil && code == 0); err != nil {
				s.BeginClose("审计写入失败")
				returnErr = fmt.Errorf("命令已执行，但结果审计写入失败：%w", err)
			}
		}
	}()
	select {
	case s.work <- Work{Operation: "exec", ID: id, Command: request.Command, Timeout: request.Timeout}:
	case <-s.closing:
		returnErr = ErrClosed
		return nil, returnErr
	}
	timer := time.NewTimer(time.Duration(request.Timeout+10) * time.Second)
	defer timer.Stop()
	select {
	case message := <-ch:
		if message.Error != "" {
			returnErr = errors.New(message.Error)
			return nil, returnErr
		}
		if message.Result == nil || len(message.Result.Stdout) > MaxOutput || len(message.Result.Stderr) > MaxOutput {
			returnErr = errors.New("执行结果无效或过长")
			s.BeginClose(returnErr.Error())
			return nil, returnErr
		}
		result = message.Result
		return result, nil
	case <-ctx.Done():
		returnErr = ctx.Err()
		s.BeginClose("调用已取消")
		return nil, returnErr
	case <-timer.C:
		returnErr = errors.New("执行超时，已结束托管会话")
		s.BeginClose(returnErr.Error())
		return nil, returnErr
	case <-s.closing:
		returnErr = ErrClosed
		return nil, returnErr
	}
}
func (s *Server) worker(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, s.workerToken) {
		return
	}
	var message WorkerMessage
	if err := readJSON(w, r, &message, 8*MaxOutput+16384); err != nil {
		http.Error(w, "invalid worker message", 400)
		return
	}
	switch message.Operation {
	case "ready":
		if message.Info == nil || s.Ready(*message.Info) != nil {
			s.BeginClose("认证身份、实例或期限不匹配")
			http.Error(w, "binding mismatch", 409)
			return
		}
		_ = json.NewEncoder(w).Encode(Work{Operation: "idle"})
	case "next":
		select {
		case <-s.closing:
			_ = json.NewEncoder(w).Encode(Work{Operation: "close"})
			return
		default:
		}
		select {
		case <-s.closing:
			_ = json.NewEncoder(w).Encode(Work{Operation: "close"})
		case task := <-s.work:
			_ = json.NewEncoder(w).Encode(task)
		case <-time.After(time.Second):
			_ = json.NewEncoder(w).Encode(Work{Operation: "idle"})
		case <-r.Context().Done():
		}
	case "result":
		s.mu.Lock()
		ch := s.pending[message.ID]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- message:
			default:
			}
		}
		_ = json.NewEncoder(w).Encode(Work{Operation: "idle"})
	case "closing":
		s.BeginClose("管理端已结束会话")
		_ = json.NewEncoder(w).Encode(Work{Operation: "close"})
	case "closed":
		s.Finish(message.Error)
		_ = json.NewEncoder(w).Encode(Work{Operation: "close"})
	default:
		http.Error(w, "unsupported worker operation", 400)
	}
}
