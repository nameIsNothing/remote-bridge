package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"remote-bridge/internal/diagnostic"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/sshclient"
)

func (r *sshTargetRuntime) Pair(ctx context.Context, request discovery.PairRequest, source *net.UDPAddr) discovery.PairResponse {
	response := discovery.PairResponse{V: discovery.Version, Type: discovery.PairResponseType, RequestNonce: request.RequestNonce}
	if r == nil {
		response.Reason = "SSH 入口不存在"
		return response
	}
	response.InstanceID = r.id
	if ctx == nil {
		ctx = context.Background()
	}
	if source == nil || source.IP.To4() == nil || request.InstanceID != r.id || ctx.Err() != nil || !time.Now().Before(r.expiresAt) {
		response.Reason = "连接入口或请求已失效"
		return response
	}
	if err := sshclient.ValidatePublicKey(request.PublicKey); err != nil {
		response.Reason = "公钥格式无效"
		return response
	}
	r.pairMu.Lock()
	defer r.pairMu.Unlock()
	deadline := time.Now().Add(time.Minute)
	if !request.ConfirmUntil.IsZero() {
		deadline = request.ConfirmUntil
	}
	if deadline.After(r.expiresAt) {
		deadline = r.expiresAt
	}
	if !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Minute)) {
		response.Reason = "连接确认请求已过期或有效期无效"
		return response
	}
	confirmCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	key := canonicalSSHPublicKey(request.PublicKey)
	address := source.IP.String()
	manager := request.ManagerHostname + " (" + address + ")"
	if r.approved == nil {
		r.approved = make(map[string]string)
	}
	approvalID := key + "\x00" + address
	if r.approved[approvalID] != address {
		r.emit(guiEvent{Kind: "request", Detail: "请在确认窗口允许或取消本次连接。", Manager: manager})
		text := fmt.Sprintf("管理端：%s\r\n地址：%s\r\n\r\n允许后，该管理端可在本次入口有效期内执行命令，后续命令无需再次确认。\r\n请求有效期至 %s；只允许你认识的管理端。", request.ManagerHostname, address, deadline.Local().Format("15:04:05"))
		accepted := false
		if r.confirm != nil {
			accepted = r.confirm(confirmCtx, text)
		} else {
			accepted = confirmSSHPairing(request.ManagerHostname, source)
		}
		if !accepted || confirmCtx.Err() != nil || !time.Now().Before(r.expiresAt) {
			response.Reason = "已取消本次连接"
			if confirmCtx.Err() != nil {
				response.Reason = "本次确认已过期，请管理端重新连接"
			}
			r.emit(guiEvent{Kind: "rejected", Detail: response.Reason})
			r.audit("target.ssh.pair", false, address)
			return response
		}
	}
	if confirmCtx.Err() != nil {
		response.Reason = "本次确认已失效"
		return response
	}
	data, err := os.ReadFile(r.keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "pair.authorization.failed", Step: "读取授权文件", Instance: r.id, Error: err.Error()})
		response.Reason = "读取授权文件失败"
		return response
	}
	if !authorizedSSHKeyPresent(string(data), key, address) {
		file, err := os.OpenFile(r.keyPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "pair.authorization.failed", Step: "打开授权文件", Instance: r.id, Error: err.Error()})
			response.Reason = "写入授权公钥失败"
			return response
		}
		_, writeErr := fmt.Fprintf(file, "from=\"%s\" %s remote-bridge-manager\n", address, key)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "pair.authorization.failed", Step: "写入授权文件", Instance: r.id, Error: errors.Join(writeErr, closeErr).Error()})
			response.Reason = "写入授权公钥失败"
			return response
		}
	}
	r.approved[approvalID] = address
	r.emit(guiEvent{Kind: "approved", Manager: manager})
	r.watchAuthentication()
	r.audit("target.ssh.pair", true, address)
	response.Accepted, response.Hostname, response.Port, response.Username, response.ExpiresAt, response.HostKey = true, localHostname(), r.port, r.username, r.expiresAt, r.hostKey
	return response
}

func canonicalSSHPublicKey(key string) string {
	parts := strings.Fields(key)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + " " + parts[1]
}
func authorizedSSHKeyPresent(data, key, address string) bool {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "from=\""+address+"\"" && fields[1]+" "+fields[2] == key {
			return true
		}
	}
	return false
}
