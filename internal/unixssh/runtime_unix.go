//go:build darwin || linux

package unixssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/model"
	"remote-bridge/internal/sshclient"
)

type Inspection struct {
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Hostname     string   `json:"hostname"`
	Username     string   `json:"username"`
	UID          int      `json:"uid"`
	SSHD         string   `json:"sshd"`
	Addresses    []string `json:"addresses"`
	Subnets      []string `json:"subnets"`
}

func localUser(name string) (*user.User, error) {
	var u *user.User
	var e error
	if name != "" {
		u, e = user.Lookup(name)
	} else if os.Geteuid() == 0 {
		u, e = user.Lookup(os.Getenv("SUDO_USER"))
	} else {
		u, e = user.Current()
	}
	if e != nil {
		return nil, e
	}
	if _, e = parseUID(u.Uid); e != nil {
		return nil, e
	}
	if !userPattern.MatchString(u.Username) {
		return nil, errors.New("unsupported account name")
	}
	return u, nil
}
func inspect(u *user.User) (Inspection, error) {
	host, _ := os.Hostname()
	uid, _ := parseUID(u.Uid)
	p := Inspection{OS: runtime.GOOS, Architecture: runtime.GOARCH, Hostname: host, Username: u.Username, UID: uid, SSHD: "/usr/sbin/sshd"}
	if st, e := os.Stat(p.SSHD); e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return p, errors.New("system /usr/sbin/sshd is unavailable; install OpenSSH server using your system's normal setup")
	}
	ifs, e := net.Interfaces()
	if e != nil {
		return p, e
	}
	seen := map[string]bool{}
	for _, in := range ifs {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, _ := in.Addrs()
		for _, a := range as {
			ip, n, e := net.ParseCIDR(a.String())
			if e != nil || ip.To4() == nil || !ip.IsPrivate() {
				continue
			}
			p.Addresses = append(p.Addresses, ip.To4().String())
			if !seen[n.String()] {
				p.Subnets = append(p.Subnets, n.String())
				seen[n.String()] = true
			}
		}
	}
	if len(p.Addresses) == 0 {
		return p, errors.New("no private LAN IPv4; connect Wi-Fi or Ethernet first")
	}
	return p, nil
}

// Run keeps explicit CLI confirmation; --start represents opening the visible
// USB launcher and requires an interactive terminal before normal sudo.
func Run(args []string) int {
	fs := flag.NewFlagSet("bridge-target ssh", flag.ContinueOnError)
	ttl := MaxLifetime
	port := 2222
	check := false
	start := false
	fs.DurationVar(&ttl, "ttl", ttl, "入口期限，最多3h")
	fs.IntVar(&port, "port", port, "临时SSH端口，默认2222")
	fs.BoolVar(&check, "inspect", false, "只读检查并输出JSON")
	fs.BoolVar(&start, "start", false, "从交互式启动器直接开始，保留sudo与配对确认")
	if fs.Parse(args) != nil || fs.NArg() != 0 || ttl < 5*time.Second || ttl > MaxLifetime || port < 1024 || port > 65535 {
		return 2
	}
	u, e := localUser("")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	p, e := inspect(u)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 20
	}
	if check {
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Printf("Remote Bridge — %s / %s\n主机：%s\n账号：%s（普通Shell权限）\n局域网地址：%s\n", p.OS, p.Architecture, p.Hostname, p.Username, strings.Join(p.Addresses, ", "))
	fmt.Printf("连接将使用独立临时SSH端口%d，有效期%s。\n需要正常sudo授权，只创建本次临时目录和进程。\n首次配对需确认管理端；结束或到期回收本次入口。\n现有系统SSH、账号、密钥及防火墙不作改写。\n", port, ttl)
	if start {
		if !interactiveTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "直接启动需要交互式终端，请从目标电脑打开启动器；只读检查可用 ssh --inspect。")
			return 2
		}
		fmt.Println("已从启动器开始连接，正在请求系统授权…")
	} else {
		fmt.Print("输入 y 并回车开始连接，其他输入取消：")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.EqualFold(strings.TrimSpace(line), "y") {
			fmt.Println("已取消。")
			return 0
		}
	}
	executable, e := os.Executable()
	if e != nil {
		return 50
	}
	executable, e = filepath.EvalSymlinks(executable)
	if e != nil {
		return 50
	}
	internal := []string{executable, "ssh-unix-run", "--user", u.Username, "--uid", u.Uid, "--ttl", ttl.String(), "--port", strconv.Itoa(port)}
	if os.Geteuid() != 0 {
		sudo := "/usr/bin/sudo"
		if _, e = os.Stat(sudo); e != nil {
			fmt.Fprintln(os.Stderr, "sudo unavailable; an administrator must launch this tool normally")
			return 11
		}
		e = syscall.Exec(sudo, append([]string{sudo, "--"}, internal...), os.Environ())
		fmt.Fprintln(os.Stderr, e)
		return 11
	}
	return Controller(internal[2:])
}

func runtimeBase() string {
	if runtime.GOOS == "darwin" {
		return "/private/var"
	}
	return "/var/lib"
}
func rootOwned(path string, dir bool) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	return rootOwnedInfo(path, st, dir)
}

func rootOwnedInfo(path string, st os.FileInfo, dir bool) error {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) {
		return fmt.Errorf("untrusted root-owned path: %s", path)
	}
	return nil
}

// OpenSSH StrictModes checks every canonical ancestor of authorized_keys,
// including a sticky /tmp or /var/tmp above a private root-owned directory.
// Fail before preparing an entry rather than weakening those checks.
func checkRootDirectoryChain(path string, stat func(string) (os.FileInfo, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("runtime directory must be canonical and absolute")
	}
	for current := path; ; current = filepath.Dir(current) {
		st, err := stat(current)
		if err != nil {
			return err
		}
		if err = rootOwnedInfo(current, st, true); err != nil {
			return err
		}
		if st.Mode().Perm()&0001 == 0 {
			return fmt.Errorf("remote account cannot traverse runtime parent: %s", current)
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func validateRuntime(dir string) error {
	base, e := filepath.EvalSymlinks(runtimeBase())
	if e != nil {
		return e
	}
	if filepath.Dir(dir) != base || !strings.HasPrefix(filepath.Base(dir), "RemoteBridge-") || !instancePattern.MatchString(strings.TrimPrefix(filepath.Base(dir), "RemoteBridge-")) {
		return errors.New("runtime path outside owned namespace")
	}
	return checkRootDirectoryChain(dir, os.Lstat)
}
func programCopy(dir string) error {
	src, e := os.Executable()
	if e != nil {
		return e
	}
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(filepath.Join(dir, "bridge-target"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	return errors.Join(e, out.Chmod(0755), out.Close())
}
func secureLog(instance string) (string, error) {
	base := "/var/log"
	if runtime.GOOS == "darwin" {
		base = "/private/var/log"
	}
	dir := filepath.Join(base, "RemoteBridge")
	if e := os.Mkdir(dir, 0755); e != nil && !errors.Is(e, os.ErrExist) {
		return "", e
	}
	if e := rootOwned(dir, true); e != nil {
		return "", e
	}
	return filepath.Join(dir, instance+".jsonl"), nil
}
func appendEvent(path, kind, instance, address, command string, code int, ok bool) error {
	meta := map[string]string{"instance_id": instance, "source": address, "exit_code": strconv.Itoa(code)}
	if command != "" {
		meta["command_hash"] = audit.Digest(command)
		meta["command_length"] = strconv.Itoa(len(command))
	}
	return audit.Append(path, model.AuditEvent{Type: kind, Success: ok, Metadata: meta})
}

func Controller(args []string) (code int) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "normal sudo authorization is required")
		return 11
	}
	fs := flag.NewFlagSet("ssh-unix-run", flag.ContinueOnError)
	name, uidText := "", ""
	ttl := MaxLifetime
	port := 2222
	fs.StringVar(&name, "user", "", "local account")
	fs.StringVar(&uidText, "uid", "", "local uid")
	fs.DurationVar(&ttl, "ttl", ttl, "lifetime")
	fs.IntVar(&port, "port", port, "port")
	if fs.Parse(args) != nil || fs.NArg() != 0 || ttl < 5*time.Second || ttl > MaxLifetime {
		return 2
	}
	u, e := localUser(name)
	if e != nil || u.Uid != uidText {
		fmt.Fprintln(os.Stderr, "local account binding mismatch")
		return 11
	}
	p, e := inspect(u)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 20
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	var random [12]byte
	if _, e = rand.Read(random[:]); e != nil {
		return 50
	}
	id := "usb-" + hex.EncodeToString(random[:])
	base, e := filepath.EvalSymlinks(runtimeBase())
	if e != nil {
		return 50
	}
	if e = checkRootDirectoryChain(base, os.Lstat); e != nil {
		fmt.Fprintln(os.Stderr, "SSH运行目录不满足严格权限要求：", e)
		return 50
	}
	dir := filepath.Join(base, "RemoteBridge-"+id)
	if e = os.Mkdir(dir, 0755); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 50
	}
	if e = os.Chmod(dir, 0755); e != nil {
		return 50
	}
	// Only the freshly created, root-owned exact directory is removed.
	defer func() {
		if validateRuntime(dir) == nil {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintln(os.Stderr, "回收目录失败：", err)
				code = 50
			}
		}
	}()
	log, e := secureLog(id)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 50
	}
	shell := "/bin/sh"
	if runtime.GOOS == "darwin" {
		shell = "/bin/zsh"
	} else {
		shell = "/bin/bash"
		if _, e = os.Stat(shell); e != nil {
			shell = "/bin/sh"
		}
	}
	now := time.Now().UTC()
	l := Lease{Version: 1, Instance: id, Username: u.Username, UID: uid, GID: gid, Shell: shell, Addresses: p.Addresses, Subnets: p.Subnets, Port: port, CreatedAt: now, ExpiresAt: now.Add(ttl), UpdatedAt: now, Active: true}
	config, e := Config(l, dir)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if e = appendEvent(log, "target.unix.prepare", id, "", "", 0, true); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 50
	}
	for name, contents := range map[string]string{"sshd_config": config, "authorized_keys": ""} {
		perm := os.FileMode(0600)
		if name == "authorized_keys" {
			perm = 0644
		}
		if e = os.WriteFile(filepath.Join(dir, name), []byte(contents), perm); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 50
		}
		if e = os.Chmod(filepath.Join(dir, name), perm); e != nil {
			return 50
		}
	}
	if e = programCopy(dir); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 50
	}
	keygen := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "host"))
	keygen.Stdin = strings.NewReader("")
	if out, e := keygen.CombinedOutput(); e != nil {
		fmt.Fprintln(os.Stderr, "主机密钥生成失败：", e, string(out))
		return 50
	}
	if e = writeLease(dir, l); e != nil {
		return 50
	}
	check := exec.Command(p.SSHD, "-t", "-f", filepath.Join(dir, "sshd_config"))
	check.Stdin = strings.NewReader("")
	if out, e := check.CombinedOutput(); e != nil {
		fmt.Fprintln(os.Stderr, "独立SSHD检查失败：", e, string(out))
		return 20
	}
	hostPub, e := os.ReadFile(filepath.Join(dir, "host.pub"))
	if e != nil {
		return 50
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	ctx, deadlineCancel := context.WithDeadline(ctx, l.ExpiresAt)
	defer deadlineCancel()
	guardRead, guardWrite, e := os.Pipe()
	if e != nil {
		return 50
	}
	defer guardRead.Close()
	defer guardWrite.Close()
	guardian := exec.Command(filepath.Join(dir, "bridge-target"), "ssh-unix-host", dir)
	guardian.ExtraFiles = []*os.File{guardRead}
	guardian.Stdin = strings.NewReader("")
	guardian.Stdout, guardian.Stderr = os.Stdout, os.Stderr
	if e = guardian.Start(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 20
	}
	_ = guardRead.Close()
	guardianDone := make(chan error, 1)
	go func() { guardianDone <- guardian.Wait() }()
	var auditSocket net.Listener
	defer func() {
		l.Active = false
		l.UpdatedAt = time.Now().UTC()
		_ = writeLease(dir, l)
		_ = guardWrite.Close()
		select {
		case e := <-guardianDone:
			if e != nil {
				code = 50
			}
		case <-time.After(9 * time.Second):
			_ = guardian.Process.Kill()
			code = 50
		}
		if auditSocket != nil {
			_ = auditSocket.Close()
		}
		_ = appendEvent(log, "target.unix.closed", id, "", "", code, code == 0)
		fmt.Printf("本次入口已结束。审计：%s\n", log)
	}()
	ready := time.NewTimer(12 * time.Second)
	defer ready.Stop()
waitReady:
	for {
		select {
		case <-ctx.Done():
			return 20
		case e := <-guardianDone:
			guardianDone <- e
			fmt.Fprintln(os.Stderr, "SSHD提前退出：", e)
			return 20
		case <-ready.C:
			fmt.Fprintln(os.Stderr, "SSH就绪超时")
			return 20
		case <-time.After(100 * time.Millisecond):
			if _, e = os.Stat(filepath.Join(dir, "ready")); e == nil {
				break waitReady
			}
		}
	}
	socket, e := startAuditSocket(context.Background(), dir, l, log)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 50
	}
	auditSocket = socket
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{Port: discovery.DefaultPort})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 20
	}
	defer conn.Close()
	announcement := discovery.Announcement{V: discovery.Version, Type: discovery.AnnouncementType, InstanceID: id, Hostname: p.Hostname, Addresses: p.Addresses, Port: port, Transport: "ssh", Username: u.Username, Shell: "posix", ExpiresAt: l.ExpiresAt}
	r := &pairRuntime{lease: l, dir: dir, hostKey: strings.TrimSpace(string(hostPub)), hostname: p.Hostname, log: log, approved: map[string]bool{}, requests: make(chan pairPrompt, 1)}
	discoveryDone := make(chan error, 1)
	go func() {
		discoveryDone <- discovery.ServeResponderWithPairingFrom(ctx, conn, announcement, r.pair, l.Allows)
	}()
	fmt.Printf("SSH入口已开启：%s@%s:%d\n实例：%s\n有效至：%s\n日志：%s\n管理端：bridge-cli ssh --target %s --manage\n等待配对；按回车 / Ctrl+C 结束。\n", l.Username, l.Addresses[0], l.Port, id, l.ExpiresAt.Local().Format("15:04:05"), log, l.Addresses[0])
	// A single reader owns the terminal, so pairing cannot consume the close key.
	lines := make(chan string)
	go func() {
		rd := bufio.NewReader(os.Stdin)
		for {
			line, e := rd.ReadString('\n')
			if e != nil {
				close(lines)
				return
			}
			select {
			case lines <- strings.TrimSpace(line):
			case <-ctx.Done():
				return
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var pending *pairPrompt
	for {
		select {
		case <-ctx.Done():
			return 0
		case e := <-guardianDone:
			guardianDone <- e
			fmt.Fprintln(os.Stderr, "SSH服务已停止：", e)
			return 20
		case e := <-discoveryDone:
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
			}
			return 20
		case prompt := <-r.requests:
			pending = &prompt
			fmt.Printf("\n允许管理端 %s (%s) 连接？\n公钥指纹：%s\n请求至 %s；输入 y 允许，其他输入拒绝：", prompt.name, prompt.address, prompt.fingerprint, prompt.deadline.Local().Format("15:04:05"))
		case line, ok := <-lines:
			if !ok {
				return 0
			}
			if pending == nil {
				if line == "" {
					return 0
				}
				fmt.Println("当前没有待确认请求；按回车可结束入口。")
				continue
			}
			pending.answer <- strings.EqualFold(line, "y") && time.Now().Before(pending.deadline)
			pending = nil
			fmt.Println("继续等待连接；按回车结束。")
		case <-ticker.C:
			l.UpdatedAt = time.Now().UTC()
			if e = writeLease(dir, l); e != nil {
				fmt.Fprintln(os.Stderr, "入口心跳失败：", e)
				return 50
			}
			if pending != nil && !time.Now().Before(pending.deadline) {
				select {
				case pending.answer <- false:
				default:
				}
				pending = nil
				fmt.Println("配对请求已过期；按回车结束。")
			}
		}
	}
}

type pairPrompt struct {
	name, address, fingerprint string
	deadline                   time.Time
	answer                     chan bool
}
type pairRuntime struct {
	lease                       Lease
	dir, hostKey, hostname, log string
	mu                          sync.Mutex
	approved                    map[string]bool
	requests                    chan pairPrompt
}

func (r *pairRuntime) pair(ctx context.Context, q discovery.PairRequest, source *net.UDPAddr) discovery.PairResponse {
	out := discovery.PairResponse{InstanceID: r.lease.Instance, Reason: "请求无效或不在本地子网"}
	latest, leaseErr := readLease(r.dir)
	if source == nil || !r.lease.Allows(source.IP) || q.InstanceID != r.lease.Instance || leaseErr != nil || latest.Check(time.Now(), r.lease.UID) != nil || sshclient.ValidatePublicKey(q.PublicKey) != nil {
		return out
	}
	deadline := q.ConfirmUntil
	if deadline.IsZero() {
		deadline = time.Now().Add(time.Minute)
	}
	if deadline.After(r.lease.ExpiresAt) {
		deadline = r.lease.ExpiresAt
	}
	if !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Minute)) {
		return out
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fields := strings.Fields(q.PublicKey)
	key := fields[0] + " " + fields[1]
	address := source.IP.To4().String()
	approval := address + "\x00" + key
	if !r.approved[approval] {
		prompt := pairPrompt{name: q.ManagerHostname, address: address, fingerprint: audit.Digest(key), deadline: deadline, answer: make(chan bool, 1)}
		select {
		case r.requests <- prompt:
		case <-ctx.Done():
			return out
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		accepted := false
		select {
		case accepted = <-prompt.answer:
		case <-ctx.Done():
			return out
		case <-timer.C:
		}
		if !accepted || !time.Now().Before(deadline) {
			out.Reason = "目标用户已拒绝本次连接"
			if !time.Now().Before(deadline) {
				out.Reason = "本次确认已过期，请重新连接"
			}
			_ = appendEvent(r.log, "target.unix.pair", r.lease.Instance, address, "", 11, false)
			return out
		}
		if e := appendEvent(r.log, "target.unix.pair", r.lease.Instance, address, "", 0, true); e != nil {
			out.Reason = "审计失败，未授权"
			return out
		}
		f, e := os.OpenFile(filepath.Join(r.dir, "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0644)
		if e != nil {
			return out
		}
		_, e = fmt.Fprintf(f, "restrict,pty,from=\"%s\",expiry-time=\"%s\" %s remote-bridge\n", address, r.lease.ExpiresAt.Local().Format("20060102150405"), key)
		e = errors.Join(e, f.Close())
		if e != nil {
			out.Reason = "临时授权写入失败"
			return out
		}
		r.approved[approval] = true
	}
	out.Accepted = true
	out.Reason = ""
	out.Hostname = r.hostname
	out.Port = r.lease.Port
	out.Username = r.lease.Username
	out.ExpiresAt = r.lease.ExpiresAt
	out.HostKey = r.hostKey
	out.Shell = "posix"
	return out
}

// Guardian owns the sshd process and a pipe held only by the visible controller.
// EOF stops admission even after SIGKILL of the controller; it is never a service.
func Guardian(dir string) int {
	if os.Geteuid() != 0 || validateRuntime(dir) != nil {
		return 11
	}
	l, e := readLease(dir)
	if e != nil {
		return 11
	}
	control := os.NewFile(3, "controller-lifetime")
	if control == nil {
		return 11
	}
	defer control.Close()
	ended := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, control); close(ended) }()
	cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e = cmd.Start(); e != nil {
		return 20
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		l.Active = false
		l.UpdatedAt = time.Now().UTC()
		_ = writeLease(dir, l)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		time.Sleep(HeartbeatGrace + time.Second)
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	timeout := time.NewTimer(time.Until(l.ExpiresAt))
	defer timeout.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	ready := false
	for {
		select {
		case <-ended:
			return 0
		case <-ctx.Done():
			return 0
		case <-timeout.C:
			return 0
		case e := <-done:
			done <- e
			return 20
		case <-poll.C:
			if ready {
				continue
			}
			conn, e := net.DialTimeout("tcp4", net.JoinHostPort(l.Addresses[0], strconv.Itoa(l.Port)), 200*time.Millisecond)
			if e != nil {
				continue
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			line, e := bufio.NewReader(conn).ReadString('\n')
			conn.Close()
			if e == nil && strings.HasPrefix(line, "SSH-2.0-") {
				if os.WriteFile(filepath.Join(dir, "ready"), []byte("ready\n"), 0600) != nil {
					return 50
				}
				ready = true
			}
		}
	}
}

type sessionAudit struct {
	Kind          string `json:"kind"`
	CommandHash   string `json:"command_hash"`
	CommandLength int    `json:"command_length"`
	ExitCode      int    `json:"exit_code"`
	Source        string `json:"source"`
}

func startAuditSocket(ctx context.Context, dir string, l Lease, path string) (net.Listener, error) {
	listener, e := net.Listen("unix", filepath.Join(dir, "audit.sock"))
	if e != nil {
		return nil, e
	}
	if e = os.Chown(filepath.Join(dir, "audit.sock"), l.UID, l.GID); e == nil {
		e = os.Chmod(filepath.Join(dir, "audit.sock"), 0600)
	}
	if e != nil {
		listener.Close()
		return nil, e
	}
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var msg sessionAudit
			e = json.NewDecoder(io.LimitReader(conn, 2048)).Decode(&msg)
			if e == nil && (msg.Kind == "target.unix.command.started" || msg.Kind == "target.unix.command.finished") && len(msg.CommandHash) == 64 && msg.CommandLength >= 0 && msg.CommandLength <= 65536 {
				e = audit.Append(path, model.AuditEvent{Type: msg.Kind, Success: msg.Kind == "target.unix.command.finished" && msg.ExitCode == 0, Metadata: map[string]string{"instance_id": l.Instance, "command_hash": msg.CommandHash, "command_length": strconv.Itoa(msg.CommandLength), "exit_code": strconv.Itoa(msg.ExitCode), "source": msg.Source}})
				if e == nil {
					_, _ = io.WriteString(conn, "ok\n")
				}
			}
			conn.Close()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	return listener, nil
}
func sendSessionAudit(dir string, event sessionAudit) error {
	c, e := net.DialTimeout("unix", filepath.Join(dir, "audit.sock"), time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if e = json.NewEncoder(c).Encode(event); e != nil {
		return e
	}
	line, e := bufio.NewReader(c).ReadString('\n')
	if e != nil {
		return e
	}
	if line != "ok\n" {
		return errors.New("target audit failed")
	}
	return nil
}

// Session is forced by the isolated sshd. The remote account cannot update
// the root-owned lease. Commands run in their own process group and stop when
// the visible controller exits, expires, or stops updating its heartbeat.
func Session(dir string) int {
	if os.Geteuid() == 0 || validateRuntime(dir) != nil || rootOwned(filepath.Join(dir, "lease.json"), false) != nil {
		return 11
	}
	l, e := readLease(dir)
	if e != nil || l.Check(time.Now(), os.Getuid()) != nil {
		fmt.Fprintln(os.Stderr, "Remote Bridge入口已失效")
		return 11
	}
	source := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(source) != 4 || !l.Allows(net.ParseIP(source[0])) {
		return 11
	}
	original := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(original) > 65536 || strings.ContainsRune(original, 0) {
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	ctx, stop := context.WithDeadline(ctx, l.ExpiresAt)
	defer stop()
	script := original
	timeout := 120 * time.Second
	var input io.Reader = os.Stdin
	program := l.Shell
	args := []string{"-c", original}
	if original == "sh -s" {
		// Drain the bounded script before executing it, so audit covers the
		// actual command and incomplete/disconnected input never starts work.
		type readResult struct {
			data []byte
			err  error
		}
		read := make(chan readResult, 1)
		go func() { data, err := io.ReadAll(io.LimitReader(os.Stdin, 65537+128)); read <- readResult{data, err} }()
		inputTimer := time.NewTimer(15 * time.Second)
		defer inputTimer.Stop()
		poll := time.NewTicker(500 * time.Millisecond)
		defer poll.Stop()
	readScript:
		for {
			select {
			case <-ctx.Done():
				return 124
			case <-inputTimer.C:
				return 124
			case <-poll.C:
				current, err := readLease(dir)
				if err != nil || current.Check(time.Now(), os.Getuid()) != nil {
					return 124
				}
			case result := <-read:
				if result.err != nil || len(result.data) > 65536+128 {
					return 2
				}
				script = string(result.data)
				if strings.HasPrefix(script, "# remote-bridge-timeout: ") {
					header, rest, ok := strings.Cut(script, "\n")
					n, err := strconv.Atoi(strings.TrimPrefix(header, "# remote-bridge-timeout: "))
					if !ok || err != nil || n < 1 || n > 120 {
						return 2
					}
					timeout = time.Duration(n) * time.Second
					script = rest
				}
				if len(script) > 65536 || strings.ContainsRune(script, 0) {
					return 2
				}
				program = "/bin/sh"
				args = []string{"-s"}
				input = strings.NewReader(script)
				break readScript
			}
		}
	}
	if original == "" {
		args = []string{"-l"}
	} else {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, timeout)
		defer timeoutCancel()
	}
	event := sessionAudit{Kind: "target.unix.command.started", CommandHash: audit.Digest(script), CommandLength: len(script), Source: source[0]}
	if e = sendSessionAudit(dir, event); e != nil {
		fmt.Fprintln(os.Stderr, "Remote Bridge审计不可用")
		return 50
	}
	cmd := exec.Command(program, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if original == "" && os.Getenv("SSH_TTY") != "" {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = 0
	}
	if e = cmd.Start(); e != nil {
		return 20
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	code := 0
running:
	for {
		select {
		case e := <-done:
			if e != nil {
				code = cmd.ProcessState.ExitCode()
			}
			break running
		case <-ctx.Done():
			code = 124
			break running
		case <-ticker.C:
			latest, e := readLease(dir)
			if e != nil || latest.Instance != l.Instance || latest.Check(time.Now(), os.Getuid()) != nil {
				code = 124
				break running
			}
		}
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	event.Kind = "target.unix.command.finished"
	event.ExitCode = code
	if e = sendSessionAudit(dir, event); e != nil {
		fmt.Fprintln(os.Stderr, "Remote Bridge结束审计不可用")
	}
	return code
}
