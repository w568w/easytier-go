// Live SSH interoperability check through the public embedded API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	et "github.com/easytier/easytier-go"
)

type route struct {
	IPv4     string `json:"ipv4"`
	Hostname string `json:"hostname"`
}
type result struct {
	Peer     string `json:"peer"`
	IPv4     string `json:"ipv4"`
	SSH      string `json:"ssh,omitempty"`
	Sent     int64  `json:"sent_bytes"`
	Received int64  `json:"received_bytes"`
	Error    string `json:"error,omitempty"`
}

func routes() ([]route, error) {
	b, e := exec.Command("easytier-cli", "-o", "json", "route", "list").Output()
	if e != nil {
		return nil, e
	}
	var r []route
	e = json.Unmarshal(b, &r)
	return r, e
}
func serviceIdentity() (et.Config, string, error) {
	b, e := exec.Command("systemctl", "show", "easytier", "--property=MainPID", "--value").Output()
	if e != nil {
		return et.Config{}, "", e
	}
	pid := strings.TrimSpace(string(b))
	if _, e = strconv.Atoi(pid); e != nil || pid == "0" {
		return et.Config{}, "", errors.New("service is not running")
	}
	raw, e := os.ReadFile("/proc/" + pid + "/cmdline")
	if e != nil {
		return et.Config{}, "", e
	}
	args := strings.Split(string(raw), "\x00")
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		key, value, found := strings.Cut(args[i], "=")
		switch key {
		case "--network-name", "--network-secret", "--secure-mode":
			if !found && i+1 < len(args) {
				i++
				value = args[i]
			}
			values[key] = value
		}
	}
	name, ok := values["--network-name"]
	if !ok || name == "" {
		return et.Config{}, "", errors.New("service must specify --network-name")
	}
	secret, ok := values["--network-secret"]
	if !ok {
		return et.Config{}, "", errors.New("service must specify --network-secret")
	}
	cfg := et.Config{NetworkName: name, NetworkSecret: secret, Encryption: et.Legacy}
	if values["--secure-mode"] == "true" {
		cfg.Encryption = et.Noise
	}
	return cfg, pid, nil
}
func freeAddress(r []route) (netip.Prefix, error) {
	used := map[netip.Addr]bool{}
	for _, v := range r {
		if p, e := netip.ParsePrefix(v.IPv4); e == nil {
			used[p.Addr()] = true
		}
	}
	for n := 254; n > 3; n-- {
		ip := netip.AddrFrom4([4]byte{10, 114, 0, byte(n)})
		if !used[ip] {
			return netip.PrefixFrom(ip, 24), nil
		}
	}
	return netip.Prefix{}, errors.New("no free test address")
}
func runCase(base et.Config, peer, targetName string, index int) (out result) {
	out.Peer = peer
	r, e := routes()
	if e != nil {
		out.Error = e.Error()
		return
	}
	base.IPv4, e = freeAddress(r)
	if e != nil {
		out.Error = e.Error()
		return
	}
	out.IPv4 = base.IPv4.String()
	base.Hostname = fmt.Sprintf("et-go-live-%d-%d", os.Getpid(), index)
	base.Peers = []string{peer}
	base.Logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[%s] "+f+"\n", append([]any{peer}, a...)...) }
	s, e := et.New(base)
	if e != nil {
		out.Error = e.Error()
		return
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if e = s.Up(ctx); e != nil {
		out.Error = e.Error()
		return
	}
	want := netip.MustParseAddr("10.114.0.2")
	for {
		ips, err := s.LookupHost(ctx, targetName)
		if err == nil && len(ips) == 1 && ips[0] == want {
			break
		}
		select {
		case <-ctx.Done():
			out.Error = "route/name discovery: " + ctx.Err().Error()
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, name := range []string{targetName, targetName + ".et.net"} {
		ips, err := s.LookupHost(ctx, name)
		if err != nil || len(ips) != 1 || ips[0] != want {
			out.Error = fmt.Sprintf("name resolution failed for %s: %v", name, err)
			return
		}
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		out.Error = e.Error()
		return
	}
	defer l.Close()
	type transferred struct {
		sent, received int64
		err            error
	}
	done := make(chan transferred, 1)
	go func() {
		local, err := l.Accept()
		if err != nil {
			done <- transferred{err: err}
			return
		}
		defer local.Close()
		overlay, err := s.Dial(ctx, "tcp", "10.114.0.2:22")
		if err != nil {
			done <- transferred{err: err}
			return
		}
		defer overlay.Close()
		deadline, _ := ctx.Deadline()
		local.SetDeadline(deadline)
		overlay.SetDeadline(deadline)
		tx := make(chan int64, 1)
		go func() { n, _ := io.Copy(overlay, local); tx <- n }()
		rx, _ := io.Copy(local, overlay)
		local.Close()
		overlay.Close()
		done <- transferred{sent: <-tx, received: rx}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	ssh := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=20", "-o", "ProxyCommand=nc 127.0.0.1 "+port, "root@10.114.0.2", "id -u; hostname")
	b, e := ssh.CombinedOutput()
	l.Close()
	transfer := <-done
	out.Sent, out.Received = transfer.sent, transfer.received
	if e != nil {
		out.Error = fmt.Sprintf("SSH: %v: %s", e, strings.TrimSpace(string(b)))
		return
	}
	if transfer.err != nil {
		out.Error = transfer.err.Error()
		return
	}
	out.SSH = strings.TrimSpace(string(b))
	if !strings.HasPrefix(out.SSH, "0\n") || out.Sent == 0 || out.Received == 0 {
		out.Error = "SSH command or overlay byte verification failed"
	}
	return
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	cfg, pid, e := serviceIdentity()
	if e != nil {
		return e
	}
	before, e := routes()
	if e != nil {
		return e
	}
	targetName := ""
	for _, r := range before {
		if p, e := netip.ParsePrefix(r.IPv4); e == nil && p.Addr() == netip.MustParseAddr("10.114.0.2") {
			targetName = r.Hostname
		}
	}
	if targetName == "" {
		return errors.New("target absent from service routes")
	}
	baseline, e := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "root@10.114.0.2", "id -u; hostname").CombinedOutput()
	if e != nil || !strings.HasPrefix(string(baseline), "0\n") {
		return fmt.Errorf("system SSH baseline failed: %v", e)
	}
	failed := false
	for i, peer := range []string{"tcp://127.0.0.1:11010", "udp://127.0.0.1:11010", "tcp://sh.kyln24.top:11020"} {
		r := runCase(cfg, peer, targetName, i)
		if r.Error == "" && r.SSH != strings.TrimSpace(string(baseline)) {
			r.Error = "SSH output differs from system baseline"
		}
		json.NewEncoder(os.Stdout).Encode(r)
		if r.Error != "" {
			failed = true
		}
		time.Sleep(3 * time.Second)
	}
	_, afterPID, e := serviceIdentity()
	if e != nil {
		return e
	}
	if pid != afterPID {
		return errors.New("existing service PID changed")
	}
	after, e := routes()
	if e != nil {
		return e
	}
	for _, old := range before {
		if old.IPv4 == "" {
			continue
		}
		found := false
		for _, now := range after {
			if now.IPv4 == old.IPv4 && now.Hostname == old.Hostname {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("existing route missing after test: %s", old.IPv4)
		}
	}
	fmt.Printf("service_pid_unchanged=%s existing_routes_preserved=true\n", pid)
	if failed {
		return errors.New("one or more live cases failed")
	}
	return nil
}
