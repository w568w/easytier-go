package easytier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/hostnet"
)

type wrappedConn struct{ net.Conn }
type wrappedListener struct{ net.Listener }
type wrappedPacket struct{ net.PacketConn }
type testNetwork struct {
	conns []net.Conn
	mu    sync.Mutex
	calls map[string]int
	fail  error
}

func (h *testNetwork) called(op string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.calls == nil {
		h.calls = map[string]int{}
	}
	h.calls[op]++
	return h.fail
}
func (h *testNetwork) DialContext(c context.Context, n, a string) (net.Conn, error) {
	if e := h.called("dial"); e != nil {
		return nil, e
	}
	v, e := (hostnet.System{}).DialContext(c, n, a)
	if e != nil {
		return nil, e
	}
	h.mu.Lock()
	h.conns = append(h.conns, v)
	h.mu.Unlock()
	return wrappedConn{v}, nil
}
func (h *testNetwork) Listen(c context.Context, n, a string) (net.Listener, error) {
	if e := h.called("listen"); e != nil {
		return nil, e
	}
	v, e := (hostnet.System{}).Listen(c, n, a)
	if e != nil {
		return nil, e
	}
	return wrappedListener{v}, nil
}
func (h *testNetwork) ListenPacket(c context.Context, n, a string) (net.PacketConn, error) {
	if e := h.called("packet"); e != nil {
		return nil, e
	}
	v, e := (hostnet.System{}).ListenPacket(c, n, a)
	if e != nil {
		return nil, e
	}
	return wrappedPacket{v}, nil
}
func (h *testNetwork) LookupIP(c context.Context, n, a string) ([]netip.Addr, error) {
	if e := h.called("dns"); e != nil {
		return nil, e
	}
	if a != "underlay.invalid" {
		return nil, fmt.Errorf("unexpected DNS %s", a)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
func makeServer(t *testing.T, c Config) *Server {
	t.Helper()
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Start(); e != nil {
		t.Fatal(e)
	}
	return s
}
func waitName(t *testing.T, s *Server, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	for {
		if _, e := s.LookupHost(ctx, name); e == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("name not propagated:", name)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func tcpEcho(t *testing.T, s *Server, address string) net.Listener {
	t.Helper()
	l, e := s.Listen("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l
}
func udpEcho(t *testing.T, s *Server) net.PacketConn {
	t.Helper()
	p, e := s.ListenPacket("udp", ":0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close() })
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			p.WriteTo(b[:n], a)
		}
	}()
	return p
}
func serviceAddr(s *Server, a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	ip, _ := s.IPv4()
	return net.JoinHostPort(ip.String(), p)
}
func checkTCP(t *testing.T, s *Server, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := s.Dial(ctx, "tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("embedded-stream"), 3000)
	done := make(chan error, 1)
	go func() {
		_, e := c.Write(payload)
		if e == nil {
			e = c.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- e
	}()
	got, e := io.ReadAll(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("TCP payload %d != %d", len(got), len(payload))
	}
}

func TestEmbeddedNetwork(t *testing.T) {
	for _, mode := range []Encryption{Legacy, Noise} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(string(mode)+"/"+transport, func(t *testing.T) {
				host := new(testNetwork)
				cfg := Config{NetworkName: "test", NetworkSecret: "secret", Hostname: "alpha", IPv4: netip.MustParsePrefix("10.77.0.1/24"), Encryption: mode, HostNetwork: host}
				if transport == "tcp" {
					cfg.Listeners = []string{"tcp://127.0.0.1:0"}
				} else {
					cfg.UDP.Listen = "127.0.0.1:0"
				}
				a := makeServer(t, cfg)
				addr := ""
				if transport == "tcp" {
					addr = a.listeners[0].Addr().String()
				} else {
					addr = a.node.LocalUDPAddr()
				}
				_, port, _ := net.SplitHostPort(addr)
				cfg.Listeners = nil
				cfg.UDP.Listen = ""
				cfg.Peers = []string{transport + "://underlay.invalid:" + port}
				cfg.Hostname = "beta"
				cfg.IPv4 = netip.MustParsePrefix("10.77.0.2/24")
				b := makeServer(t, cfg)
				cfg.Hostname = "gamma"
				cfg.IPv4 = netip.MustParsePrefix("10.77.0.3/24")
				c := makeServer(t, cfg)
				waitName(t, b, "alpha.et.net")
				waitName(t, a, "beta")
				waitName(t, b, "gamma")
				la := tcpEcho(t, a, ":0")
				lb := tcpEcho(t, b, ":0")
				lc := tcpEcho(t, c, ":0")
				_, p, _ := net.SplitHostPort(la.Addr().String())
				checkTCP(t, b, "alpha.et.net:"+p)
				checkTCP(t, a, serviceAddr(b, lb.Addr()))
				checkTCP(t, b, serviceAddr(c, lc.Addr())) // relay
				hl, e := a.Listen("tcp", ":0")
				if e != nil {
					t.Fatal(e)
				}
				hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello overlay") })}
				defer hs.Close()
				go hs.Serve(hl)
				tr := &http.Transport{DialContext: b.Dial}
				defer tr.CloseIdleConnections()
				client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
				_, p, _ = net.SplitHostPort(hl.Addr().String())
				res, e := client.Get("http://alpha:" + p)
				if e != nil {
					t.Fatal(e)
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if string(body) != "hello overlay" {
					t.Fatal(string(body))
				}
				ua, uc := udpEcho(t, a), udpEcho(t, c)
				sender, e := b.ListenPacket("udp", ":0")
				if e != nil {
					t.Fatal(e)
				}
				defer sender.Close()
				sender.SetDeadline(time.Now().Add(5 * time.Second))
				for _, target := range []struct {
					s *Server
					p net.PacketConn
				}{{a, ua}, {c, uc}} {
					ap := netip.MustParseAddrPort(serviceAddr(target.s, target.p.LocalAddr()))
					want := []byte(ap.String())
					if _, e = sender.WriteTo(want, net.UDPAddrFromAddrPort(ap)); e != nil {
						t.Fatal(e)
					}
					buf := make([]byte, 100)
					n, from, e := sender.ReadFrom(buf)
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(buf[:n], want) || from.String() != ap.String() {
						t.Fatalf("UDP mismatch %s %s", buf[:n], from)
					}
				}
				host.mu.Lock()
				defer host.mu.Unlock()
				if host.calls["dns"] < 2 {
					t.Fatal(host.calls)
				}
				if transport == "tcp" && (host.calls["dial"] < 2 || host.calls["listen"] != 1) {
					t.Fatal(host.calls)
				}
				if transport == "udp" && host.calls["packet"] != 3 {
					t.Fatal(host.calls)
				}
			})
		}
	}
}
func TestLifecycle(t *testing.T) {
	h := new(testNetwork)
	s, e := New(Config{NetworkName: "x", DHCP: true, HostNetwork: h})
	if e != nil {
		t.Fatal(e)
	}
	if len(h.calls) != 0 {
		t.Fatal("New performed IO")
	}
	if _, e = s.Listen("tcp", ":0"); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	if _, e = s.ListenPacket("udp", ":0"); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e = s.Up(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if e = s.Start(); e != nil {
		t.Fatal(e)
	}
	if e = s.changeAddress(netip.MustParseAddr("10.1.0.1")); e != nil {
		t.Fatal(e)
	}
	wildcard := tcpEcho(t, s, ":0")
	explicit := tcpEcho(t, s, "10.1.0.1:0")
	u := udpEcho(t, s)
	old, e := s.Dial(context.Background(), "tcp", serviceAddr(s, wildcard.Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	if e = s.changeAddress(netip.MustParseAddr("10.1.0.2")); e != nil {
		t.Fatal(e)
	}
	old.SetDeadline(time.Now().Add(time.Second))
	if _, e = old.Write([]byte("x")); e == nil {
		t.Fatal("old flow survived address change")
	}
	if _, e = explicit.Accept(); e == nil {
		t.Fatal("explicit listener survived")
	}
	checkTCP(t, s, serviceAddr(s, wildcard.Addr()))
	p, e := s.ListenPacket("udp", ":0")
	if e != nil {
		t.Fatal(e)
	}
	p.SetDeadline(time.Now().Add(time.Second))
	dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(serviceAddr(s, u.LocalAddr())))
	p.WriteTo([]byte("new IP"), dst)
	buf := make([]byte, 50)
	if _, _, e = p.ReadFrom(buf); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()
	if e = s.Start(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if _, ok := s.IPv4(); ok {
		t.Fatal("closed address ready")
	}
	if _, e = p.WriteTo([]byte("closed"), dst); e == nil {
		t.Fatal("socket leaked")
	}
}
func TestInjectionFailure(t *testing.T) {
	sentinel := errors.New("host rejected")
	h := &testNetwork{fail: sentinel}
	s, e := New(Config{NetworkName: "x", IPv4: netip.MustParsePrefix("10.1.0.1/24"), Listeners: []string{"tcp://underlay.invalid:0"}, HostNetwork: h})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Start(); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.calls["dns"] != 1 || h.calls["listen"] != 0 {
		t.Fatal(h.calls)
	}
}
func TestNameAmbiguity(t *testing.T) {
	cfg := Config{NetworkName: "names", Hostname: "dup", IPv4: netip.MustParsePrefix("10.2.0.1/24"), Listeners: []string{"tcp://127.0.0.1:0"}}
	a := makeServer(t, cfg)
	cfg.Listeners = nil
	cfg.Peers = []string{"tcp://" + a.listeners[0].Addr().String()}
	cfg.IPv4 = netip.MustParsePrefix("10.2.0.2/24")
	b := makeServer(t, cfg)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, e := b.LookupHost(context.Background(), "dup.et.net")
		if errors.Is(e, ErrAmbiguousName) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("duplicate accepted")
}
func TestConfigCopy(t *testing.T) {
	c := Config{NetworkName: "copy", Hostname: "same", IPv4: netip.MustParsePrefix("10.2.0.1/24"), Peers: []string{"tcp://127.0.0.1:1"}, PrivateKey: bytes.Repeat([]byte{1}, 32), Encryption: Noise}
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c.Peers[0] = "bad"
	c.PrivateKey[0] = 2
	if strings.Contains(s.config.Peers[0], "bad") || s.config.PrivateKey[0] != 1 {
		t.Fatal("config aliased")
	}
}

func TestInjectedReconnectAndClosePendingDial(t *testing.T) {
	h := new(testNetwork)
	a := makeServer(t, Config{NetworkName: "reconnect", IPv4: netip.MustParsePrefix("10.73.0.1/24"), Hostname: "a", Listeners: []string{"tcp://127.0.0.1:0"}, HostNetwork: h})
	b := makeServer(t, Config{NetworkName: "reconnect", IPv4: netip.MustParsePrefix("10.73.0.2/24"), Hostname: "b", Peers: []string{"tcp://" + a.listeners[0].Addr().String()}, HostNetwork: h})
	waitName(t, b, "a")
	h.mu.Lock()
	first := h.conns[0]
	h.mu.Unlock()
	first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		dials := h.calls["dial"]
		h.mu.Unlock()
		if dials >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconnect bypassed host")
		}
		time.Sleep(20 * time.Millisecond)
	}
	l := tcpEcho(t, a, ":0")
	checkTCP(t, b, serviceAddr(a, l.Addr()))
	pending := make(chan error, 1)
	go func() { _, e := b.Dial(context.Background(), "tcp", "10.73.0.99:1234"); pending <- e }()
	time.Sleep(20 * time.Millisecond)
	b.Close()
	select {
	case e := <-pending:
		if e == nil {
			t.Fatal("pending dial succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close left pending dial")
	}
}

type blockedHost struct {
	testNetwork
	entered chan struct{}
}

func (h *blockedHost) Listen(ctx context.Context, n, a string) (net.Listener, error) {
	close(h.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestCancelDuringHostInitialization(t *testing.T) {
	h := &blockedHost{entered: make(chan struct{})}
	s, e := New(Config{NetworkName: "blocked", IPv4: netip.MustParsePrefix("10.1.0.1/24"), Listeners: []string{"tcp://127.0.0.1:0"}, Timeout: time.Hour, HostNetwork: h})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Up(ctx) }()
	<-h.entered
	if _, e = s.Listen("tcp", ":0"); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	if _, e = s.ListenPacket("udp", ":0"); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Up cancellation blocked by initialization")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel host initialization")
	}
	if e = s.Start(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}
func TestCloseBeforeStartDoesNotUseHost(t *testing.T) {
	h := new(testNetwork)
	s, e := New(Config{NetworkName: "closed", IPv4: netip.MustParsePrefix("10.1.0.1/24"), Listeners: []string{"tcp://127.0.0.1:0"}, HostNetwork: h})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s.Close()
	if len(h.calls) != 0 {
		t.Fatal("Close created sockets")
	}
	if e = s.Start(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}
