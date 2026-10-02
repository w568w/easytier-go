package easytier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/easytier/easytier-go/internal/hostnet"
	"github.com/easytier/easytier-go/internal/netstack"
	"github.com/easytier/easytier-go/internal/peerconn"
	"github.com/easytier/easytier-go/internal/wire"
)

type Server struct {
	config     Config
	startOnce  sync.Once
	startDone  chan struct{}
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	closeDone  chan struct{}
	changed    chan struct{}
	failure    error
	ipv4       netip.Addr
	stack      *netstack.Stack
	node       *peerconn.Node
	listeners  []*peerconn.Listener
	wg         sync.WaitGroup
	resources  map[*resource]struct{}
	generation uint64
}

type endpoint struct{ network, address string }

func parseEndpoint(raw string) (endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return endpoint{}, err
	}
	if (u.Scheme != "tcp" && u.Scheme != "udp") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return endpoint{}, fmt.Errorf("invalid peer/listener URL %q", raw)
	}
	if _, _, err = net.SplitHostPort(u.Host); err != nil {
		return endpoint{}, err
	}
	return endpoint{u.Scheme, u.Host}, nil
}

// New copies the configuration. It does not open sockets or start goroutines.
func New(config Config) (*Server, error) {
	if config.NetworkName == "" {
		return nil, errors.New("network name required")
	}
	if config.IPv4.IsValid() && (!config.IPv4.Addr().Is4() || config.IPv4.Addr().IsUnspecified() || config.IPv4.Addr().IsMulticast()) {
		return nil, errors.New("unicast IPv4 prefix required")
	}
	if config.DHCP && config.IPv4.IsValid() {
		return nil, errors.New("choose IPv4 or DHCP")
	}
	if !config.DHCP && !config.IPv4.IsValid() {
		return nil, errors.New("IPv4 or DHCP required")
	}
	if config.DHCPSubnet.IsValid() {
		if !config.DHCP {
			return nil, errors.New("DHCPSubnet requires DHCP")
		}
		if _, err := peerconn.SelectIPv4(config.DHCPSubnet, netip.Prefix{}, nil); err != nil {
			return nil, err
		}
	}
	if config.Encryption == "" {
		config.Encryption = Legacy
	}
	if config.Encryption != Legacy && config.Encryption != Noise {
		return nil, errors.New("unknown encryption mode")
	}
	if len(config.PrivateKey) != 0 && (len(config.PrivateKey) != 32 || config.Encryption != Noise) {
		return nil, errors.New("private key requires Noise and 32 bytes")
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Timeout < 0 {
		return nil, errors.New("positive timeout required")
	}
	config.Peers = append([]string(nil), config.Peers...)
	config.Listeners = append([]string(nil), config.Listeners...)
	config.PrivateKey = append([]byte(nil), config.PrivateKey...)
	for _, raw := range append(append([]string(nil), config.Peers...), config.Listeners...) {
		if _, err := parseEndpoint(raw); err != nil {
			return nil, err
		}
	}
	for _, raw := range config.Listeners {
		e, _ := parseEndpoint(raw)
		if e.network != "tcp" {
			return nil, errors.New("UDP listeners use UDP.Listen")
		}
	}
	for _, raw := range config.Peers {
		e, _ := parseEndpoint(raw)
		if e.network == "udp" && config.UDP.Listen == "" {
			config.UDP.Listen = "0.0.0.0:0"
		}
	}
	if config.UDP.Punch && config.UDP.Listen == "" {
		config.UDP.Listen = "0.0.0.0:0"
	}
	if config.UDP.STUN != "" && config.UDP.Advertise != "" {
		return nil, errors.New("choose STUN or Advertise")
	}
	switch config.UDP.NAT {
	case "", "auto", "symmetric", "incremental", "decremental":
	default:
		return nil, errors.New("unknown NAT mode")
	}
	for _, a := range []string{config.UDP.Listen, config.UDP.STUN, config.UDP.Advertise} {
		if a != "" {
			if _, _, e := net.SplitHostPort(a); e != nil {
				return nil, e
			}
		}
	}
	if config.PeerID == 0 {
		var b [4]byte
		for config.PeerID == 0 {
			if _, e := rand.Read(b[:]); e != nil {
				return nil, e
			}
			config.PeerID = binary.LittleEndian.Uint32(b[:])
		}
	}
	if config.Hostname == "" {
		config.Hostname = fmt.Sprintf("et-%08x", config.PeerID)
	}
	config.Hostname = normalizeName(config.Hostname)
	if config.Hostname == "" || strings.ContainsAny(config.Hostname, " :/\\") {
		return nil, errors.New("invalid hostname")
	}
	config.HostNetwork = hostnet.OrSystem(config.HostNetwork)
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{config: config, ctx: ctx, cancel: cancel, startDone: make(chan struct{}), changed: make(chan struct{}), closeDone: make(chan struct{}), resources: make(map[*resource]struct{})}, nil
}
func normalizeName(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), ".et.net")
}

// Start initializes the in-memory stack and underlay listeners once. Peers
// reconnect in the background. A startup failure is terminal for this Server.
func (s *Server) beginStart() {
	s.startOnce.Do(func() { go func() { defer close(s.startDone); _ = s.start() }() })
}
func (s *Server) Start() error {
	s.beginStart()
	<-s.startDone
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.failure
}
func (s *Server) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := netstack.New()
	if err != nil {
		s.failure = err
		s.cancel()
		return err
	}
	s.stack = st
	// No serving goroutine needs s.mu during setup, so failed startup can clean up here.
	fail := func(e error) error {
		s.failure = e
		s.cancel()
		for _, l := range s.listeners {
			l.Close()
		}
		s.wg.Wait()
		st.Close()
		s.stack = nil
		return e
	}
	n, err := peerconn.NewNode(s.config.PeerID, func(_ context.Context, p wire.Packet) error { st.Inject(p.Payload); return nil })
	if err != nil {
		return fail(err)
	}
	s.node = n
	n.Log = s.config.Logf
	n.SetHostname(s.config.Hostname)
	cfg := peerconn.Config{PeerID: s.config.PeerID, NetworkName: s.config.NetworkName, NetworkSecret: s.config.NetworkSecret, Timeout: s.config.Timeout, HostNetwork: s.config.HostNetwork}
	if s.config.Encryption == Noise {
		cfg.Security, err = peerconn.NewSecurity(s.config.PrivateKey)
		if err != nil {
			return fail(err)
		}
	}
	if err = n.Configure(cfg); err != nil {
		return fail(err)
	}

	if s.config.IPv4.IsValid() {
		if err = st.SetAddress(netip.Addr{}, s.config.IPv4.Addr()); err != nil {
			return fail(err)
		}
		if err = n.SetIPv4(s.config.IPv4); err != nil {
			return fail(err)
		}
		s.ipv4 = s.config.IPv4.Addr()
	}
	for _, raw := range s.config.Listeners {
		e, _ := parseEndpoint(raw)
		l, err := peerconn.ListenContext(s.ctx, e.address, cfg)
		if err != nil {
			return fail(err)
		}
		s.listeners = append(s.listeners, l)
	}
	if s.config.UDP.Listen != "" {
		ready := make(chan error, 1)
		s.run(func() {
			e := n.RunUDPReady(s.ctx, peerconn.UDPConfig(s.config.UDP), cfg, ready)
			if e != nil && s.ctx.Err() == nil && s.config.Logf != nil {
				s.config.Logf("UDP: %v", e)
			}
		})
		if err = <-ready; err != nil {
			return fail(err)
		}
	}
	s.run(func() { st.Run(s.ctx, n.SendIP, s.config.Logf) })
	for _, l := range s.listeners {
		l := l
		s.run(func() { _ = n.Serve(s.ctx, l) })
	}
	for _, raw := range s.config.Peers {
		e, _ := parseEndpoint(raw)
		s.run(func() {
			if e.network == "udp" {
				_ = n.ConnectUDP(s.ctx, e.address)
			} else {
				_ = n.Connect(s.ctx, e.address, cfg.NetworkName, cfg.NetworkSecret, cfg.Security)
			}
		})
	}
	if s.config.DHCP {
		s.run(func() {
			err := n.RunDHCP(s.ctx, s.config.DHCPSubnet, func(_, next netip.Prefix) error { return s.changeAddress(next.Addr()) })
			if err != nil && s.ctx.Err() == nil {
				s.mu.Lock()
				s.failure = err
				s.signal()
				s.mu.Unlock()
			}
		})
	}
	s.signal()
	return nil
}
func (s *Server) run(f func()) { s.wg.Add(1); go func() { defer s.wg.Done(); f() }() }
func (s *Server) signal()      { close(s.changed); s.changed = make(chan struct{}) }
func (s *Server) changeAddress(next netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.ipv4 == next {
		return nil
	}
	if err := s.stack.SetAddress(s.ipv4, next); err != nil {
		return err
	}
	s.generation++
	for r := range s.resources {
		if !r.wildcard {
			r.close()
			delete(s.resources, r)
		}
	}
	s.ipv4 = next
	s.signal()
	return nil
}

// Up starts the Server and waits for a virtual address. Cancelling this wait
// leaves the Server running; Close owns its lifetime.
func (s *Server) Up(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.beginStart()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.startDone:
	}
	for {
		s.mu.Lock()
		err := s.ready()
		ch := s.changed
		s.mu.Unlock()
		if !errors.Is(err, ErrNotReady) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}
func (s *Server) ready() error {
	if s.closed {
		return ErrClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if !s.ipv4.IsValid() {
		return ErrNotReady
	}
	return nil
}
func (s *Server) IPv4() (netip.Addr, bool) {
	select {
	case <-s.startDone:
	default:
		return netip.Addr{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv4, !s.closed && s.failure == nil && s.ipv4.IsValid()
}
func (s *Server) LookupHost(ctx context.Context, name string) ([]netip.Addr, error) {
	select {
	case <-s.startDone:
	default:
		return nil, ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		if !ip.Is4() {
			return nil, errors.New("only overlay IPv4 supported")
		}
		return []netip.Addr{ip}, nil
	}
	ips, count := s.node.LookupHostname(normalizeName(name))
	if count > 1 {
		return nil, fmt.Errorf("%w: %s", ErrAmbiguousName, name)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNameNotFound, name)
	}
	return ips, nil
}

// Close permanently stops the Server and all overlay and underlay work.
// Concurrent calls wait for the same cleanup.
func (s *Server) Close() error {
	s.cancel() // Interrupt host initialization even while start holds mu.
	s.startOnce.Do(func() { close(s.startDone) })
	<-s.startDone
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return nil
	}
	s.closed = true
	s.signal()
	for r := range s.resources {
		r.close()
		delete(s.resources, r)
	}
	for _, l := range s.listeners {
		l.Close()
	}
	st := s.stack
	s.mu.Unlock()
	s.wg.Wait()
	if st != nil {
		st.Close()
	}
	close(s.closeDone)
	return nil
}
