package easytier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/easytier/easytier-go/internal/lifecycle"
)

type resource struct {
	close    func() error
	wildcard bool
	s        *Server
	once     sync.Once
}

func (r *resource) Close() error {
	var err error
	r.once.Do(func() { err = r.close(); r.s.forget(r) })
	return err
}

type conn struct {
	net.Conn
	*resource
}

func (c *conn) Close() error { return c.resource.Close() }
func (c *conn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return errors.New("half-close unsupported")
}
func (c *conn) CloseRead() error {
	if c, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return errors.New("half-close unsupported")
}

type packetConn struct {
	net.PacketConn
	*resource
}

func (c *packetConn) Close() error { return c.resource.Close() }

type listener struct {
	net.Listener
	*resource
}

func (l *listener) Close() error { return l.resource.Close() }
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.s.mu.Lock()
		if err = l.s.ready(); err != nil {
			l.s.mu.Unlock()
			c.Close()
			if errors.Is(err, ErrNotReady) {
				continue
			}
			return nil, err
		}
		host, _, err := net.SplitHostPort(c.LocalAddr().String())
		if err != nil || host != l.s.ipv4.String() {
			l.s.mu.Unlock()
			c.Close()
			// Address changes may leave an old connection queued on a wildcard listener.
			continue
		}
		out := l.s.trackConn(c)
		l.s.mu.Unlock()
		return out, nil
	}
}
func (s *Server) forget(r *resource) { s.mu.Lock(); delete(s.resources, r); s.mu.Unlock() }
func (s *Server) trackConn(c net.Conn) net.Conn {
	r := &resource{close: c.Close, s: s}
	s.resources[r] = struct{}{}
	return &conn{Conn: c, resource: r}
}
func overlayNetwork(network string, packet bool) (string, error) {
	if !packet && (network == "tcp" || network == "tcp4") {
		return "tcp", nil
	}
	if network == "udp" || network == "udp4" {
		return "udp", nil
	}
	return "", fmt.Errorf("unsupported overlay network %q", network)
}
func splitAddress(address string) (string, uint16, error) {
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		return "", 0, e
	}
	v, e := strconv.ParseUint(p, 10, 16)
	if e != nil {
		return "", 0, fmt.Errorf("numeric port required: %w", e)
	}
	return h, uint16(v), nil
}
func (s *Server) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	network, err := overlayNetwork(network, false)
	if err != nil {
		return nil, err
	}
	h, p, err := splitAddress(address)
	if err != nil {
		return nil, err
	}
	if h == "" || p == 0 {
		return nil, errors.New("destination host and port required")
	}
	if err = s.Up(ctx); err != nil {
		return nil, err
	}
	ips, err := s.LookupHost(ctx, h)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err = s.ready(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	st, gen, serverCtx := s.stack, s.generation, s.ctx
	dialCtx, cancel := context.WithCancel(ctx)
	pending := &resource{close: func() error { cancel(); return nil }}
	s.resources[pending] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	defer s.forget(pending)
	defer cancel()
	stop := lifecycle.OnCancel(serverCtx, cancel)
	defer stop()
	c, err := st.Dial(dialCtx, network, netip.AddrPortFrom(ips[0], p))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.ready(); err == nil && gen != s.generation {
		err = ErrAddressChanged
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return s.trackConn(c), nil
}
func (s *Server) localAddress(address string) (netip.AddrPort, bool, error) {
	h, p, err := splitAddress(address)
	if err != nil {
		return netip.AddrPort{}, false, err
	}
	if h == "" || h == "0.0.0.0" {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), p), true, nil
	}
	a, err := netip.ParseAddr(h)
	if err != nil && normalizeName(h) == s.config.Hostname {
		a = s.ipv4
		err = nil
	}
	if err != nil || !a.Is4() || a != s.ipv4 {
		return netip.AddrPort{}, false, fmt.Errorf("bind address %q is not local", h)
	}
	return netip.AddrPortFrom(a, p), false, nil
}
func (s *Server) Listen(network, address string) (net.Listener, error) {
	select {
	case <-s.startDone:
	default:
		return nil, ErrNotReady
	}
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("unsupported listener network %q", network)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	a, w, err := s.localAddress(address)
	if err != nil {
		return nil, err
	}
	l, err := s.stack.Listen(a)
	if err != nil {
		return nil, err
	}
	r := &resource{close: l.Close, wildcard: w, s: s}
	s.resources[r] = struct{}{}
	return &listener{Listener: l, resource: r}, nil
}
func (s *Server) ListenPacket(network, address string) (net.PacketConn, error) {
	select {
	case <-s.startDone:
	default:
		return nil, ErrNotReady
	}
	network, err := overlayNetwork(network, true)
	if err != nil {
		return nil, fmt.Errorf("unsupported packet network %q", network)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	a, w, err := s.localAddress(address)
	if err != nil {
		return nil, err
	}
	c, err := s.stack.ListenPacket(a)
	if err != nil {
		return nil, err
	}
	r := &resource{close: c.Close, wildcard: w, s: s}
	s.resources[r] = struct{}{}
	return &packetConn{PacketConn: c, resource: r}, nil
}
