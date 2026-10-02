// Package hosttrace records the socket seam in external interoperability tests.
package hosttrace

import (
	"context"
	"github.com/easytier/easytier-go/internal/hostnet"
	"net"
	"net/netip"
	"sync/atomic"
)

type Network struct {
	hostnet.System
	Dials, Listeners, Packets, DNS atomic.Int64
}
type conn struct{ net.Conn }
type listener struct{ net.Listener }

func (l listener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return conn{c}, nil
}

type packet struct{ net.PacketConn }
type address struct{ net.Addr }

func (p packet) LocalAddr() net.Addr { return address{p.PacketConn.LocalAddr()} }
func (p packet) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if e != nil {
		return n, nil, e
	}
	return n, address{a}, nil
}
func (h *Network) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	h.Dials.Add(1)
	c, e := h.System.DialContext(ctx, n, a)
	if e != nil {
		return nil, e
	}
	return conn{c}, nil
}
func (h *Network) Listen(ctx context.Context, n, a string) (net.Listener, error) {
	h.Listeners.Add(1)
	l, e := h.System.Listen(ctx, n, a)
	if e != nil {
		return nil, e
	}
	return listener{l}, nil
}
func (h *Network) ListenPacket(ctx context.Context, n, a string) (net.PacketConn, error) {
	h.Packets.Add(1)
	p, e := h.System.ListenPacket(ctx, n, a)
	if e != nil {
		return nil, e
	}
	return packet{p}, nil
}
func (h *Network) LookupIP(ctx context.Context, n, a string) ([]netip.Addr, error) {
	h.DNS.Add(1)
	return h.System.LookupIP(ctx, n, a)
}
