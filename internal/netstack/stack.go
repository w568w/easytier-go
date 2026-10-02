// Package netstack connects an in-memory IPv4 interface to Go network sockets.
package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

type Stack struct {
	stack *stack.Stack
	link  *channel.Endpoint
}

func New() (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})
	link := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, link); err != nil {
		s.Close()
		s.Wait()
		return nil, fmt.Errorf("create virtual NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return &Stack{stack: s, link: link}, nil
}
func addr(a netip.Addr) tcpip.Address {
	if !a.IsValid() || a.IsUnspecified() {
		return tcpip.Address{}
	}
	return tcpip.AddrFrom4(a.As4())
}
func full(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: addr(a.Addr()), Port: a.Port()}
}
func (s *Stack) SetAddress(old, next netip.Addr) error {
	if old == next {
		return nil
	}
	if next.IsValid() {
		a := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr(next), PrefixLen: 32}}
		if err := s.stack.AddProtocolAddress(1, a, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("add address: %s", err)
		}
	}
	if old.IsValid() {
		if err := s.stack.RemoveAddress(1, addr(old)); err != nil {
			return fmt.Errorf("remove address: %s", err)
		}
	}
	return nil
}
func (s *Stack) Inject(b []byte) {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	defer p.DecRef()
	s.link.InjectInbound(ipv4.ProtocolNumber, p)
}
func (s *Stack) Run(ctx context.Context, send func(context.Context, netip.Addr, []byte) error, logf func(string, ...any)) {
	for {
		p := s.link.ReadContext(ctx)
		if p == nil {
			return
		}
		v := p.ToView()
		b := append([]byte(nil), v.AsSlice()...)
		v.Release()
		p.DecRef()
		if len(b) < 20 {
			continue
		}
		dst := netip.AddrFrom4([4]byte(b[16:20]))
		if err := send(ctx, dst, b); err != nil && ctx.Err() == nil && logf != nil {
			logf("send IP: %v", err)
		}
	}
}
func (s *Stack) Dial(ctx context.Context, network string, remote netip.AddrPort) (net.Conn, error) {
	if network == "tcp" {
		return gonet.DialContextTCP(ctx, s.stack, full(remote), ipv4.ProtocolNumber)
	}
	r := full(remote)
	return gonet.DialUDP(s.stack, nil, &r, ipv4.ProtocolNumber)
}
func (s *Stack) Listen(local netip.AddrPort) (net.Listener, error) {
	return gonet.ListenTCP(s.stack, full(local), ipv4.ProtocolNumber)
}
func (s *Stack) ListenPacket(local netip.AddrPort) (net.PacketConn, error) {
	l := full(local)
	return gonet.DialUDP(s.stack, &l, nil, ipv4.ProtocolNumber)
}
func (s *Stack) Close() { s.stack.Close(); s.link.Close(); s.stack.Wait() }
