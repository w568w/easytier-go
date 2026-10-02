package peerconn

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/hostnet"
	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"
)

// Deliberately hide every concrete socket and address type.
type opaqueAddr struct{ value string }

func (a opaqueAddr) Network() string { return "udp" }
func (a opaqueAddr) String() string  { return a.value }

type opaquePacket struct{ net.PacketConn }

func (p opaquePacket) LocalAddr() net.Addr { return opaqueAddr{p.PacketConn.LocalAddr().String()} }
func (p opaquePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if e != nil {
		return n, nil, e
	}
	return n, opaqueAddr{a.String()}, nil
}

type injectedNetwork struct {
	hostnet.System
	mu      sync.Mutex
	sockets []net.PacketConn
	dns     int
	reject  bool
}

func (h *injectedNetwork) ListenPacket(ctx context.Context, n, a string) (net.PacketConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reject {
		return nil, errors.New("injected rejection")
	}
	p, e := h.System.ListenPacket(ctx, n, a)
	if e != nil {
		return nil, e
	}
	h.sockets = append(h.sockets, p)
	return opaquePacket{p}, nil
}
func (h *injectedNetwork) LookupIP(ctx context.Context, n, a string) ([]netip.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dns++
	if a != "stun.invalid" {
		return nil, errors.New("unexpected DNS")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
func TestInjectedPunchSockets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	stun, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer stun.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 100)
		for {
			n, a, e := stun.ReadFrom(b)
			if e != nil {
				return
			}
			if n < 20 {
				continue
			}
			ap := netip.MustParseAddrPort(a.String())
			rsp := make([]byte, 32)
			copy(rsp, b[:20])
			binary.BigEndian.PutUint16(rsp, 0x101)
			binary.BigEndian.PutUint16(rsp[2:], 12)
			binary.BigEndian.PutUint16(rsp[20:], 0x20)
			binary.BigEndian.PutUint16(rsp[22:], 8)
			rsp[25] = 1
			binary.BigEndian.PutUint16(rsp[26:], ap.Port()^0x2112)
			ip := ap.Addr().As4()
			binary.BigEndian.PutUint32(rsp[28:], binary.BigEndian.Uint32(ip[:])^0x2112a442)
			stun.WriteTo(rsp, a)
		}
	}()
	defer func() { stun.Close(); <-done }()
	_, port, _ := net.SplitHostPort(stun.LocalAddr().String())
	h := new(injectedNetwork)
	s := &udpService{cfg: Config{HostNetwork: h}, options: UDPConfig{Listen: "127.0.0.1:0", STUN: "stun.invalid:" + port}, ctx: ctx}
	endpoint, e := transport.ListenUDPWithHost(ctx, h, s.options.Listen)
	if e != nil {
		t.Fatal(e)
	}
	s.endpoint = endpoint
	defer endpoint.Close()
	if s.mapped, e = s.mapping(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = sampleMapping(ctx, s); e != nil {
		t.Fatal(e)
	}
	for _, count := range []int{25, 84} {
		p, e := newPunchPoolWithHost(ctx, h, s.options.Listen, count, 123)
		if e != nil {
			t.Fatal(e)
		}
		p.closeExcept(nil)
	}
	n, _ := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	base, _ := socketProto(s.mapped)
	// Execute both-symmetric server allocation and cancellation through wrapped sockets.
	out, e := n.symmetricRPC(s, 5, mustProto(&pb.SendPunchPacketBothEasySymRequest{UdpSocketCount: 25, PublicIp: base.GetIpv4(), DstPortNum: base.Port, TransactionId: 12, WaitTimeMs: 100}))
	if e != nil {
		t.Fatal(e)
	}
	if out.(*pb.SendPunchPacketBothEasySymResponse).BaseMappedAddr == nil {
		t.Fatal("missing mapping")
	}
	s.jobs.Wait()
	endpoint.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dns != 3 || len(h.sockets) != 137 {
		t.Fatalf("DNS=%d sockets=%d", h.dns, len(h.sockets))
	}
	for _, p := range h.sockets {
		if _, e = p.WriteTo([]byte{1}, stun.LocalAddr()); e == nil {
			t.Fatal("host socket leaked")
		}
	}
}
func TestInjectedPoolFailure(t *testing.T) {
	h := &injectedNetwork{reject: true}
	if _, e := newPunchPoolWithHost(context.Background(), h, "127.0.0.1:0", 84, 1); e == nil {
		t.Fatal("host rejection ignored")
	}
}
