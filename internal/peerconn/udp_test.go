package peerconn

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/wire"
)

func TestUDPNodeAutomaticRoutesAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan wire.Packet, 4)
	a, err := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNode(2, func(_ context.Context, p wire.Packet) error { packets <- p; return nil })
	if err != nil {
		t.Fatal(err)
	}
	sa, err := NewSecurity(nil)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewSecurity(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.SetIPv4(netip.MustParsePrefix("10.4.0.1/24")); err != nil {
		t.Fatal(err)
	}
	if err = b.SetIPv4(netip.MustParsePrefix("10.4.0.2/24")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 3)
	go func() {
		done <- a.RunUDP(ctx, UDPConfig{Listen: "127.0.0.1:0"}, Config{PeerID: 1, NetworkName: "udp", NetworkSecret: "secret", Security: sa, Timeout: time.Second})
	}()
	go func() {
		done <- b.RunUDP(ctx, UDPConfig{Listen: "127.0.0.1:0"}, Config{PeerID: 2, NetworkName: "udp", NetworkSecret: "secret", Security: sb, Timeout: time.Second})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for a.LocalUDPAddr() == "" || b.LocalUDPAddr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("UDP startup timeout")
		}
		time.Sleep(time.Millisecond)
	}
	go func() { done <- a.ConnectUDP(ctx, b.LocalUDPAddr()) }()
	destination := netip.MustParseAddr("10.4.0.2")
	for {
		if _, ok := a.Routes.Lookup(destination); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no synchronized route")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 20)
	copy(ip[16:], []byte{10, 4, 0, 2})
	if err = a.SendIP(ctx, destination, ip); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-packets:
		if p.Header.FromPeerID != 1 || string(p.Payload) != string(ip) {
			t.Fatal("bad UDP delivery")
		}
	case <-time.After(time.Second):
		t.Fatal("UDP delivery timeout")
	}
	cancel()
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("UDP shutdown leak")
		}
	}
}
