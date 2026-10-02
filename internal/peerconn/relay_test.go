package peerconn

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/wire"
)

func TestNoiseDataThroughRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secA, _ := NewSecurity(nil)
	secB, _ := NewSecurity(nil)
	secC, _ := NewSecurity(nil)
	received := make(chan wire.Packet, 1)
	c := func(id uint32, sec *Security, deliver func(context.Context, wire.Packet) error) (*Node, *Listener) {
		n, err := NewNode(id, deliver)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Listen("127.0.0.1:0", Config{PeerID: id, NetworkName: "relay", NetworkSecret: "secret", Timeout: time.Second, Security: sec})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = n.Serve(ctx, l) }()
		return n, l
	}
	a, _ := c(1, secA, func(_ context.Context, p wire.Packet) error { return nil })
	b, lb := c(2, secB, func(_ context.Context, p wire.Packet) error { return nil })
	cNode, lc := c(3, secC, func(_ context.Context, p wire.Packet) error { received <- p; return nil })
	if err := a.SetIPv4(netip.MustParsePrefix("10.1.0.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := cNode.SetIPv4(netip.MustParsePrefix("10.3.0.1/24")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	ca, err := a.Dial(ctx, lb.Addr().String(), "relay", "secret", secA)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.Dial(ctx, lc.Addr().String(), "relay", "secret", secB)
	if err != nil {
		t.Fatal(err)
	}
	go a.RunConn(ctx, ca)
	go b.RunConn(ctx, cb)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20)
	copy(ip[16:20], []byte{10, 3, 0, 1})
	deadline := time.Now().Add(12 * time.Second)
	for {
		err = a.SendIP(ctx, netip.MustParseAddr("10.3.0.1"), ip)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case p := <-received:
		if len(p.Payload) != 20 {
			t.Fatalf("payload len=%d", len(p.Payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay data timeout")
	}
}
