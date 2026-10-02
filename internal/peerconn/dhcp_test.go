package peerconn

import (
	"context"
	"errors"
	"github.com/easytier/easytier-go/internal/wire"
	"net/netip"
	"testing"
)

func TestDHCPAllocationRetentionConflictAndExhaustion(t *testing.T) {
	pool := netip.MustParsePrefix("10.2.0.0/30")
	used := map[netip.Addr]bool{netip.MustParseAddr("10.2.0.1"): true}
	p, err := SelectIPv4(pool, netip.Prefix{}, used)
	if err != nil || p.String() != "10.2.0.2/30" {
		t.Fatalf("%v %v", p, err)
	}
	delete(used, netip.MustParseAddr("10.2.0.1"))
	next, err := SelectIPv4(pool, p, used)
	if err != nil || next != p {
		t.Fatalf("valid address not retained: %v %v", next, err)
	}
	used[p.Addr()] = true
	next, err = SelectIPv4(pool, p, used)
	if err != nil || next.String() != "10.2.0.1/30" {
		t.Fatalf("conflict unresolved: %v %v", next, err)
	}
	used[next.Addr()] = true
	next, err = SelectIPv4(pool, p, used)
	if err != nil || next.IsValid() {
		t.Fatalf("exhaustion: %v %v", next, err)
	}
}

func TestDHCPFailedApplyDoesNotAdvertise(t *testing.T) {
	n, err := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.peers[2] = &Conn{}
	sentinel := errors.New("host refused")
	err = n.RunDHCP(context.Background(), netip.MustParsePrefix("10.2.0.0/24"), func(netip.Prefix, netip.Prefix) error { return sentinel })
	if !errors.Is(err, sentinel) || n.IPv4().IsValid() {
		t.Fatalf("err=%v address=%v", err, n.IPv4())
	}
}
