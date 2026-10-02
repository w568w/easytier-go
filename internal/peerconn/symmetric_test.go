package peerconn

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"
)

func TestPredictedPorts(t *testing.T) {
	for _, tc := range []struct {
		base, span  uint32
		inc         bool
		first, last uint16
	}{{40000, 50, true, 40001, 40050}, {40000, 50, false, 39950, 39999}, {65530, 50, true, 65531, 65535}, {4, 50, false, 1, 3}} {
		ports, err := predictedPorts(tc.base, tc.span, tc.inc)
		if err != nil || ports[0] != tc.first || ports[len(ports)-1] != tc.last {
			t.Fatalf("range=%v err=%v", ports, err)
		}
	}
	if _, err := predictedPorts(65535, 50, true); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, err := predictedPorts(1, 50, false); err == nil {
		t.Fatal("underflow accepted")
	}
}
func TestSymmetricRPCPredictsAndSendsMatchingTransaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	target, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	s := &udpService{endpoint: endpoint, mapped: endpoint.Addr().String(), ctx: ctx}
	n, _ := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	local, _ := socketProto(endpoint.Addr().String())
	port := target.Addr().(*net.UDPAddr).Port
	if port < 2 || port > 65533 {
		t.Skip("ephemeral port near boundary")
	}
	watch, stop := target.WatchPunch(777)
	defer stop()
	_, err = n.symmetricRPC(s, 4, mustProto(&pb.SendPunchPacketEasySymRequest{ListenerMappedAddr: local, PublicIps: []*pb.Ipv4Addr{{Addr: 0x7f000001}}, BasePortNum: uint32(port - 1), MaxPortNum: 2, IsIncremental: true, TransactionId: 777}))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-watch:
	case <-time.After(time.Second):
		t.Fatal("predicted probe absent")
	}
	_, err = n.symmetricRPC(s, 3, mustProto(&pb.SendPunchPacketHardSymRequest{ListenerMappedAddr: local, PublicIps: []*pb.Ipv4Addr{{Addr: 0x7f000001}}, PortIndex: 65530, Round: 100, TransactionId: 777}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestPunchPoolCancellationClosesAllSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := newPunchPoolWithHost(ctx, nil, "127.0.0.1:0", 25, 123)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	pool.closeExcept(nil)
	for _, u := range pool.sockets {
		if err := u.Probe("127.0.0.1:9", 123); err == nil {
			t.Fatal("socket leaked")
		}
	}
}

func TestBothSymmetricBusyResponse(t *testing.T) {
	s := &udpService{}
	s.symMu.Lock()
	defer s.symMu.Unlock()
	n, _ := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	response, err := n.symmetricRPC(s, 5, nil)
	if err != nil || !response.(*pb.SendPunchPacketBothEasySymResponse).IsBusy {
		t.Fatalf("response=%v err=%v", response, err)
	}
}
