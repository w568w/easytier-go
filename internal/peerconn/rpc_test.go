package peerconn

import (
	"context"
	"testing"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/proto"
)

func TestRouteResponseCorrelationAndErrors(t *testing.T) {
	n, err := NewNode(1, func(context.Context, wire.Packet) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.config = &Config{NetworkName: "test"}
	c := &Conn{remoteID: 2}
	link := &routeLink{merger: make(rpcMerger), pending: map[int64]time.Time{11: time.Now()}}
	n.links[c] = link
	response := func(id int64, body *pb.RpcResponse) wire.Packet {
		encoded, e := proto.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		packets, e := rpcPackets(2, 1, id, false, routeDescriptor("test"), encoded)
		if e != nil {
			t.Fatal(e)
		}
		return packets[0]
	}
	good := &pb.RpcResponse{Response: mustProto(&pb.SyncRouteInfoResponse{SessionId: 22})}
	if err = n.handleRPC(context.Background(), c, response(12, good)); err != nil {
		t.Fatal(err)
	}
	if n.syncOK.Load() != 0 {
		t.Fatal("unsolicited response counted")
	}
	if err = n.handleRPC(context.Background(), c, response(11, good)); err != nil {
		t.Fatal(err)
	}
	if n.syncOK.Load() != 1 {
		t.Fatal("correlated response not counted")
	}
	if err = n.handleRPC(context.Background(), c, response(11, good)); err != nil {
		t.Fatal(err)
	}
	if n.syncOK.Load() != 1 {
		t.Fatal("duplicate response counted")
	}
	link.pending[13] = time.Now()
	bad := &pb.RpcResponse{Error: &pb.Error{ErrorKind: &pb.Error_ExecuteError{ExecuteError: &pb.ExecuteError{ErrorMessage: "rejected"}}}}
	if err = n.handleRPC(context.Background(), c, response(13, bad)); err == nil {
		t.Fatal("RPC error counted as success")
	}
	if n.syncOK.Load() != 1 {
		t.Fatal("failed response counted")
	}
}
