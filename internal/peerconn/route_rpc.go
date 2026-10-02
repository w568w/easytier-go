package peerconn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/proto"
)

func randomID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b[:]) | 1
}

// rpcMerger bounds partial RPC storage and keeps the first fragment's metadata.
type rpcKey struct {
	from    uint32
	id      int64
	request bool
}
type rpcParts struct {
	first  *pb.RpcPacket
	pieces [][]byte
	size   int
	at     time.Time
}
type rpcMerger map[rpcKey]*rpcParts

func (m rpcMerger) feed(p wire.Packet) (*pb.RpcPacket, error) {
	var r pb.RpcPacket
	if err := proto.Unmarshal(p.Payload, &r); err != nil {
		return nil, err
	}
	if r.FromPeer != p.Header.FromPeerID || r.ToPeer != p.Header.ToPeerID || r.IsRequest != (p.Header.PacketType == wire.PacketRPCRequest) {
		return nil, errors.New("RPC envelope identity mismatch")
	}
	if r.TotalPieces == 0 && r.PieceIdx == 0 {
		r.TotalPieces = 1
	}
	if r.TotalPieces == 0 || r.TotalPieces > 4096 || r.PieceIdx >= r.TotalPieces {
		return nil, errors.New("invalid RPC fragment")
	}
	for k, v := range m {
		if time.Since(v.at) > 10*time.Second {
			delete(m, k)
		}
	}
	k := rpcKey{r.FromPeer, r.TransactionId, r.IsRequest}
	v := m[k]
	if v == nil {
		if len(m) >= 64 {
			return nil, errors.New("too many partial RPCs")
		}
		v = &rpcParts{pieces: make([][]byte, r.TotalPieces), at: time.Now()}
		m[k] = v
	}
	if len(v.pieces) != int(r.TotalPieces) {
		delete(m, k)
		return nil, errors.New("RPC fragment count changed")
	}
	if r.PieceIdx == 0 {
		v.first = &r
	}
	if v.pieces[r.PieceIdx] == nil {
		v.pieces[r.PieceIdx] = append([]byte{}, r.Body...)
		v.size += len(r.Body)
	}
	if v.size > 4<<20 {
		delete(m, k)
		return nil, errors.New("RPC exceeds 4 MiB")
	}
	if v.first == nil {
		return nil, nil
	}
	for _, part := range v.pieces {
		if part == nil {
			return nil, nil
		}
	}
	delete(m, k)
	out := v.first
	out.Body = make([]byte, 0, v.size)
	for _, part := range v.pieces {
		out.Body = append(out.Body, part...)
	}
	switch out.CompressionInfo.GetAlgo() {
	case pb.CompressionAlgoPb_Invalid, pb.CompressionAlgoPb_None:
	case pb.CompressionAlgoPb_Zstd:
		var err error
		out.Body, err = decompress(out.Body)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported RPC compression")
	}
	return out, nil
}
func rpcPackets(from, to uint32, id int64, request bool, desc *pb.RpcDescriptor, body []byte) ([]wire.Packet, error) {
	const pieceSize = 1000
	count := (len(body) + pieceSize - 1) / pieceSize
	if count == 0 {
		count = 1
	}
	packets := make([]wire.Packet, 0, count)
	for i := 0; i < count; i++ {
		start := i * pieceSize
		end := start + pieceSize
		if end > len(body) {
			end = len(body)
		}
		r := &pb.RpcPacket{FromPeer: from, ToPeer: to, TransactionId: id, Descriptor_: desc, Body: body[start:end], IsRequest: request, TotalPieces: uint32(count), PieceIdx: uint32(i)}
		if i == 0 {
			r.CompressionInfo = &pb.RpcCompressionInfo{Algo: pb.CompressionAlgoPb_None, AcceptedAlgo: pb.CompressionAlgoPb_Zstd}
		}
		b, err := proto.Marshal(r)
		if err != nil {
			return nil, err
		}
		kind := wire.PacketRPCResponse
		if request {
			kind = wire.PacketRPCRequest
		}
		packets = append(packets, wire.Packet{Header: wire.Header{FromPeerID: from, ToPeerID: to, PacketType: kind, ForwardCounter: 1}, Payload: b})
	}
	return packets, nil
}
func routeDescriptor(network string) *pb.RpcDescriptor {
	return &pb.RpcDescriptor{DomainName: network, ProtoName: "OspfRouteRpc", ServiceName: "OspfRouteRpc", MethodIndex: 1}
}
func routeRequest(r *pb.RpcPacket, network string) (*pb.SyncRouteInfoRequest, error) {
	d := r.Descriptor_
	if d == nil || d.DomainName != network || d.ServiceName != "OspfRouteRpc" || d.ProtoName != "OspfRouteRpc" || d.MethodIndex != 1 {
		return nil, fmt.Errorf("unsupported RPC service %v", d)
	}
	var envelope pb.RpcRequest
	if err := proto.Unmarshal(r.Body, &envelope); err != nil {
		return nil, err
	}
	var request pb.SyncRouteInfoRequest
	if err := proto.Unmarshal(envelope.Request, &request); err != nil {
		return nil, err
	}
	if request.MyPeerId != r.FromPeer {
		return nil, errors.New("route source mismatch")
	}
	return &request, nil
}
