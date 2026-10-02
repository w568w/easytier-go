//go:build upstream

package peerconn

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// EasyTier v2.6.4 peers/encrypt/aes_gcm.rs::test_aes_gcm_cipher.
func TestUpstreamAESGCM(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	enc := Encryptor{cipher: aead}
	payload := []byte("1234567")
	p := wire.NewData(0, 0, payload)
	if err = enc.Encrypt(&p); err != nil {
		t.Fatal(err)
	}
	if len(p.Payload) != len(payload)+28 || p.Header.Flags&wire.FlagEncrypted == 0 {
		t.Fatal("encrypted packet tail or flag mismatch")
	}
	if err = enc.Decrypt(&p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Payload, payload) || p.Header.Flags&wire.FlagEncrypted != 0 {
		t.Fatal("decrypted payload or flag mismatch")
	}
}

// peers/{peer_session,secure_datagram}.rs::*supports_asymmetric_algorithms.
func TestUpstreamAsymmetricAlgorithms(t *testing.T) {
	for _, chacha := range []string{"chacha20-poly1305", "chacha20"} {
		t.Run(chacha, func(t *testing.T) {
			a := &Session{sendAlgo: "aes-256-gcm", recvAlgo: chacha, started: time.Now()}
			b := &Session{sendAlgo: chacha, recvAlgo: "aes-256-gcm", started: time.Now()}
			for _, direction := range []struct {
				sender, receiver *Session
				from, to         uint32
				text             string
			}{{a, b, 10, 20, "hello from a"}, {b, a, 20, 10, "hello from b"}} {
				p := wire.NewData(direction.from, direction.to, []byte(direction.text))
				if e := direction.sender.Encrypt(&p); e != nil {
					t.Fatal(e)
				}
				if e := direction.receiver.Decrypt(&p); e != nil {
					t.Fatal(e)
				}
				if string(p.Payload) != direction.text {
					t.Fatal("payload mismatch")
				}
			}
		})
	}
}

// secure_datagram.rs::replay_window_out_of_order_within_window.
func TestUpstreamOutOfOrderWindow(t *testing.T) {
	tx := &Session{sendAlgo: "aes-256-gcm", recvAlgo: "aes-256-gcm", started: time.Now()}
	rx := &Session{sendAlgo: "aes-256-gcm", recvAlgo: "aes-256-gcm", started: time.Now()}
	packets := make([]wire.Packet, 21)
	for i := range packets {
		packets[i] = wire.NewData(10, 20, []byte{byte(i)})
		if e := tx.Encrypt(&packets[i]); e != nil {
			t.Fatal(e)
		}
	}
	for _, parity := range []int{0, 1} {
		for i := parity; i < len(packets); i += 2 {
			p := packets[i]
			if e := rx.Decrypt(&p); e != nil {
				t.Fatalf("seq %d: %v", i, e)
			}
			if !bytes.Equal(p.Payload, []byte{byte(i)}) {
				t.Fatal("payload mismatch")
			}
		}
	}
	for _, packet := range packets {
		p := packet
		if e := rx.Decrypt(&p); e == nil {
			t.Fatal("duplicate accepted")
		}
	}
}

// secure_datagram.rs::sync_root_key_keeps_previous_epochs_during_grace_window.
func TestUpstreamSyncEpochGrace(t *testing.T) {
	public := bytes.Repeat([]byte{9}, 32)
	rx := &Session{generation: 1, public: public, sendAlgo: "aes-gcm", recvAlgo: "aes-256-gcm", started: time.Now()}
	sessions := Sessions{peers: map[uint32]*Session{10: rx}}
	packet := func(epoch uint32, seq uint64) wire.Packet {
		sender := &Session{root: rx.root, epoch: epoch, seq: seq, sendAlgo: "aes-256-gcm", started: time.Now()}
		p := wire.NewData(10, 20, []byte("data"))
		if e := sender.Encrypt(&p); e != nil {
			t.Fatal(e)
		}
		return p
	}
	for _, epoch := range []uint32{0, 1} {
		p := packet(epoch, 0)
		if e := rx.Decrypt(&p); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := sessions.apply(10, pb.PeerConnSessionActionPb_Sync, 2, rx.root[:], 2, public, "aes-256-gcm"); e != nil {
		t.Fatal(e)
	}
	for _, entry := range []struct {
		epoch uint32
		seq   uint64
	}{{2, 0}, {1, 1}, {0, 1}} {
		p := packet(entry.epoch, entry.seq)
		if e := rx.Decrypt(&p); e != nil {
			t.Fatalf("epoch %d seq %d in immediate post-SYNC window: %v", entry.epoch, entry.seq, e)
		}
	}
}

// peers/peer_conn.rs::peer_conn_handshake_same_id.
func TestUpstreamHandshakeSameID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cfg := Config{PeerID: 7, NetworkName: "upstream", NetworkSecret: "secret", Timeout: time.Second}
	l, e := Listen("127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted := make(chan error, 1)
	go func() {
		c, e := l.Accept(ctx)
		if c != nil {
			c.Close()
		}
		accepted <- e
	}()
	c, e := Dial(ctx, l.Addr().String(), cfg)
	if c != nil {
		c.Close()
	}
	if e == nil {
		t.Fatal("client accepted duplicate identity")
	}
	if e = <-accepted; e == nil {
		t.Fatal("server accepted duplicate identity")
	}
}

// peer_ospf_route.rs::test_raw_peer_info and unknown-field preservation for shared senders.
func TestUpstreamRouteUnknownFields(t *testing.T) {
	for _, bitmap := range []bool{false, true} {
		t.Run(map[bool]string{false: "list", true: "bitmap"}[bitmap], func(t *testing.T) {
			top := newTopology(1)
			peers := map[uint32]*Conn{2: {}}
			top.localLinks(1, peers)
			unknown := protowire.AppendVarint(protowire.AppendTag(nil, 9999, protowire.VarintType), 42)
			info := &pb.RoutePeerInfo{PeerId: 2, Version: 1}
			raw := append(mustProto(info), unknown...)
			if e := proto.Unmarshal(raw, info); e != nil {
				t.Fatal(e)
			}
			request := &pb.SyncRouteInfoRequest{MyPeerId: 2, PeerInfos: &pb.RoutePeerInfos{Items: []*pb.RoutePeerInfo{info}}}
			if bitmap {
				request.ConnInfo = &pb.SyncRouteInfoRequest_ConnBitmap{ConnBitmap: &pb.RouteConnBitmap{PeerIds: []*pb.PeerIdVersion{{PeerId: 2, Version: 1}}, Bitmap: []byte{0}}}
			} else {
				request.ConnInfo = &pb.SyncRouteInfoRequest_ConnPeerList{ConnPeerList: &pb.RouteConnPeerList{PeerConnInfos: []*pb.RouteConnPeerList_PeerConnInfo{{PeerId: &pb.PeerIdVersion{PeerId: 2, Version: 1}, ConnectedPeerIds: []uint32{1}}}}}
			}
			if e := top.merge(1, request); e != nil {
				t.Fatal(e)
			}
			top.rebuild(1, peers)
			var out pb.SyncRouteInfoRequest
			if e := proto.Unmarshal(mustProto(top.snapshot(1, 1)), &out); e != nil {
				t.Fatal(e)
			}
			for _, v := range out.GetPeerInfos().GetItems() {
				if v.PeerId == 2 {
					if !bytes.Equal(v.ProtoReflect().GetUnknown(), unknown) {
						t.Fatal("unknown route field lost")
					}
					return
				}
			}
			t.Fatal("route peer missing")
		})
	}
}
