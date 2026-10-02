package peerconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"
)

// One exchange per remote peer. n.mu protects the Noise state; closing done
// publishes the result to all concurrent senders, including collision losers.
type relayAttempt struct {
	handshake *noise.HandshakeState
	connID    *pb.UUID
	public    []byte
	done      chan struct{}
	session   *Session
	err       error
	responder bool
}

func (n *Node) relayIdentity(peer uint32) (*Security, []byte, error) {
	if n.config == nil || n.config.Security == nil {
		return nil, nil, errors.New("secure mode is required for relay Noise")
	}
	info := n.topo.infos[peer]
	if info == nil || len(info.NoiseStaticPubkey) != 32 {
		return nil, nil, fmt.Errorf("peer %d has no route public key", peer)
	}
	return n.config.Security, bytes.Clone(info.NoiseStaticPubkey), nil
}

func (n *Node) completeRelay(peer uint32, a *relayAttempt, s *Session, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.relay[peer] != a {
		return
	}
	delete(n.relay, peer)
	a.session = s
	a.err = err
	close(a.done)
}

func (n *Node) ensureRelay(ctx context.Context, peer uint32) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	security, public, err := n.relayIdentity(peer)
	if err != nil {
		n.mu.Unlock()
		return nil, err
	}
	if s := security.Sessions.get(peer); s != nil {
		s.mu.Lock()
		matches := bytes.Equal(s.public, public)
		s.mu.Unlock()
		if matches {
			n.mu.Unlock()
			return s, nil
		}
		n.mu.Unlock()
		return nil, errors.New("route key differs from established session")
	}
	a := n.relay[peer]
	owner := a == nil
	var payload []byte
	if owner {
		h, e := security.handshake(true, true, public)
		if e != nil {
			n.mu.Unlock()
			return nil, e
		}
		a = &relayAttempt{handshake: h, connID: newUUID(), public: public, done: make(chan struct{})}
		payload, err = noiseWrite(h, &pb.RelayNoiseMsg1Pb{Version: 1, AConnId: a.connID, ClientEncryptionAlgorithm: "aes-gcm"})
		if err != nil {
			n.mu.Unlock()
			return nil, err
		}
		n.relay[peer] = a
	}
	timeout := n.config.Timeout
	n.mu.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if owner {
		err = n.sendRelay(waitCtx, peer, wire.PacketRelayHandshake, payload)
		if err != nil {
			n.completeRelay(peer, a, nil, err)
		}
	}
	select {
	case <-a.done:
		return a.session, a.err
	case <-waitCtx.Done():
		if owner {
			n.completeRelay(peer, a, nil, waitCtx.Err())
		}
		return nil, waitCtx.Err()
	}
}

func (n *Node) sendRelay(ctx context.Context, peer uint32, kind wire.PacketType, payload []byte) error {
	c, err := n.nextHop(peer)
	if err != nil {
		return err
	}
	return c.write(ctx, wire.Packet{Header: wire.Header{FromPeerID: n.ID, ToPeerID: peer, PacketType: kind, ForwardCounter: 1}, Payload: payload})
}

func (n *Node) handleRelay(ctx context.Context, p wire.Packet) error {
	peer := p.Header.FromPeerID
	if peer == 0 || peer == n.ID || p.Header.Flags&wire.FlagEncrypted != 0 {
		return errors.New("invalid relay header")
	}
	n.mu.Lock()
	security, public, err := n.relayIdentity(peer)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	a := n.relay[peer]
	if p.Header.PacketType == wire.PacketRelayHandshakeAck {
		if a == nil || a.responder {
			n.mu.Unlock()
			return nil
		}
		var rsp pb.RelayNoiseMsg2Pb
		err = noiseRead(a.handshake, p.Payload, &rsp)
		if err == nil && (!proto.Equal(rsp.AConnIdEcho, a.connID) || rsp.BConnId == nil || !bytes.Equal(public, a.public)) {
			err = errors.New("relay ack identity mismatch")
		}
		var session *Session
		if err == nil {
			session, err = security.Sessions.apply(peer, rsp.Action, rsp.BSessionGeneration, rsp.RootKey_32, rsp.InitialEpoch, public, rsp.ServerEncryptionAlgorithm)
		}
		n.mu.Unlock()
		n.completeRelay(peer, a, session, err)
		return err
	}
	h, err := security.handshake(false, true, nil)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	var req pb.RelayNoiseMsg1Pb
	if err = noiseRead(h, p.Payload, &req); err != nil {
		n.mu.Unlock()
		return err
	}
	if req.Version != 1 || req.AConnId == nil || !bytes.Equal(h.PeerStatic(), public) {
		n.mu.Unlock()
		return errors.New("relay initiator authentication failed")
	}
	// The smaller peer ID keeps its initiator role when both ends start together.
	if a != nil && !a.responder && n.ID < peer {
		n.mu.Unlock()
		return nil
	}
	if a != nil {
		a.responder = true
	}
	session, action, root, epoch, err := security.Sessions.respond(peer, req.ASessionGeneration, public, req.ClientEncryptionAlgorithm)
	if err != nil {
		n.mu.Unlock()
		if a != nil {
			n.completeRelay(peer, a, nil, err)
		}
		return err
	}
	payload, err := noiseWrite(h, &pb.RelayNoiseMsg2Pb{Action: action, BSessionGeneration: session.Generation(), RootKey_32: root, InitialEpoch: epoch, BConnId: newUUID(), AConnIdEcho: req.AConnId, ServerEncryptionAlgorithm: "aes-gcm"})
	n.mu.Unlock()
	if err == nil {
		err = n.sendRelay(ctx, peer, wire.PacketRelayHandshakeAck, payload)
	}
	if a != nil {
		n.completeRelay(peer, a, session, err)
	}
	return err
}
