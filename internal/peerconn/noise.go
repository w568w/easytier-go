package peerconn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"
	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"
)

// Security is one node's static identity and shared direct/relay session store.
type Security struct {
	key      noise.DHKey
	Sessions Sessions
}

func NewSecurity(private []byte) (*Security, error) {
	var key *ecdh.PrivateKey
	var err error
	if len(private) == 0 {
		key, err = ecdh.X25519().GenerateKey(rand.Reader)
	} else {
		key, err = ecdh.X25519().NewPrivateKey(private)
	}
	if err != nil {
		return nil, err
	}
	return &Security{key: noise.DHKey{Private: key.Bytes(), Public: key.PublicKey().Bytes()}}, nil
}
func (s *Security) PublicKey() []byte { return bytes.Clone(s.key.Public) }
func (s *Security) handshake(initiator, relay bool, remote []byte) (*noise.HandshakeState, error) {
	pattern, prologue := noise.HandshakeXX, "easytier-peerconn-noise"
	if relay {
		pattern, prologue = noise.HandshakeIK, "easytier-relay-noise"
	}
	return noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: pattern, Initiator: initiator, Prologue: []byte(prologue), StaticKeypair: s.key, PeerStatic: remote})
}
func proof(secret string, challenge []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("easytier secret proof"))
	m.Write(challenge)
	return m.Sum(nil)
}
func newUUID() *pb.UUID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return &pb.UUID{Part1: binary.LittleEndian.Uint32(b[:4]), Part2: binary.LittleEndian.Uint32(b[4:8]), Part3: binary.LittleEndian.Uint32(b[8:12]), Part4: binary.LittleEndian.Uint32(b[12:])}
}
func noiseWrite(h *noise.HandshakeState, m proto.Message) ([]byte, error) {
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	b, _, _, err = h.WriteMessage(nil, b)
	return b, err
}
func noiseRead(h *noise.HandshakeState, b []byte, m proto.Message) error {
	b, _, _, err := h.ReadMessage(nil, b)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, m)
}
func (c *Conn) sendNoise(h *noise.HandshakeState, kind wire.PacketType, m proto.Message) error {
	payload, err := noiseWrite(h, m)
	if err != nil {
		return err
	}
	return transport.Write(c.socket, wire.Packet{Header: wire.Header{FromPeerID: c.localID, ToPeerID: c.remoteID, PacketType: kind, ForwardCounter: 1}, Payload: payload})
}
func (c *Conn) readNoise(h *noise.HandshakeState, kind wire.PacketType, m proto.Message) error {
	p, err := transport.Read(c.socket)
	if err != nil {
		return err
	}
	if p.Header.PacketType != kind || (c.remoteID != 0 && p.Header.FromPeerID != c.remoteID) {
		return errors.New("unexpected Noise packet")
	}
	if p.Header.FromPeerID == 0 || p.Header.FromPeerID == c.localID {
		return errors.New("invalid Noise peer ID")
	}
	c.remoteID = p.Header.FromPeerID
	return noiseRead(h, p.Payload, m)
}
func (c *Conn) noiseClient(cfg Config) error {
	h, err := cfg.Security.handshake(true, false, nil)
	if err != nil {
		return err
	}
	id := newUUID()
	if err = c.sendNoise(h, wire.PacketNoiseHandshakeMsg1, &pb.PeerConnNoiseMsg1Pb{Version: 1, ANetworkName: cfg.NetworkName, AConnId: id, ClientEncryptionAlgorithm: "aes-gcm"}); err != nil {
		return err
	}
	challenge := bytes.Clone(h.ChannelBinding())
	var rsp pb.PeerConnNoiseMsg2Pb
	if err = c.readNoise(h, wire.PacketNoiseHandshakeMsg2, &rsp); err != nil {
		return err
	}
	if rsp.BNetworkName != cfg.NetworkName || rsp.RoleHint != 1 || !proto.Equal(rsp.AConnIdEcho, id) || !hmac.Equal(rsp.SecretProof_32, proof(cfg.NetworkSecret, challenge)) {
		return errors.New("Noise responder authentication failed")
	}
	digest := NetworkDigest(cfg.NetworkName, cfg.NetworkSecret)
	if err = c.sendNoise(h, wire.PacketNoiseHandshakeMsg3, &pb.PeerConnNoiseMsg3Pb{AConnIdEcho: id, BConnIdEcho: rsp.BConnId, SecretProof_32: proof(cfg.NetworkSecret, h.ChannelBinding()), SecretDigest: digest[:]}); err != nil {
		return err
	}
	c.session, err = cfg.Security.Sessions.apply(c.remoteID, rsp.Action, rsp.BSessionGeneration, rsp.RootKey_32, rsp.InitialEpoch, h.PeerStatic(), rsp.ServerEncryptionAlgorithm)
	return err
}
func (c *Conn) noiseServer(cfg Config, p wire.Packet) error {
	h, err := cfg.Security.handshake(false, false, nil)
	if err != nil {
		return err
	}
	c.remoteID = p.Header.FromPeerID
	if c.remoteID == 0 || c.remoteID == c.localID {
		return errors.New("invalid Noise peer ID")
	}
	var req pb.PeerConnNoiseMsg1Pb
	if err = noiseRead(h, p.Payload, &req); err != nil {
		return err
	}
	if req.Version != 1 || req.ANetworkName != cfg.NetworkName || req.AConnId == nil {
		return errors.New("invalid Noise request")
	}
	session, action, root, epoch, err := cfg.Security.Sessions.respond(c.remoteID, req.ASessionGeneration, nil, req.ClientEncryptionAlgorithm)
	if err != nil {
		return err
	}
	id := newUUID()
	rsp := &pb.PeerConnNoiseMsg2Pb{BNetworkName: cfg.NetworkName, RoleHint: 1, Action: action, BSessionGeneration: session.Generation(), RootKey_32: root, InitialEpoch: epoch, BConnId: id, AConnIdEcho: req.AConnId, SecretProof_32: proof(cfg.NetworkSecret, h.ChannelBinding()), ServerEncryptionAlgorithm: "aes-gcm"}
	if err = c.sendNoise(h, wire.PacketNoiseHandshakeMsg2, rsp); err != nil {
		return err
	}
	challenge := bytes.Clone(h.ChannelBinding())
	var last pb.PeerConnNoiseMsg3Pb
	if err = c.readNoise(h, wire.PacketNoiseHandshakeMsg3, &last); err != nil {
		return err
	}
	if !proto.Equal(last.AConnIdEcho, req.AConnId) || !proto.Equal(last.BConnIdEcho, id) || !hmac.Equal(last.SecretProof_32, proof(cfg.NetworkSecret, challenge)) {
		return errors.New("Noise initiator authentication failed")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.public) > 0 && !bytes.Equal(session.public, h.PeerStatic()) {
		return errors.New("Noise initiator key changed")
	}
	session.public = bytes.Clone(h.PeerStatic())
	c.session = session
	return nil
}
