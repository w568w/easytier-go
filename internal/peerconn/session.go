package peerconn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
	"golang.org/x/crypto/chacha20poly1305"
)

const syncReceiveGrace = 5 * time.Second

// Sessions belongs to one network identity and is shared by its connections.
type Sessions struct {
	mu    sync.Mutex
	peers map[uint32]*Session
}

func (s *Sessions) get(id uint32) *Session { s.mu.Lock(); defer s.mu.Unlock(); return s.peers[id] }

type Session struct {
	mu                 sync.Mutex
	root               [32]byte
	generation, epoch  uint32
	seq, count         uint64
	started            time.Time
	public             []byte
	sendAlgo, recvAlgo string
	rx                 [2]replayWindow
	rxGrace            [2]replayWindow
	rxGraceUntil       time.Time
}
type replayWindow struct {
	epoch uint32
	max   uint64
	seen  [256]bool
	valid bool
}

func (s *Session) Generation() uint32 { s.mu.Lock(); defer s.mu.Unlock(); return s.generation }
func (s *Session) check(public []byte, send, recv string) error {
	if len(public) != 32 || (len(s.public) > 0 && !bytes.Equal(s.public, public)) {
		return errors.New("session public key mismatch")
	}
	if s.sendAlgo != send || s.recvAlgo != recv {
		return errors.New("session algorithm mismatch")
	}
	return nil
}

func (s *Sessions) respond(id uint32, generation *uint32, public []byte, recv string) (*Session, pb.PeerConnSessionActionPb, []byte, uint32, error) {
	if _, err := trafficCipher(make([]byte, 32), recv); err != nil {
		return nil, 0, nil, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers == nil {
		s.peers = make(map[uint32]*Session)
	}
	v := s.peers[id]
	if v == nil {
		v = &Session{generation: 1, public: bytes.Clone(public), sendAlgo: "aes-gcm", recvAlgo: recv, started: time.Now()}
		if _, err := rand.Read(v.root[:]); err != nil {
			return nil, 0, nil, 0, err
		}
		s.peers[id] = v
		return v, pb.PeerConnSessionActionPb_Create, bytes.Clone(v.root[:]), 0, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	// XX reveals the initiator static key only in message 3.
	if len(public) > 0 {
		if err := v.check(public, "aes-gcm", recv); err != nil {
			return nil, 0, nil, 0, err
		}
	}
	if v.recvAlgo != recv {
		return nil, 0, nil, 0, errors.New("session algorithm mismatch")
	}
	if generation != nil && *generation == v.generation {
		return v, pb.PeerConnSessionActionPb_Join, nil, 0, nil
	}
	epoch := v.epoch
	for _, w := range v.rx {
		if w.valid && w.epoch > epoch {
			epoch = w.epoch
		}
	}
	if epoch == ^uint32(0) {
		return nil, 0, nil, 0, errors.New("epoch exhausted")
	}
	return v, pb.PeerConnSessionActionPb_Sync, bytes.Clone(v.root[:]), epoch + 1, nil
}

func (s *Sessions) apply(id uint32, action pb.PeerConnSessionActionPb, generation uint32, root []byte, epoch uint32, public []byte, recv string) (*Session, error) {
	if _, err := trafficCipher(make([]byte, 32), recv); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers == nil {
		s.peers = make(map[uint32]*Session)
	}
	v := s.peers[id]
	if action == pb.PeerConnSessionActionPb_Join {
		if v == nil {
			return nil, errors.New("JOIN without existing session")
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.generation != generation {
			return nil, errors.New("JOIN generation mismatch")
		}
		return v, v.check(public, "aes-gcm", recv)
	}
	if (action != pb.PeerConnSessionActionPb_Create && action != pb.PeerConnSessionActionPb_Sync) || len(root) != 32 || len(public) != 32 {
		return nil, errors.New("invalid session action or key")
	}
	if v == nil {
		v = &Session{sendAlgo: "aes-gcm", recvAlgo: recv, public: bytes.Clone(public)}
		s.peers[id] = v
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(public, "aes-gcm", recv); err != nil {
		return nil, err
	}
	if action == pb.PeerConnSessionActionPb_Sync && bytes.Equal(v.root[:], root) {
		v.rxGrace = v.rx
		v.rxGraceUntil = time.Now().Add(syncReceiveGrace)
	} else {
		v.rxGrace = [2]replayWindow{}
		v.rxGraceUntil = time.Time{}
	}
	v.rx = [2]replayWindow{}
	copy(v.root[:], root)
	v.generation = generation
	v.epoch = epoch
	v.seq = 0
	v.count = 0
	v.started = time.Now()
	return v, nil
}

func trafficCipher(key []byte, algo string) (cipher.AEAD, error) {
	switch algo {
	case "", "aes-gcm", "openssl-aes128-gcm":
		key = key[:16]
	case "aes-256-gcm", "aes-gcm-256", "openssl-aes256-gcm":
	case "chacha20", "chacha20-poly1305", "openssl-chacha20":
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported session cipher %q", algo)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func (s *Session) cipher(epoch uint32, from, to uint32, algo string) (cipher.AEAD, error) {
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(s.root[:])
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("et-traffic"))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], epoch)
	expand.Write(encoded[:])
	dir := byte(0)
	if from >= to {
		dir = 1
	}
	expand.Write([]byte{dir, 1})
	return trafficCipher(expand.Sum(nil), algo)
}
func (s *Session) Encrypt(p *wire.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Header.Flags&wire.FlagEncrypted != 0 {
		return nil
	}
	if s.count >= 999999 || time.Since(s.started) >= 10*time.Minute {
		if s.epoch == ^uint32(0) {
			return errors.New("epoch exhausted")
		}
		s.epoch++
		s.count = 0
		s.started = time.Now()
	}
	if s.seq == ^uint64(0) {
		return errors.New("sequence exhausted")
	}
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], s.epoch)
	binary.BigEndian.PutUint64(nonce[4:], s.seq)
	a, err := s.cipher(s.epoch, p.Header.FromPeerID, p.Header.ToPeerID, s.sendAlgo)
	if err != nil {
		return err
	}
	p.Header.Length = uint32(len(p.Payload))
	p.Payload = append(a.Seal(nil, nonce[:], p.Payload, nil), nonce[:]...)
	p.Header.Flags |= wire.FlagEncrypted
	s.seq++
	s.count++
	return nil
}
func (s *Session) Decrypt(p *wire.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Header.Flags&wire.FlagEncrypted == 0 || len(p.Payload) < 28 {
		return errors.New("missing secure ciphertext")
	}
	nonce := p.Payload[len(p.Payload)-12:]
	epoch := binary.BigEndian.Uint32(nonce)
	seq := binary.BigEndian.Uint64(nonce[4:])
	if !s.rxGraceUntil.IsZero() && !time.Now().Before(s.rxGraceUntil) {
		s.rxGrace = [2]replayWindow{}
		s.rxGraceUntil = time.Time{}
	}
	var w *replayWindow
	for i := range s.rxGrace {
		if s.rxGrace[i].valid && s.rxGrace[i].epoch == epoch {
			w = &s.rxGrace[i]
			break
		}
	}
	if w == nil {
		for i := range s.rx {
			if s.rx[i].valid && s.rx[i].epoch == epoch {
				w = &s.rx[i]
				break
			}
		}
	}
	if w != nil {
		if seq <= w.max && (w.max-seq >= 256 || w.seen[seq%256]) {
			return errors.New("replayed packet")
		}
	} else if s.rx[0].valid {
		baseline := s.rx[0].epoch
		if s.epoch > baseline {
			baseline = s.epoch
		}
		if epoch < s.rx[0].epoch || uint64(epoch) > uint64(baseline)+3 {
			return errors.New("invalid receive epoch")
		}
	}
	a, err := s.cipher(epoch, p.Header.FromPeerID, p.Header.ToPeerID, s.recvAlgo)
	if err != nil {
		return err
	}
	plain, err := a.Open(nil, nonce, p.Payload[:len(p.Payload)-12], nil)
	if err != nil {
		return err
	}
	if w == nil {
		s.rx[1] = s.rx[0]
		s.rx[0] = replayWindow{epoch: epoch, valid: true}
		w = &s.rx[0]
	}
	if seq > w.max {
		if seq-w.max >= 256 {
			w.seen = [256]bool{}
		} else {
			for j := w.max + 1; j <= seq; j++ {
				w.seen[j%256] = false
			}
		}
		w.max = seq
	}
	w.seen[seq%256] = true
	p.Payload = plain
	p.Header.Flags &^= wire.FlagEncrypted
	return nil
}
