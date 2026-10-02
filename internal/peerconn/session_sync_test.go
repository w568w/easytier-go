package peerconn

import (
	"bytes"
	"testing"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/wire"
)

func encryptedEpochPacket(t *testing.T, root [32]byte, epoch uint32, seq uint64) wire.Packet {
	t.Helper()
	sender := &Session{root: root, epoch: epoch, seq: seq, sendAlgo: "aes-gcm", started: time.Now()}
	p := wire.NewData(10, 20, []byte("epoch payload"))
	if err := sender.Encrypt(&p); err != nil {
		t.Fatal(err)
	}
	return p
}
func receiveEpochPacket(t *testing.T, s *Session, p wire.Packet, accept bool) {
	t.Helper()
	err := s.Decrypt(&p)
	if accept {
		if err != nil {
			t.Fatal(err)
		}
		if string(p.Payload) != "epoch payload" {
			t.Fatal("payload mismatch")
		}
	} else if err == nil {
		t.Fatal("unexpectedly accepted packet")
	}
}
func receiverBeforeSync(t *testing.T) (*Sessions, *Session) {
	t.Helper()
	s := &Session{generation: 1, public: bytes.Repeat([]byte{9}, 32), sendAlgo: "aes-gcm", recvAlgo: "aes-gcm", started: time.Now()}
	for _, epoch := range []uint32{0, 1} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, epoch, 0), true)
	}
	return &Sessions{peers: map[uint32]*Session{10: s}}, s
}
func syncReceiver(t *testing.T, store *Sessions, s *Session, generation, epoch uint32) {
	t.Helper()
	if _, err := store.apply(10, pb.PeerConnSessionActionPb_Sync, generation, s.root[:], epoch, s.public, s.recvAlgo); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficCipherAliases(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	nonce := bytes.Repeat([]byte{3}, 12)
	payload := []byte("alias payload")
	var reference []byte
	for _, name := range []string{"chacha20", "chacha20-poly1305", "openssl-chacha20"} {
		a, err := trafficCipher(key, name)
		if err != nil {
			t.Fatal(err)
		}
		encrypted := a.Seal(nil, nonce, payload, nil)
		if reference == nil {
			reference = encrypted
		} else if !bytes.Equal(reference, encrypted) {
			t.Fatalf("%s changed ciphertext", name)
		}
		plain, err := a.Open(nil, nonce, reference, nil)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := trafficCipher(key, "unknown-cipher"); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
	public := bytes.Repeat([]byte{9}, 32)
	session := &Session{public: public, sendAlgo: "aes-gcm", recvAlgo: "chacha20"}
	if err := session.check(public, "aes-gcm", "chacha20-poly1305"); err == nil {
		t.Fatal("session algorithm change accepted")
	}
}

func TestSessionSyncGraceReceiveAndReplay(t *testing.T) {
	store, s := receiverBeforeSync(t)
	before := s.rx
	start := time.Now()
	syncReceiver(t, store, s, 2, 2)
	if s.rx != ([2]replayWindow{}) || s.rxGrace != before {
		t.Fatal("SYNC did not move receive windows into grace snapshot")
	}
	if s.rxGraceUntil.Before(start.Add(5*time.Second)) || s.rxGraceUntil.After(time.Now().Add(5*time.Second)) {
		t.Fatal("grace duration differs from upstream five seconds")
	}
	for _, entry := range []struct {
		epoch uint32
		seq   uint64
	}{{2, 0}, {1, 1}, {0, 1}} {
		p := encryptedEpochPacket(t, s.root, entry.epoch, entry.seq)
		receiveEpochPacket(t, s, p, true)
		receiveEpochPacket(t, s, p, false)
	}
	for _, epoch := range []uint32{0, 1} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, epoch, 0), false)
	}
	if !s.rx[0].valid || s.rx[0].epoch != 2 || s.rx[1].valid {
		t.Fatal("old epoch changed regular receive slots")
	}
}

func TestSessionSyncGraceExpires(t *testing.T) {
	store, s := receiverBeforeSync(t)
	syncReceiver(t, store, s, 2, 2)
	receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, 2, 0), true)
	s.mu.Lock()
	s.rxGraceUntil = time.Now()
	s.mu.Unlock()
	for _, epoch := range []uint32{0, 1} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, epoch, 1), false)
	}
	if s.rxGrace != ([2]replayWindow{}) || !s.rxGraceUntil.IsZero() {
		t.Fatal("expired snapshot retained")
	}
	for _, entry := range []struct {
		epoch uint32
		seq   uint64
	}{{2, 1}, {3, 0}, {2, 2}} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, entry.epoch, entry.seq), true)
	}
}

func TestSessionReceiveReset(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     pb.PeerConnSessionActionPb
		changeRoot bool
	}{{"CREATE", pb.PeerConnSessionActionPb_Create, false}, {"SYNC new root", pb.PeerConnSessionActionPb_Sync, true}} {
		t.Run(tc.name, func(t *testing.T) {
			store, s := receiverBeforeSync(t)
			syncReceiver(t, store, s, 2, 2)
			receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, 2, 0), true)
			oldRoot := s.root
			root := oldRoot
			if tc.changeRoot {
				root[0] = 42
			}
			if _, err := store.apply(10, tc.action, 3, root[:], 3, s.public, s.recvAlgo); err != nil {
				t.Fatal(err)
			}
			if s.rx != ([2]replayWindow{}) || s.rxGrace != ([2]replayWindow{}) || !s.rxGraceUntil.IsZero() {
				t.Fatal("receive state survived reset")
			}
			receiveEpochPacket(t, s, encryptedEpochPacket(t, root, 3, 0), true)
			receiveEpochPacket(t, s, encryptedEpochPacket(t, oldRoot, 1, 1), false)
			if tc.changeRoot {
				receiveEpochPacket(t, s, encryptedEpochPacket(t, oldRoot, 4, 0), false)
			}
		})
	}
}

func TestSessionJoinPreservesReceiveState(t *testing.T) {
	store, s := receiverBeforeSync(t)
	syncReceiver(t, store, s, 2, 2)
	receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, 2, 0), true)
	rx, grace, until := s.rx, s.rxGrace, s.rxGraceUntil
	joined, err := store.apply(10, pb.PeerConnSessionActionPb_Join, 2, nil, 99, s.public, s.recvAlgo)
	if err != nil {
		t.Fatal(err)
	}
	if joined != s || s.rx != rx || s.rxGrace != grace || s.rxGraceUntil != until || s.epoch != 2 {
		t.Fatal("JOIN changed existing state")
	}
}

func TestSessionRepeatedSyncReplacesGrace(t *testing.T) {
	store, s := receiverBeforeSync(t)
	syncReceiver(t, store, s, 2, 2)
	for _, epoch := range []uint32{2, 3} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, epoch, 0), true)
	}
	latest := s.rx
	syncReceiver(t, store, s, 3, 4)
	if s.rxGrace != latest {
		t.Fatal("second SYNC did not replace snapshot")
	}
	for _, entry := range []struct {
		epoch uint32
		seq   uint64
	}{{4, 0}, {3, 1}, {2, 1}} {
		receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, entry.epoch, entry.seq), true)
	}
	receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, 0, 1), false)
}

func TestSessionFailedDecryptPreservesReceiveState(t *testing.T) {
	store, s := receiverBeforeSync(t)
	syncReceiver(t, store, s, 2, 2)
	receiveEpochPacket(t, s, encryptedEpochPacket(t, s.root, 2, 0), true)
	for _, epoch := range []uint32{0, 3} {
		original := encryptedEpochPacket(t, s.root, epoch, 10)
		forged := original
		forged.Payload = bytes.Clone(original.Payload)
		forged.Payload[0] ^= 1
		rx, grace := s.rx, s.rxGrace
		receiveEpochPacket(t, s, forged, false)
		if s.rx != rx || s.rxGrace != grace {
			t.Fatal("failed decryption changed receive state")
		}
		receiveEpochPacket(t, s, original, true)
		receiveEpochPacket(t, s, original, false)
	}
}
