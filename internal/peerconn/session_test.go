package peerconn

import (
	"bytes"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/wire"
)

func TestSecureDatagramReorderReplayAndTamper(t *testing.T) {
	a := &Session{sendAlgo: "aes-gcm", recvAlgo: "aes-gcm", started: time.Now()}
	b := &Session{root: a.root, sendAlgo: "aes-gcm", recvAlgo: "aes-gcm", started: time.Now()}
	var packets []wire.Packet
	for i := 0; i < 3; i++ {
		p := wire.NewData(1, 2, []byte{byte(i)})
		if err := a.Encrypt(&p); err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	forged := packets[2]
	forged.Payload = bytes.Clone(forged.Payload)
	forged.Payload[0] ^= 1
	if err := b.Decrypt(&forged); err == nil {
		t.Fatal("tampering accepted")
	}
	for _, i := range []int{2, 0, 1} {
		p := packets[i]
		if err := b.Decrypt(&p); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p.Payload, []byte{byte(i)}) {
			t.Fatal("bad plaintext")
		}
	}
	p := packets[2]
	if err := b.Decrypt(&p); err == nil {
		t.Fatal("replay accepted")
	}
}
