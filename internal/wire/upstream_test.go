//go:build upstream

package wire

import (
	"bytes"
	"testing"
)

// EasyTier v2.6.4 tunnel/packet_def.rs::test_zc_packet and short-header access tests.
func TestUpstreamPacketLayout(t *testing.T) {
	payload := []byte("hello world")
	p := NewData(1, 2, payload)
	b, e := p.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParsePacket(b)
	if e != nil {
		t.Fatal(e)
	}
	if got.Header.Length != 11 || got.Header.PacketType != PacketData || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("round trip: %+v", got)
	}
}
func TestUpstreamShortPacket(t *testing.T) {
	if _, e := ParseHeader([]byte{1}); e == nil {
		t.Fatal("short header accepted")
	}
	if _, e := ParsePacket([]byte{1}); e == nil {
		t.Fatal("short packet accepted")
	}
}
