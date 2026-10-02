package wire

import "testing"

func TestPacketRoundTripUsesRustLayout(t *testing.T) {
	p := NewData(0x01020304, 0x05060708, []byte{1, 2, 3})
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{4, 3, 2, 1, 8, 7, 6, 5, 1, 0, 1, 0, 3, 0, 0, 0, 1, 2, 3}
	if string(b) != string(want) {
		t.Fatalf("wire bytes = %v, want %v", b, want)
	}
	got, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.FromPeerID != p.Header.FromPeerID || string(got.Payload) != string(p.Payload) {
		t.Fatalf("round trip = %#v", got)
	}
}
