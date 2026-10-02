package peerpb

import (
	"bytes"
	"google.golang.org/protobuf/proto"
	"testing"
)

// These bytes use the upstream field numbers, independently of our descriptor
// package/file names (which differ so Mihomo can import both implementations).
func TestUpstreamHostnameWire(t *testing.T) {
	var info RoutePeerInfo
	raw := []byte{0x08, 0x07, 0x32, 0x04, 'n', 'o', 'd', 'e'}
	if err := proto.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	if info.PeerId != 7 || info.GetHostname() != "node" {
		t.Fatalf("%v", &info)
	}
	got, err := proto.Marshal(&info)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("%x %v", got, err)
	}
}
func TestUpstreamErrorOneof(t *testing.T) {
	fields := []string{"other_error", "invalid_method_index", "invalid_service", "prost_decode_error", "prost_encode_error", "execute_error", "malformat_rpc_packet", "timeout"}
	for i, want := range fields {
		raw := []byte{byte((i+1)<<3 | 2), 0}
		var e Error
		if err := proto.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		desc := e.ProtoReflect()
		field := desc.WhichOneof(desc.Descriptor().Oneofs().ByName("error_kind"))
		if field == nil || string(field.Name()) != want {
			t.Fatalf("field %d decoded as %v", i+1, field)
		}
		got, err := proto.Marshal(&e)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%x %v", got, err)
		}
	}
}
