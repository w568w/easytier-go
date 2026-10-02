//go:build upstream

package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/easytier/easytier-go/internal/wire"
)

// EasyTier v2.6.4 tunnel/common.rs::framed_reader_rejects_short_peer_manager_body.
func TestUpstreamShortFrame(t *testing.T) {
	frame := make([]byte, 4+wire.PeerManagerHeaderSize-1)
	binary.LittleEndian.PutUint32(frame, uint32(wire.PeerManagerHeaderSize-1))
	if _, err := Read(bytes.NewReader(frame)); err == nil {
		t.Fatal("short peer manager body accepted")
	}
}

// tunnel/{tcp,udp}.rs::*_pingpong use this exact payload through the common helper.
func TestUpstreamTunnelPingpong(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var client, server net.Conn
			if network == "tcp" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				client, err = (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				server, err = l.Accept()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				a, err := ListenUDP("127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				b, err := ListenUDP("127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				client, err = a.Dial(ctx, b.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				server, err = b.Accept(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer server.Close()
			deadline, _ := ctx.Deadline()
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)
			done := make(chan error, 1)
			go func() {
				p, e := Read(server)
				if e == nil {
					e = Write(server, p)
				}
				done <- e
			}()
			payload := []byte("12345678abcdefg")
			if e := Write(client, wire.NewData(1, 2, payload)); e != nil {
				t.Fatal(e)
			}
			got, e := Read(client)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got.Payload, payload) {
				t.Fatalf("got %q", got.Payload)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

// tunnel/udp.rs::test_v4_hole_punch_packet.
func TestUpstreamV4PunchPacket(t *testing.T) {
	endpoint, e := ListenUDP("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	target, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	target.SetReadDeadline(time.Now().Add(2 * time.Second))
	if e = endpoint.Probe(target.LocalAddr().String(), 42); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 128)
	n, _, e := target.ReadFrom(b)
	if e != nil {
		t.Fatal(e)
	}
	if n != 24 || b[4] != 5 || binary.LittleEndian.Uint32(b) != 42 || binary.LittleEndian.Uint16(b[6:]) != 16 {
		t.Fatalf("invalid punch packet %x", b[:n])
	}
}
