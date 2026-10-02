package transport

import (
	"context"
	"github.com/easytier/easytier-go/internal/wire"
	"net"
	"testing"
	"time"
)

func TestUDPSessionFramingAndDeadline(t *testing.T) {
	a, e := ListenUDP("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := ListenUDP("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, e := a.Dial(ctx, b.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := b.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	if e = Write(client, wire.NewData(1, 2, []byte("hello"))); e != nil {
		t.Fatal(e)
	}
	p, e := Read(server)
	if e != nil || string(p.Payload) != "hello" {
		t.Fatalf("%v %v", p, e)
	}
	if e = server.SetReadDeadline(time.Now().Add(time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if _, e = Read(server); e == nil {
		t.Fatal("missing timeout")
	}
}

func TestUDPConcurrentEndpointAndSessionClose(t *testing.T) {
	for i := 0; i < 20; i++ {
		endpoint, err := ListenUDP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		remote := endpoint.Addr().(*net.UDPAddr)
		c := endpoint.makeConn(remote, 1)
		endpoint.mu.Lock()
		endpoint.sessions[udpKey{remote.String(), 1}] = c
		endpoint.mu.Unlock()
		done := make(chan struct{}, 2)
		go func() { c.Close(); done <- struct{}{} }()
		go func() { endpoint.Close(); done <- struct{}{} }()
		for j := 0; j < 2; j++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("close deadlock")
			}
		}
	}
}
