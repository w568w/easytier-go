package peerconn

import (
	"context"
	"testing"
	"time"
)

func TestNoiseHandshakeBetweenGoPeers(t *testing.T) {
	serverSecurity, err := NewSecurity(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSecurity, err := NewSecurity(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := Config{PeerID: 2, NetworkName: "test", NetworkSecret: "secret", Timeout: time.Second, Security: serverSecurity}
	listener, err := Listen("127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		c, e := listener.Accept(context.Background())
		if c != nil {
			c.Close()
		}
		accepted <- e
	}()
	client, err := Dial(context.Background(), listener.Addr().String(), Config{PeerID: 1, NetworkName: "test", NetworkSecret: "secret", Timeout: time.Second, Security: clientSecurity})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}
