// Package traffic provides bounded TCP and UDP echo checks for interoperability tests.
package traffic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

func ServeTCP(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(15 * time.Second)); _, _ = io.Copy(c, c) }()
	}
}
func ServeUDP(p net.PacketConn) {
	b := make([]byte, 65536)
	for {
		n, a, e := p.ReadFrom(b)
		if e != nil {
			return
		}
		_, _ = p.WriteTo(b[:n], a)
	}
}
func Probe(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), target string) error {
	for _, network := range []string{"tcp", "udp"} {
		c, e := dial(ctx, network, target)
		if e != nil {
			return fmt.Errorf("%s dial: %w", network, e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		size := 1024
		if network == "tcp" {
			size = 32768
		}
		payload := bytes.Repeat([]byte{0x42}, size)
		done := make(chan error, 1)
		go func() { _, e := c.Write(payload); done <- e }()
		got := make([]byte, len(payload))
		_, e = io.ReadFull(c, got)
		c.Close()
		we := <-done
		if e != nil {
			return fmt.Errorf("%s read: %w", network, e)
		}
		if we != nil {
			return fmt.Errorf("%s write: %w", network, we)
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("%s payload mismatch", network)
		}
	}
	return nil
}
