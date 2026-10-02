// Test-only service/probe running on the Rust node's ordinary network.
package main

import (
	"context"
	"fmt"
	"github.com/easytier/easytier-go/tests/internal/traffic"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: service serve|probe IP:port")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Args[1] == "probe" {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		d := new(net.Dialer)
		if e := traffic.Probe(c, d.DialContext, os.Args[2]); e != nil {
			return e
		}
		fmt.Println("PASS TCP UDP")
		return nil
	}
	if os.Args[1] != "serve" {
		return fmt.Errorf("unknown command")
	}
	l, e := net.Listen("tcp", os.Args[2])
	if e != nil {
		return e
	}
	defer l.Close()
	p, e := net.ListenPacket("udp", os.Args[2])
	if e != nil {
		return e
	}
	defer p.Close()
	go traffic.ServeTCP(l)
	go traffic.ServeUDP(p)
	<-ctx.Done()
	return nil
}
