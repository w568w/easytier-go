// Test-only embedded node driver.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	et "github.com/easytier/easytier-go"
	"github.com/easytier/easytier-go/tests/internal/hosttrace"
	"github.com/easytier/easytier-go/tests/internal/traffic"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var c et.Config
	host := new(hosttrace.Network)
	c.HostNetwork = host
	defer func() {
		fmt.Printf("host calls dial=%d listen=%d packet=%d dns=%d\n", host.Dials.Load(), host.Listeners.Load(), host.Packets.Load(), host.DNS.Load())
	}()
	flag.StringVar(&c.NetworkName, "network-name", "interop", "network")
	flag.StringVar(&c.NetworkSecret, "network-secret", "test-secret", "secret")
	flag.StringVar(&c.Hostname, "hostname", "go-node", "overlay name")
	listen := flag.String("listen", "", "TCP host listener")
	peer := flag.String("peer", "", "TCP peer")
	udpPeer := flag.String("udp-peer", "", "UDP peer")
	ip := flag.String("ipv4", "10.199.0.254/24", "overlay prefix")
	secure := flag.Bool("secure-mode", false, "Noise")
	flag.BoolVar(&c.DHCP, "dhcp", false, "DHCP")
	pool := flag.String("dhcp-subnet", "", "DHCP subnet")
	flag.StringVar(&c.UDP.Listen, "udp-listen", "", "UDP host listener")
	flag.StringVar(&c.UDP.STUN, "stun", "", "STUN host:port")
	flag.StringVar(&c.UDP.Advertise, "udp-advertise", "", "numeric mapped address")
	flag.BoolVar(&c.UDP.Punch, "udp-punch", false, "punch peers")
	flag.StringVar(&c.UDP.NAT, "udp-nat", "auto", "NAT hint")
	control := flag.String("control", "127.0.0.1:18080", "test control HTTP")
	flag.Parse()
	var err error
	if !c.DHCP {
		c.IPv4, err = netip.ParsePrefix(*ip)
		if err != nil {
			return err
		}
	}
	if *pool != "" {
		c.DHCPSubnet, err = netip.ParsePrefix(*pool)
		if err != nil {
			return err
		}
	}
	if *secure {
		c.Encryption = et.Noise
	}
	if *listen != "" {
		c.Listeners = []string{"tcp://" + *listen}
	}
	if *peer != "" {
		c.Peers = append(c.Peers, "tcp://"+*peer)
	}
	if *udpPeer != "" {
		c.Peers = append(c.Peers, "udp://"+*udpPeer)
	}
	c.Logf = func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	s, err := et.New(c)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = s.Start(); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		ip, ready := s.IPv4()
		fmt.Fprintf(w, "ip=%s ready=%v\n", ip, ready)
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if e := traffic.Probe(ctx, s.Dial, r.URL.Query().Get("target")); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		fmt.Fprintln(w, "PASS TCP UDP")
	})
	ctl, err := net.Listen("tcp", *control)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	defer httpServer.Close()
	go httpServer.Serve(ctl)
	if err = s.Up(ctx); err != nil {
		return err
	}
	l, err := s.Listen("tcp", ":18081")
	if err != nil {
		return err
	}
	go traffic.ServeTCP(l)
	p, err := s.ListenPacket("udp", ":18081")
	if err != nil {
		return err
	}
	go traffic.ServeUDP(p)
	<-ctx.Done()
	return nil
}
