// Package hostnet defines the underlay services supplied by an embedding host.
package hostnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

type Network interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Listen(context.Context, string, string) (net.Listener, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
	LookupIP(context.Context, string, string) ([]netip.Addr, error)
}

// System uses ordinary Go sockets. A custom Network replaces it in full.
type System struct{}

func (System) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
func (System) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var l net.ListenConfig
	return l.Listen(ctx, network, address)
}
func (System) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var l net.ListenConfig
	return l.ListenPacket(ctx, network, address)
}
func (System) LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
func OrSystem(n Network) Network {
	if n == nil {
		return System{}
	}
	return n
}

// Resolve resolves through the injected resolver and returns a numeric endpoint.
func Resolve(ctx context.Context, n Network, network, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	family := "ip"
	if network == "tcp4" || network == "udp4" {
		family = "ip4"
	}
	if network == "tcp6" || network == "udp6" {
		family = "ip6"
	}
	ips, err := n.LookupIP(ctx, family, host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.IsValid() && (family != "ip4" || ip.Is4()) && (family != "ip6" || ip.Is6()) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", fmt.Errorf("host %q has no %s address", host, family)
}
