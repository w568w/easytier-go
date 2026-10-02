//go:build upstream

package easytier

import (
	"net/netip"
	"testing"
)

// EasyTier v2.6.4 peers/peer_ospf_route.rs::test_connect_at_different_time.
func TestUpstreamLatePeerJoin(t *testing.T) {
	for _, mode := range []Encryption{Legacy, Noise} {
		t.Run(string(mode), func(t *testing.T) {
			a := makeServer(t, Config{NetworkName: "late-join", NetworkSecret: "secret", Hostname: "a", IPv4: netip.MustParsePrefix("10.93.0.1/24"), Encryption: mode, Listeners: []string{"tcp://127.0.0.1:0"}})
			b := makeServer(t, Config{NetworkName: "late-join", NetworkSecret: "secret", Hostname: "b", IPv4: netip.MustParsePrefix("10.93.0.2/24"), Encryption: mode, Listeners: []string{"tcp://127.0.0.1:0"}, Peers: []string{"tcp://" + a.listeners[0].Addr().String()}})
			waitName(t, a, "b")
			waitName(t, b, "a")
			c := makeServer(t, Config{NetworkName: "late-join", NetworkSecret: "secret", Hostname: "c", IPv4: netip.MustParsePrefix("10.93.0.3/24"), Encryption: mode, Peers: []string{"tcp://" + b.listeners[0].Addr().String()}})
			waitName(t, a, "c")
			waitName(t, c, "a")
			la := tcpEcho(t, a, ":0")
			lc := tcpEcho(t, c, ":0")
			checkTCP(t, a, serviceAddr(c, lc.Addr()))
			checkTCP(t, c, serviceAddr(a, la.Addr()))
		})
	}
}
