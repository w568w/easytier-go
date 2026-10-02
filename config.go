// Package easytier embeds an EasyTier virtual IPv4 network.
package easytier

import (
	"errors"
	"net/netip"
	"time"

	"github.com/easytier/easytier-go/internal/hostnet"
)

// HostNetwork owns all underlay sockets and DNS. Implementations must honor
// contexts and Close, and support concurrent calls. Errors never fall back to
// the system network. Returned objects need only implement standard interfaces.
type HostNetwork = hostnet.Network

type Encryption string

const (
	Legacy Encryption = "legacy" // EasyTier shared-secret AES-GCM.
	Noise  Encryption = "noise"  // EasyTier Noise identity and session encryption.
)

type UDPConfig struct {
	Listen    string // Host IP:port; empty disables UDP unless a udp:// peer is configured.
	Advertise string // Numeric mapped IP:port, as an alternative to STUN.
	STUN      string // Hostname:port, resolved through HostNetwork.
	Punch     bool
	NAT       string // auto, symmetric, incremental, or decremental.
}

type Config struct {
	NetworkName   string
	NetworkSecret string
	Hostname      string
	IPv4          netip.Prefix
	DHCP          bool
	DHCPSubnet    netip.Prefix // Invalid means learn the subnet from peers.
	Peers         []string     // tcp://host:port or udp://host:port; reconnected until Close.
	Listeners     []string     // tcp://host:port; UDP uses UDP.Listen.
	UDP           UDPConfig
	Encryption    Encryption    // Empty selects Legacy.
	PrivateKey    []byte        // Optional 32-byte X25519 key; the application persists it.
	PeerID        uint32        // Zero generates a fresh ID.
	Timeout       time.Duration // Underlay connection/handshake timeout; default 5s.
	Logf          func(string, ...any)
	HostNetwork   HostNetwork
}

var (
	ErrNotReady       = errors.New("easytier: virtual address not ready")
	ErrClosed         = errors.New("easytier: server closed")
	ErrNameNotFound   = errors.New("easytier: node name not found")
	ErrAmbiguousName  = errors.New("easytier: ambiguous node name")
	ErrAddressChanged = errors.New("easytier: virtual address changed")
)
