package peerconn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/route"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/proto"
)

type Node struct {
	ID      uint32
	Routes  *route.Table
	Deliver func(context.Context, wire.Packet) error
	// Log reports connection and packet errors; configure before starting the node.
	Log                               func(string, ...any)
	mu                                sync.RWMutex
	peers                             map[uint32]*Conn
	config                            *Config
	topo                              *topology
	links                             map[*Conn]*routeLink
	relay                             map[uint32]*relayAttempt
	udp                               *udpService
	calls                             map[int64]*rpcCall
	tx                                atomic.Int64
	received, sent, forwarded, syncOK atomic.Uint64
}
type routeLink struct {
	session uint64
	merger  rpcMerger
	pending map[int64]time.Time
	syncMu  sync.Mutex
}
type NodeStats struct {
	Received, Sent, Forwarded, RouteSyncOK uint64
	Peers, Routes                          int
}

func NewNode(id uint32, deliver func(context.Context, wire.Packet) error) (*Node, error) {
	if id == 0 || deliver == nil {
		return nil, errors.New("node ID and deliver callback required")
	}
	return &Node{ID: id, Routes: new(route.Table), Deliver: deliver, peers: make(map[uint32]*Conn), topo: newTopology(id), links: make(map[*Conn]*routeLink), relay: make(map[uint32]*relayAttempt), calls: make(map[int64]*rpcCall)}, nil
}
func (n *Node) Stats() NodeStats {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return NodeStats{n.received.Load(), n.sent.Load(), n.forwarded.Load(), n.syncOK.Load(), len(n.peers), len(n.Routes.Entries())}
}
func (n *Node) log(format string, args ...any) {
	if n.Log != nil {
		n.Log(format, args...)
	}
}
func (n *Node) SetIPv4(prefix netip.Prefix) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return errors.New("valid IPv4 prefix required")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	info := n.topo.infos[n.ID]
	b := prefix.Addr().As4()
	info.Ipv4Addr = &pb.Ipv4Addr{Addr: binary.BigEndian.Uint32(b[:])}
	info.NetworkLength = uint32(prefix.Bits())
	info.Version++
	return nil
}
func (n *Node) Configure(config Config) error {
	if err := config.validate(); err != nil {
		return err
	}
	if config.PeerID != n.ID {
		return errors.New("node peer ID mismatch")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.config != nil {
		if n.config.NetworkName != config.NetworkName || n.config.NetworkSecret != config.NetworkSecret || n.config.Security != config.Security {
			return errors.New("node identity cannot change")
		}
		return nil
	}
	n.config = &config
	if config.Security != nil {
		n.topo.infos[n.ID].NoiseStaticPubkey = config.Security.PublicKey()
	}
	return nil
}
func (n *Node) rebuildLocked() {
	n.Routes.Replace(n.topo.rebuild(n.ID, n.peers))
}
func (n *Node) AddConn(c *Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	old := n.peers[c.remoteID]
	if old != nil && old.isUDP() == c.isUDP() {
		old.Close()
	}
	if old == nil || c.isUDP() || !old.isUDP() {
		n.peers[c.remoteID] = c
	}
	link := n.links[old]
	if link == nil {
		link = &routeLink{session: randomID(), merger: make(rpcMerger), pending: make(map[int64]time.Time)}
	}
	n.links[c] = link
	n.topo.localLinks(n.ID, n.peers)
	n.rebuildLocked()
}
func (n *Node) remove(c *Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.links, c)
	if n.peers[c.remoteID] != c {
		return
	}
	delete(n.peers, c.remoteID)
	for other := range n.links {
		if other.remoteID == c.remoteID {
			n.peers[c.remoteID] = other
			break
		}
	}
	n.topo.localLinks(n.ID, n.peers)
	n.rebuildLocked()
}
func (n *Node) Dial(ctx context.Context, address, name, secret string, security *Security) (*Conn, error) {
	cfg := Config{PeerID: n.ID, NetworkName: name, NetworkSecret: secret, Timeout: 5 * time.Second, Security: security}
	n.mu.RLock()
	if n.config != nil {
		cfg.HostNetwork = n.config.HostNetwork
		cfg.Timeout = n.config.Timeout
	}
	n.mu.RUnlock()
	if err := n.Configure(cfg); err != nil {
		return nil, err
	}
	c, err := Dial(ctx, address, cfg)
	if err != nil {
		return nil, err
	}
	n.AddConn(c)
	return c, nil
}

// RunConn owns routing sync and the connection until it closes.
func (n *Node) RunConn(ctx context.Context, c *Conn) error {
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			if err := n.syncRoute(runCtx, c); err != nil {
				if runCtx.Err() == nil {
					n.log("route sync send: %v", err)
				}
				c.Close()
				return
			}
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	err := c.run(runCtx, time.Second, n.handle)
	cancel()
	c.Close()
	<-done
	n.remove(c)
	return err
}
func (n *Node) Connect(ctx context.Context, address, name, secret string, security *Security) error {
	for {
		c, err := n.Dial(ctx, address, name, secret, security)
		if err == nil {
			n.log("connected peer=%d address=%s", c.remoteID, address)
			err = n.RunConn(ctx, c)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n.log("connection %s: %v; retry in 1s", address, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (n *Node) Serve(ctx context.Context, l *Listener) error {
	if err := n.Configure(l.config); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return err
			}
			n.log("accept: %v", err)
			continue
		}
		n.AddConn(c)
		n.log("accepted peer=%d", c.remoteID)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.RunConn(ctx, c); err != nil && ctx.Err() == nil {
				n.log("peer=%d: %v", c.remoteID, err)
			}
		}()
	}
}
func (n *Node) nextHop(dst uint32) (*Conn, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if c := n.peers[dst]; c != nil {
		return c, nil
	}
	if c := n.peers[n.topo.hops[dst]]; c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("no next hop to peer %d", dst)
}
func (n *Node) SendIP(ctx context.Context, dst netip.Addr, payload []byte) error {
	actual, err := packetDestination(payload)
	if err != nil {
		return err
	}
	if actual != dst {
		return errors.New("destination differs from IP header")
	}
	entry, ok := n.Routes.Lookup(dst)
	if !ok {
		return fmt.Errorf("no route for %s", dst)
	}
	p := wire.NewData(n.ID, entry.PeerID, append([]byte(nil), payload...))
	c, err := n.nextHop(entry.PeerID)
	if err != nil {
		return err
	}
	n.mu.RLock()
	cfg := n.config
	n.mu.RUnlock()
	if cfg == nil {
		return errors.New("node not configured")
	}
	if cfg.Security != nil {
		session, err := n.ensureRelay(ctx, entry.PeerID)
		if err != nil {
			return err
		}
		if err = session.Encrypt(&p); err != nil {
			return err
		}
	} else if err = c.cipher.Encrypt(&p); err != nil {
		return err
	}
	if err = c.write(ctx, p); err == nil {
		n.sent.Add(1)
	}
	return err
}
func packetDestination(b []byte) (netip.Addr, error) {
	if len(b) >= 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&15) * 4
		if ihl < 20 || ihl > len(b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			return netip.Addr{}, errors.New("invalid IPv4 length")
		}
		return netip.AddrFrom4([4]byte(b[16:20])), nil
	}
	if len(b) >= 40 && b[0]>>4 == 6 && int(binary.BigEndian.Uint16(b[4:6]))+40 == len(b) {
		return netip.AddrFrom16([16]byte(b[24:40])), nil
	}
	return netip.Addr{}, errors.New("invalid IP packet")
}
func (n *Node) forward(ctx context.Context, p wire.Packet) error {
	c, err := n.nextHop(p.Header.ToPeerID)
	if err != nil {
		return err
	}
	if err = c.SendRaw(ctx, p); err == nil {
		n.forwarded.Add(1)
	}
	return err
}
func (n *Node) handle(ctx context.Context, c *Conn, p wire.Packet) error {
	if p.Header.ToPeerID != n.ID {
		if err := n.forward(ctx, p); err != nil {
			n.log("drop relay: %v", err)
		}
		return nil
	}
	if p.Header.PacketType == wire.PacketRelayHandshake || p.Header.PacketType == wire.PacketRelayHandshakeAck {
		if err := n.handleRelay(ctx, p); err != nil {
			n.log("drop relay handshake: %v", err)
		}
		return nil
	}
	if c.security != nil {
		session := c.security.Sessions.get(p.Header.FromPeerID)
		if session == nil {
			return errors.New("no end-to-end session")
		}
		if err := session.Decrypt(&p); err != nil {
			n.log("drop secure packet: %v", err)
			return nil
		}
	} else if p.Header.Flags&wire.FlagEncrypted != 0 {
		if err := c.cipher.Decrypt(&p); err != nil {
			return err
		}
	} else if p.Header.PacketType == wire.PacketData {
		return errors.New("unencrypted Data")
	}
	if err := decompressData(&p); err != nil {
		return err
	}
	switch p.Header.PacketType {
	case wire.PacketRPCRequest, wire.PacketRPCResponse:
		return n.handleRPC(ctx, c, p)
	case wire.PacketData:
		if _, err := packetDestination(p.Payload); err != nil {
			return err
		}
		n.received.Add(1)
		return n.Deliver(ctx, p)
	}
	return nil
}

func (n *Node) syncRoute(ctx context.Context, c *Conn) error {
	n.mu.RLock()
	link := n.links[c]
	if n.peers[c.remoteID] != c {
		n.mu.RUnlock()
		return nil
	}
	req := n.topo.snapshot(n.ID, link.session)
	network := n.config.NetworkName
	n.mu.RUnlock()
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	envelope, err := proto.Marshal(&pb.RpcRequest{Request: body, TimeoutMs: 3000})
	if err != nil {
		return err
	}
	id := n.tx.Add(1)
	link.syncMu.Lock()
	for tid, at := range link.pending {
		if time.Since(at) > 10*time.Second {
			delete(link.pending, tid)
		}
	}
	link.pending[id] = time.Now()
	link.syncMu.Unlock()
	packets, err := rpcPackets(n.ID, c.remoteID, id, true, routeDescriptor(network), envelope)
	if err != nil {
		return err
	}
	for _, p := range packets {
		if err = c.sendRPC(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) handleRPC(ctx context.Context, c *Conn, p wire.Packet) error {
	n.mu.RLock()
	link := n.links[c]
	network := n.config.NetworkName
	n.mu.RUnlock()
	link.syncMu.Lock()
	r, err := link.merger.feed(p)
	link.syncMu.Unlock()
	if err != nil || r == nil {
		return err
	}
	if r.IsRequest && n.handleUDPRPC(ctx, r) {
		return nil
	}
	if !r.IsRequest && n.completeCall(r) {
		return nil
	}
	if r.IsRequest {
		var body []byte
		req, err := routeRequest(r, network)
		if err != nil {
			body = mustProto(&pb.RpcResponse{Error: &pb.Error{ErrorKind: &pb.Error_InvalidService{InvalidService: &pb.InvalidService{ServiceName: r.Descriptor_.GetServiceName()}}}})
		} else {
			n.mu.Lock()
			err = n.topo.merge(n.ID, req)
			n.rebuildLocked()
			session := link.session
			n.mu.Unlock()
			if err != nil {
				return err
			}
			body, err = proto.Marshal(&pb.RpcResponse{Response: mustProto(&pb.SyncRouteInfoResponse{IsInitiator: true, SessionId: session})})
			if err != nil {
				return err
			}
		}
		packets, err := rpcPackets(n.ID, c.remoteID, r.TransactionId, false, r.Descriptor_, body)
		if err != nil {
			return err
		}
		for _, out := range packets {
			if err = c.sendRPC(ctx, out); err != nil {
				return err
			}
		}
		return nil
	}
	link.syncMu.Lock()
	_, pending := link.pending[r.TransactionId]
	delete(link.pending, r.TransactionId)
	link.syncMu.Unlock()
	if !pending || r.FromPeer != c.remoteID || !proto.Equal(r.Descriptor_, routeDescriptor(network)) {
		return nil
	}
	var response pb.RpcResponse
	if err = proto.Unmarshal(r.Body, &response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("route RPC: %v", response.Error)
	}
	var routeResponse pb.SyncRouteInfoResponse
	if err = proto.Unmarshal(response.Response, &routeResponse); err != nil {
		return err
	}
	if routeResponse.Error != nil {
		return fmt.Errorf("route sync: %v", *routeResponse.Error)
	}
	n.syncOK.Add(1)
	return nil
}

func mustProto(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// SetHostname advertises the overlay name in route synchronization.
func (n *Node) SetHostname(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	info := n.topo.infos[n.ID]
	info.Hostname = &name
	info.Version++
}

// LookupHostname returns addresses only for this node and reachable peers.
// The count includes peers without addresses so duplicate names stay ambiguous.
func (n *Node) LookupHostname(name string) ([]netip.Addr, int) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var addrs []netip.Addr
	count := 0
	normalize := func(s string) string {
		return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(s), "."), ".et.net")
	}
	for id, info := range n.topo.infos {
		if id != n.ID && n.topo.hops[id] == 0 {
			continue
		}
		if normalize(info.GetHostname()) != normalize(name) {
			continue
		}
		count++
		if info.Ipv4Addr != nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], info.Ipv4Addr.Addr)
			addrs = append(addrs, netip.AddrFrom4(b))
		}
	}
	return addrs, count
}
