package peerconn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/easytier/easytier-go/internal/hostnet"
	"github.com/easytier/easytier-go/internal/lifecycle"
	"net"
	"net/netip"
	"sync"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/proto"
)

type UDPConfig struct {
	Listen, Advertise, STUN string
	Punch                   bool
	NAT                     string
}
type udpService struct {
	endpoint  *transport.UDP
	cfg       Config
	options   UDPConfig
	mapped    string
	run       func(*Conn)
	mu        sync.RWMutex
	symMu     sync.Mutex
	ports     []uint16
	portIndex uint32
	jobMu     sync.Mutex
	jobs      sync.WaitGroup
	stopping  bool
	ctx       context.Context
}
type rpcCall struct {
	peer       uint32
	descriptor *pb.RpcDescriptor
	response   chan *pb.RpcResponse
}

func (c *Conn) isUDP() bool { _, ok := c.socket.(*transport.DatagramConn); return ok }
func (n *Node) LocalUDPAddr() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.udp == nil {
		return ""
	}
	return n.udp.endpoint.Addr().String()
}

// RunUDP owns the socket and accepts UDP PeerConns. Advertise is an explicit
// mapped address when STUN is unavailable; the two options are alternatives.
func (n *Node) RunUDP(ctx context.Context, options UDPConfig, cfg Config) error {
	return n.RunUDPReady(ctx, options, cfg, nil)
}

// RunUDPReady reports initialization once before serving connections.
func (n *Node) RunUDPReady(ctx context.Context, options UDPConfig, cfg Config, ready chan<- error) (retErr error) {
	defer func() {
		if ready != nil {
			ready <- retErr
		}
	}()
	if err := n.Configure(cfg); err != nil {
		return err
	}
	switch options.NAT {
	case "", "auto", "symmetric", "incremental", "decremental":
	default:
		return errors.New("invalid UDP NAT hint")
	}
	if options.STUN != "" && options.Advertise != "" {
		return errors.New("use STUN or advertise, not both")
	}
	endpoint, err := transport.ListenUDPWithHost(ctx, cfg.HostNetwork, options.Listen)
	if err != nil {
		return err
	}
	defer endpoint.Close()
	stop := lifecycle.OnCancel(ctx, func() { endpoint.Close() })
	defer stop()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &udpService{endpoint: endpoint, cfg: cfg, options: options, ctx: runCtx}
	n.mu.Lock()
	if n.udp != nil {
		n.mu.Unlock()
		return errors.New("UDP already running")
	}
	n.udp = s
	info := n.topo.infos[n.ID]
	switch options.NAT {
	case "symmetric":
		info.UdpNatType = pb.NatType_Symmetric
	case "incremental":
		info.UdpNatType = pb.NatType_SymmetricEasyInc
	case "decremental":
		info.UdpNatType = pb.NatType_SymmetricEasyDec
	}
	info.Version++
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.udp = nil; n.mu.Unlock() }()
	s.run = func(c *Conn) {
		if !s.spawn(func() { _ = n.RunConn(runCtx, c) }) {
			c.Close()
		}
	}
	defer func() {
		s.jobMu.Lock()
		s.stopping = true
		s.jobMu.Unlock()
		cancel()
		endpoint.Close()
		s.jobs.Wait()
	}()
	if ready != nil {
		ready <- nil
		ready = nil
	}
	s.spawn(func() { n.punchLoop(runCtx, s) })
	for {
		socket, err := endpoint.Accept(runCtx)
		if err != nil {
			return err
		}
		s.spawn(func() {
			stop := lifecycle.OnCancel(runCtx, func() { socket.Close() })
			defer stop()
			c, err := newConn(socket, cfg)
			if err == nil {
				err = c.acceptHandshake(cfg)
			}
			if err != nil {
				socket.Close()
				n.log("UDP handshake: %v", err)
				return
			}
			n.AddConn(c)
			n.log("UDP accepted peer=%d", c.remoteID)
			_ = n.RunConn(runCtx, c)
		})
	}
}
func (n *Node) dialUDP(ctx context.Context, s *udpService, address string, expected uint32) (*Conn, error) {
	return n.dialUDPSocket(ctx, s, s.endpoint, address, expected)
}
func (n *Node) dialUDPSocket(ctx context.Context, s *udpService, endpoint *transport.UDP, address string, expected uint32) (*Conn, error) {
	attempt, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	address, err := hostnet.Resolve(attempt, hostnet.OrSystem(s.cfg.HostNetwork), "udp4", address)
	if err != nil {
		return nil, err
	}
	socket, err := endpoint.Dial(attempt, address)
	if err != nil {
		return nil, fmt.Errorf("SYN/SACK: %w", err)
	}
	stop := lifecycle.OnCancel(attempt, func() { socket.Close() })
	defer stop()
	c, err := newConn(socket, s.cfg)
	if err == nil {
		err = c.handshake(s.cfg)
		if err != nil {
			err = fmt.Errorf("PeerConn handshake: %w", err)
		}
	}
	if err == nil && expected != 0 && expected != c.remoteID {
		err = errors.New("UDP peer identity mismatch")
	}
	if err != nil {
		socket.Close()
		return nil, err
	}
	n.AddConn(c)
	n.log("UDP connected peer=%d address=%s", c.remoteID, address)
	return c, nil
}
func (n *Node) ConnectUDP(ctx context.Context, address string) error {
	for {
		n.mu.RLock()
		s := n.udp
		n.mu.RUnlock()
		if s != nil {
			c, err := n.dialUDP(ctx, s, address, 0)
			if err == nil {
				err = n.RunConn(ctx, c)
			}
			if ctx.Err() == nil {
				n.log("UDP connection: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (s *udpService) mapping(ctx context.Context) (string, error) {
	if s.options.Advertise != "" {
		addr, err := numericUDPAddr(s.options.Advertise)
		if err != nil {
			return "", err
		}
		if addr.Port == 0 || addr.IP.IsUnspecified() {
			return "", errors.New("advertise requires concrete IP:port")
		}
		return addr.String(), nil
	}
	if s.options.STUN != "" {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return s.endpoint.MappedAddress(c, s.options.STUN)
	}
	addr, err := numericUDPAddr(s.endpoint.Addr().String())
	if err != nil {
		return "", err
	}
	if addr.IP.IsUnspecified() {
		return "", errors.New("punching needs STUN, advertise, or concrete listen IP")
	}
	return addr.String(), nil
}
func (n *Node) punchLoop(ctx context.Context, s *udpService) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		mapped, err := s.mapping(ctx)
		if err == nil {
			s.mu.Lock()
			s.mapped = mapped
			s.mu.Unlock()
		}
		if err != nil && s.options.Punch {
			n.log("UDP mapping: %v", err)
		}
		if err == nil && s.options.Punch {
			n.mu.RLock()
			var targets []uint32
			for id := range n.topo.hops {
				if id != n.ID && (n.peers[id] == nil || !n.peers[id].isUDP()) {
					targets = append(targets, id)
				}
			}
			n.mu.RUnlock()
			for _, id := range targets {
				if ctx.Err() != nil {
					return
				}
				c, err := n.punchPeer(ctx, s, id, mapped)
				if err != nil && ctx.Err() == nil {
					c, err = n.punchSymmetric(ctx, s, id)
				}
				if err != nil {
					n.log("UDP punch peer=%d: %v (relay retained)", id, err)
					continue
				}
				s.run(c)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (n *Node) punchPeer(ctx context.Context, s *udpService, peer uint32, local string) (*Conn, error) {
	var selected pb.SelectPunchListenerResponse
	if err := n.callRPC(ctx, peer, "UdpHolePunchRpc", 1, &pb.SelectPunchListenerRequest{}, &selected); err != nil {
		return nil, fmt.Errorf("select listener: %w", err)
	}
	remote, err := socketString(selected.ListenerMappedAddr)
	n.log("UDP punch mapping local=%s remote=%s", local, remote)
	if err != nil {
		return nil, err
	}
	destination, err := socketProto(local)
	if err != nil {
		return nil, err
	}
	tid := uint32(randomID())
	punchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.endpoint.Punch(punchCtx, remote, tid, 10, 100*time.Millisecond) }()
	var response pb.Void
	err = n.callRPC(punchCtx, peer, "UdpHolePunchRpc", 2, &pb.SendPunchPacketConeRequest{ListenerMappedAddr: selected.ListenerMappedAddr, DestAddr: destination, TransactionId: tid, PacketCountPerBatch: 2, PacketBatchCount: 5, PacketIntervalMs: 100}, &response)
	if err != nil {
		cancel()
		<-done
		return nil, err
	}
	if err = <-done; err != nil {
		return nil, err
	}
	c, e := n.dialUDP(ctx, s, remote, peer)
	if e != nil {
		return nil, fmt.Errorf("UDP dial: %w", e)
	}
	return c, nil
}
func socketProto(address string) (*pb.SocketAddr, error) {
	a, err := numericUDPAddr(address)
	if err != nil {
		return nil, err
	}
	v4 := a.IP.To4()
	if v4 == nil || a.Port == 0 {
		return nil, errors.New("IPv4 UDP endpoint required")
	}
	return &pb.SocketAddr{Ip: &pb.SocketAddr_Ipv4{Ipv4: &pb.Ipv4Addr{Addr: binary.BigEndian.Uint32(v4)}}, Port: uint32(a.Port)}, nil
}
func socketString(a *pb.SocketAddr) (string, error) {
	if a == nil || a.Ip == nil || a.GetIpv4() == nil || a.Port == 0 || a.Port > 65535 {
		return "", errors.New("invalid IPv4 endpoint")
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, a.GetIpv4().Addr)
	if ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("invalid punch destination")
	}
	return (&net.UDPAddr{IP: ip, Port: int(a.Port)}).String(), nil
}
func (n *Node) sendControl(ctx context.Context, peer uint32, packet wire.Packet) error {
	c, err := n.nextHop(peer)
	if err != nil {
		return err
	}
	n.mu.RLock()
	secure := n.config.Security != nil
	n.mu.RUnlock()
	if secure {
		session, err := n.ensureRelay(ctx, peer)
		if err != nil {
			return err
		}
		if err = session.Encrypt(&packet); err != nil {
			return err
		}
	}
	return c.write(ctx, packet)
}
func (n *Node) callRPC(ctx context.Context, peer uint32, service string, method uint32, input, output proto.Message) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n.mu.Lock()
	network := n.config.NetworkName
	if len(n.calls) >= 32 {
		n.mu.Unlock()
		return errors.New("too many pending RPCs")
	}
	id := n.tx.Add(1)
	desc := &pb.RpcDescriptor{DomainName: network, ProtoName: service, ServiceName: service, MethodIndex: method}
	call := &rpcCall{peer: peer, descriptor: desc, response: make(chan *pb.RpcResponse, 1)}
	n.calls[id] = call
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.calls, id); n.mu.Unlock() }()
	body, err := proto.Marshal(input)
	if err != nil {
		return err
	}
	envelope, err := proto.Marshal(&pb.RpcRequest{Request: body, TimeoutMs: 4000})
	if err != nil {
		return err
	}
	packets, err := rpcPackets(n.ID, peer, id, true, desc, envelope)
	if err != nil {
		return err
	}
	for _, p := range packets {
		if err = n.sendControl(ctx, peer, p); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case response := <-call.response:
		if response.Error != nil {
			return fmt.Errorf("%s: %v", service, response.Error)
		}
		return proto.Unmarshal(response.Response, output)
	}
}
func (n *Node) completeCall(r *pb.RpcPacket) bool {
	n.mu.RLock()
	call := n.calls[r.TransactionId]
	n.mu.RUnlock()
	if call == nil {
		return false
	}
	if call.peer != r.FromPeer || !proto.Equal(call.descriptor, r.Descriptor_) {
		n.log("RPC mismatch expected=%v received=%v peer=%d", call.descriptor, r.Descriptor_, r.FromPeer)
		return true
	}
	var response pb.RpcResponse
	if err := proto.Unmarshal(r.Body, &response); err != nil {
		return true
	}
	select {
	case call.response <- &response:
	default:
	}
	return true
}
func (n *Node) handleUDPRPC(ctx context.Context, r *pb.RpcPacket) bool {
	d := r.Descriptor_
	if d == nil || d.ServiceName != "UdpHolePunchRpc" {
		return false
	}
	n.mu.RLock()
	s := n.udp
	network := n.config.NetworkName
	n.mu.RUnlock()
	if s == nil || d.DomainName != network {
		return false
	}
	var req pb.RpcRequest
	if proto.Unmarshal(r.Body, &req) != nil {
		return false
	}
	var out proto.Message
	var err error
	switch d.MethodIndex {
	case 1:
		s.mu.RLock()
		mapped := s.mapped
		s.mu.RUnlock()
		var addr *pb.SocketAddr
		addr, err = socketProto(mapped)
		out = &pb.SelectPunchListenerResponse{ListenerMappedAddr: addr}
	case 2:
		var punch pb.SendPunchPacketConeRequest
		err = proto.Unmarshal(req.Request, &punch)
		if err == nil {
			var dest string
			dest, err = socketString(punch.DestAddr)
			if err == nil {
				count := uint64(punch.PacketCountPerBatch) * uint64(punch.PacketBatchCount)
				interval := time.Duration(punch.PacketIntervalMs) * time.Millisecond
				if count < 1 || count > 20 || interval < 10*time.Millisecond || interval > time.Second {
					err = errors.New("invalid punch rate")
				} else {
					s.spawn(func() { _ = s.endpoint.Punch(s.ctx, dest, punch.TransactionId, int(count), interval) })
				}
			}
		}
		out = &pb.Void{}
	case 3, 4, 5:
		out, err = n.symmetricRPC(s, d.MethodIndex, req.Request)
	default:
		err = errors.New("unknown UDP punch method")
	}
	response := &pb.RpcResponse{}
	if err != nil {
		response.Error = &pb.Error{ErrorKind: &pb.Error_ExecuteError{ExecuteError: &pb.ExecuteError{ErrorMessage: err.Error()}}}
	} else {
		response.Response = mustProto(out)
	}
	packets, e := rpcPackets(n.ID, r.FromPeer, r.TransactionId, false, d, mustProto(response))
	if e == nil {
		for _, p := range packets {
			if e = n.sendControl(ctx, r.FromPeer, p); e != nil {
				break
			}
		}
	}
	if e != nil {
		n.log("UDP RPC response: %v", e)
	}
	return true
}

func numericUDPAddr(address string) (*net.UDPAddr, error) {
	a, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(a), nil
}
