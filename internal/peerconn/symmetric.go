package peerconn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/easytier/easytier-go/internal/hostnet"
	"github.com/easytier/easytier-go/internal/lifecycle"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"google.golang.org/protobuf/proto"
)

func (s *udpService) spawn(fn func()) bool {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.stopping {
		return false
	}
	s.jobs.Add(1)
	go func() { defer s.jobs.Done(); fn() }()
	return true
}
func predictedPorts(base, span uint32, increasing bool) ([]uint16, error) {
	if base == 0 || base > 65535 || span < 2 || span > 256 {
		return nil, errors.New("invalid prediction range")
	}
	start, end := int(base)+1, int(base)+int(span)
	if !increasing {
		start, end = int(base)-int(span), int(base)-1
	}
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if start > end {
		return nil, errors.New("prediction exceeds port range")
	}
	out := make([]uint16, 0, end-start+1)
	for p := start; p <= end; p++ {
		out = append(out, uint16(p))
	}
	return out, nil
}
func shuffledPorts() ([]uint16, error) {
	ports := make([]uint16, 65535)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	for i := len(ports) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		ports[i], ports[j.Int64()] = ports[j.Int64()], ports[i]
	}
	return ports, nil
}
func publicIPs(ips []*pb.Ipv4Addr) ([]string, error) {
	if len(ips) == 0 || len(ips) > 4 {
		return nil, errors.New("one to four public IPv4 addresses required")
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			return nil, errors.New("missing public IP")
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], ip.Addr)
		v := net.IP(b[:])
		if v.IsUnspecified() || v.IsMulticast() {
			return nil, errors.New("invalid public IP")
		}
		out = append(out, v.String())
	}
	return out, nil
}
func sweep(ctx context.Context, u *transport.UDP, ips []string, ports []uint16, tid uint32) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for repeat := 0; repeat < 2; repeat++ {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
			for _, ip := range ips {
				for j := 0; j < 3; j++ {
					if err := u.Probe(net.JoinHostPort(ip, strconv.Itoa(int(port))), tid); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func (s *udpService) listenerMatches(p *pb.SocketAddr) bool {
	a, e := socketString(p)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return e == nil && a == s.mapped
}
func (n *Node) symmetricRPC(s *udpService, method uint32, body []byte) (proto.Message, error) {
	if !s.symMu.TryLock() {
		if method == 5 {
			return &pb.SendPunchPacketBothEasySymResponse{IsBusy: true}, nil
		}
		return nil, errors.New("symmetric punch busy")
	}
	if method == 5 {
		out, err := n.bothServer(s, body)
		if err != nil {
			s.symMu.Unlock()
		}
		return out, err
	}
	defer s.symMu.Unlock()
	var ips []string
	var ports []uint16
	var tid uint32
	var err error
	next := uint32(0)
	if method == 4 {
		var req pb.SendPunchPacketEasySymRequest
		if err = proto.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		if !s.listenerMatches(req.ListenerMappedAddr) {
			return nil, errors.New("unknown punch listener")
		}
		ips, err = publicIPs(req.PublicIps)
		if err != nil {
			return nil, err
		}
		ports, err = predictedPorts(req.BasePortNum, req.MaxPortNum, req.IsIncremental)
		tid = req.TransactionId
	} else {
		var req pb.SendPunchPacketHardSymRequest
		if err = proto.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		if !s.listenerMatches(req.ListenerMappedAddr) {
			return nil, errors.New("unknown punch listener")
		}
		ips, err = publicIPs(req.PublicIps)
		if err != nil {
			return nil, err
		}
		if s.ports == nil {
			s.ports, err = shuffledPorts()
			if err != nil {
				return nil, err
			}
		}
		count := uint32(700)
		if req.Round > 2 {
			count = 1400 / req.Round
			if count < 180 {
				count = 180
			}
		}
		for i := uint32(0); i < count; i++ {
			ports = append(ports, s.ports[(req.PortIndex+i)%65535])
		}
		next = (req.PortIndex + count) % 65535
		tid = req.TransactionId
	}
	if err != nil {
		return nil, err
	}
	if err = sweep(s.ctx, s.endpoint, ips, ports, tid); err != nil {
		return nil, err
	}
	if method == 3 {
		return &pb.SendPunchPacketHardSymResponse{NextPortIndex: next}, nil
	}
	return &pb.Void{}, nil
}

type punchHit struct {
	socket  *transport.UDP
	address string
}
type punchPool struct {
	sockets  []*transport.UDP
	hits     chan punchHit
	cancel   context.CancelFunc
	unwatch  []func()
	watchers sync.WaitGroup
}

func newPunchPoolWithHost(ctx context.Context, network hostnet.Network, listen string, count int, tid uint32) (*punchPool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if count < 1 || count > 84 {
		return nil, errors.New("invalid socket count")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &punchPool{hits: make(chan punchHit, 128), cancel: cancel}
	for i := 0; i < count; i++ {
		u, e := transport.ListenUDPWithHost(ctx, network, net.JoinHostPort(host, "0"))
		if e != nil {
			p.closeExcept(nil)
			return nil, e
		}
		p.sockets = append(p.sockets, u)
		ch, stop := u.WatchPunch(tid)
		p.unwatch = append(p.unwatch, stop)
		// Multiplex watchers into a bounded channel; every watcher exits on pctx.
		p.watchers.Add(1)
		go func() {
			defer p.watchers.Done()
			for {
				select {
				case <-pctx.Done():
					return
				case addr := <-ch:
					select {
					case p.hits <- punchHit{u, addr}:
					case <-pctx.Done():
						return
					}
				}
			}
		}()
	}
	return p, nil
}
func (p *punchPool) closeExcept(keep *transport.UDP) {
	p.cancel()
	p.watchers.Wait()
	for _, f := range p.unwatch {
		f()
	}
	for _, u := range p.sockets {
		if u != keep {
			u.Close()
		}
	}
}
func (p *punchPool) probe(addr string, tid uint32) error {
	for _, u := range p.sockets {
		if err := u.Probe(addr, tid); err != nil {
			return err
		}
	}
	return nil
}
func (n *Node) retainSocket(s *udpService, u *transport.UDP) {
	if !s.spawn(func() {
		defer u.Close()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if u.SessionCount() == 0 {
					return
				}
			}
		}
	}) {
		u.Close()
	}
}

// Try predicted sequential allocations first, then 84 sockets against shuffled
// remote port batches (birthday punching). All unsuccessful sockets are closed.
func (n *Node) punchSymmetric(ctx context.Context, s *udpService, peer uint32) (*Conn, error) {
	if s.options.STUN == "" {
		return nil, errors.New("symmetric punching requires STUN")
	}
	n.mu.RLock()
	remoteType := pb.NatType_Unknown
	if info := n.topo.infos[peer]; info != nil {
		remoteType = info.UdpNatType
	}
	n.mu.RUnlock()
	if remoteType == pb.NatType_SymmetricEasyInc || remoteType == pb.NatType_SymmetricEasyDec {
		return n.bothClient(ctx, s, peer, remoteType == pb.NatType_SymmetricEasyInc)
	}
	var response pb.SelectPunchListenerResponse
	if err := n.callRPC(ctx, peer, "UdpHolePunchRpc", 1, &pb.SelectPunchListenerRequest{}, &response); err != nil {
		return nil, err
	}
	remote, err := socketString(response.ListenerMappedAddr)
	if err != nil {
		return nil, err
	}
	// A fresh STUN socket samples the allocator immediately before the pool is used.
	local, err := sampleMapping(ctx, s)
	if err != nil {
		return nil, err
	}
	mapped, _ := socketString(local)
	ips := []*pb.Ipv4Addr{local.GetIpv4()}
	tid := uint32(randomID())
	pool, err := newPunchPoolWithHost(ctx, s.cfg.HostNetwork, s.options.Listen, 84, tid)
	if err != nil {
		return nil, err
	}
	var keep *transport.UDP
	defer func() { pool.closeExcept(keep) }()
	for attempt := 0; attempt < 6; attempt++ {
		attemptCtx, stop := context.WithTimeout(ctx, 4500*time.Millisecond)
		if err = pool.probe(remote, tid); err != nil {
			stop()
			return nil, err
		}
		done := make(chan error, 1)
		go func() {
			if attempt < 2 {
				var out pb.Void
				done <- n.callRPC(attemptCtx, peer, "UdpHolePunchRpc", 4, &pb.SendPunchPacketEasySymRequest{ListenerMappedAddr: response.ListenerMappedAddr, PublicIps: ips, TransactionId: tid, BasePortNum: local.Port, MaxPortNum: 128, IsIncremental: attempt == 0}, &out)
			} else {
				var out pb.SendPunchPacketHardSymResponse
				e := n.callRPC(attemptCtx, peer, "UdpHolePunchRpc", 3, &pb.SendPunchPacketHardSymRequest{ListenerMappedAddr: response.ListenerMappedAddr, PublicIps: ips, TransactionId: tid, Round: 1, PortIndex: s.portIndex}, &out)
				if e == nil {
					s.portIndex = out.NextPortIndex
				}
				done <- e
			}
		}()
		n.log("UDP symmetric peer=%d phase=%d base=%s", peer, attempt, mapped)
		c, u, e := n.awaitPool(attemptCtx, s, pool, remote, tid, peer)
		stop()
		<-done
		if e == nil {
			keep = u
			n.retainSocket(s, u)
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("symmetric punch attempts exhausted; relay retained")
}
func (n *Node) awaitPool(ctx context.Context, s *udpService, p *punchPool, remote string, tid, peer uint32) (*Conn, *transport.UDP, error) {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	target, _ := numericUDPAddr(remote)
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-ticker.C:
			if err := p.probe(remote, tid); err != nil {
				return nil, nil, err
			}
		case hit := <-p.hits:
			addr, e := numericUDPAddr(hit.address)
			if e != nil || !addr.IP.Equal(target.IP) {
				continue
			}
			n.log("UDP predicted probe received peer=%d source=%s", peer, hit.address)
			c, e := n.dialUDPSocket(ctx, s, hit.socket, hit.address, peer)
			if e == nil {
				return c, hit.socket, nil
			}
		}
	}
}

func portOffset(port uint32, increasing bool) (uint32, error) {
	if increasing {
		if port > 65515 {
			return 0, errors.New("predicted port overflows")
		}
		return port + 20, nil
	}
	if port <= 20 {
		return 0, errors.New("predicted port underflows")
	}
	return port - 20, nil
}
func sampleMapping(ctx context.Context, s *udpService) (*pb.SocketAddr, error) {
	if s.options.STUN == "" {
		return nil, errors.New("STUN is required for symmetric mapping")
	}
	u, err := transport.ListenUDPWithHost(ctx, s.cfg.HostNetwork, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	mapped, err := u.MappedAddress(ctx, s.options.STUN)
	if err != nil {
		return nil, err
	}
	return socketProto(mapped)
}
func (n *Node) bothClient(ctx context.Context, s *udpService, peer uint32, remoteIncreasing bool) (*Conn, error) {
	tid := uint32(randomID())
	pool, err := newPunchPoolWithHost(ctx, s.cfg.HostNetwork, s.options.Listen, 25, tid)
	if err != nil {
		return nil, err
	}
	var keep *transport.UDP
	defer func() { pool.closeExcept(keep) }()
	local, err := sampleMapping(ctx, s)
	if err != nil {
		return nil, err
	}
	port, err := portOffset(local.Port, s.options.NAT != "decremental")
	if err != nil {
		return nil, err
	}
	var rsp pb.SendPunchPacketBothEasySymResponse
	err = n.callRPC(ctx, peer, "UdpHolePunchRpc", 5, &pb.SendPunchPacketBothEasySymRequest{UdpSocketCount: 25, PublicIp: local.GetIpv4(), TransactionId: tid, DstPortNum: port, WaitTimeMs: 5000}, &rsp)
	if err != nil {
		return nil, err
	}
	if rsp.IsBusy {
		return nil, errors.New("remote symmetric punch busy")
	}
	if rsp.BaseMappedAddr == nil {
		return nil, errors.New("missing symmetric base mapping")
	}
	predicted := proto.Clone(rsp.BaseMappedAddr).(*pb.SocketAddr)
	predicted.Port, err = portOffset(predicted.Port, remoteIncreasing)
	if err != nil {
		return nil, err
	}
	remote, err := socketString(predicted)
	if err != nil {
		return nil, err
	}
	n.log("UDP both-symmetric peer=%d target=%s", peer, remote)
	attempt, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	c, u, err := n.awaitPool(attempt, s, pool, remote, tid, peer)
	if err != nil {
		return nil, err
	}
	keep = u
	n.retainSocket(s, u)
	return c, nil
}
func (n *Node) bothServer(s *udpService, body []byte) (proto.Message, error) {
	var req pb.SendPunchPacketBothEasySymRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.UdpSocketCount < 1 || req.UdpSocketCount > 84 || req.WaitTimeMs == 0 || req.WaitTimeMs > 8000 {
		return nil, errors.New("invalid both-symmetric limits")
	}
	destination := &pb.SocketAddr{Ip: &pb.SocketAddr_Ipv4{Ipv4: req.PublicIp}, Port: req.DstPortNum}
	target, err := socketString(destination)
	if err != nil {
		return nil, err
	}
	base, err := sampleMapping(s.ctx, s)
	if err != nil {
		return nil, err
	}
	pool, err := newPunchPoolWithHost(s.ctx, s.cfg.HostNetwork, s.options.Listen, int(req.UdpSocketCount), req.TransactionId)
	if err != nil {
		return nil, err
	}
	if !s.spawn(func() {
		defer s.symMu.Unlock()
		var keep *transport.UDP
		defer func() { pool.closeExcept(keep) }()
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(req.WaitTimeMs)*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		_ = pool.probe(target, req.TransactionId)
		expected, _ := numericUDPAddr(target)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = pool.probe(target, req.TransactionId)
			case hit := <-pool.hits:
				source, e := numericUDPAddr(hit.address)
				if e != nil || !source.IP.Equal(expected.IP) {
					continue
				}
				n.log("UDP both-symmetric probe received source=%s", hit.address)
				// Keep the successful NAT socket bound while admitting the remote's SYN.
				_ = hit.socket.Probe(hit.address, req.TransactionId)
				socket, e := hit.socket.Accept(ctx)
				if e != nil {
					return
				}
				stop := lifecycle.OnCancel(ctx, func() { socket.Close() })
				c, e := newConn(socket, s.cfg)
				if e == nil {
					e = c.acceptHandshake(s.cfg)
				}
				stop()
				if e == nil {
					e = ctx.Err()
				}
				if e != nil {
					socket.Close()
					return
				}
				n.AddConn(c)
				keep = hit.socket
				n.retainSocket(s, keep)
				s.run(c)
				n.log("UDP both-symmetric accepted peer=%d", c.remoteID)
				return
			}
		}
	}) {
		pool.closeExcept(nil)
		return nil, errors.New("UDP service stopping")
	}
	return &pb.SendPunchPacketBothEasySymResponse{BaseMappedAddr: base}, nil
}
