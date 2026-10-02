package peerconn

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SelectIPv4 follows EasyTier's distributed DHCP: retain an unclaimed address,
// otherwise choose the first free host in the subnet. Zero means exhaustion.
func SelectIPv4(subnet, current netip.Prefix, used map[netip.Addr]bool) (netip.Prefix, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet.Bits() > 30 {
		return netip.Prefix{}, errors.New("DHCP requires an IPv4 subnet with host addresses")
	}
	subnet = subnet.Masked()
	if current.IsValid() && subnet.Contains(current.Addr()) && current.Bits() == subnet.Bits() && !used[current.Addr()] {
		return current, nil
	}
	b := subnet.Addr().As4()
	base := binary.BigEndian.Uint32(b[:])
	size := uint64(1) << (32 - subnet.Bits())
	// At most len(used)+1 candidates can precede a free host.
	for offset := uint64(1); offset < size-1 && offset <= uint64(len(used))+1; offset++ {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], base+uint32(offset))
		addr := netip.AddrFrom4(raw)
		if !used[addr] {
			return netip.PrefixFrom(addr, subnet.Bits()), nil
		}
	}
	return netip.Prefix{}, nil
}
func (n *Node) IPv4() netip.Prefix {
	n.mu.RLock()
	defer n.mu.RUnlock()
	info := n.topo.infos[n.ID]
	if info.Ipv4Addr == nil {
		return netip.Prefix{}
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], info.Ipv4Addr.Addr)
	return netip.PrefixFrom(netip.AddrFrom4(b), int(info.NetworkLength))
}
func (n *Node) setDHCP(prefix netip.Prefix) {
	n.mu.Lock()
	defer n.mu.Unlock()
	info := n.topo.infos[n.ID]
	if prefix.IsValid() {
		b := prefix.Addr().As4()
		info.Ipv4Addr = &pb.Ipv4Addr{Addr: binary.BigEndian.Uint32(b[:])}
		info.NetworkLength = uint32(prefix.Bits())
	} else {
		info.Ipv4Addr = nil
	}
	info.Version++
	info.LastUpdate = timestamppb.Now()
}

// RunDHCP applies the host-provided address update before advertising it. A failed apply leaves
// the previous advertisement unchanged and is returned to the host.
// An invalid subnet derives the subnet from existing peers, or uses 10.0.0.0/24.
func (n *Node) RunDHCP(ctx context.Context, subnet netip.Prefix, apply func(netip.Prefix, netip.Prefix) error) error {
	if apply == nil {
		return errors.New("DHCP apply callback required")
	}
	if subnet.IsValid() {
		if _, err := SelectIPv4(subnet, netip.Prefix{}, nil); err != nil {
			return err
		}
	}
	current := n.IPv4()
	for {
		n.mu.RLock()
		used := make(map[netip.Addr]bool)
		var candidates []netip.Prefix
		hasPeers := len(n.peers) > 0
		for id := range n.topo.hops {
			if id == n.ID {
				continue
			}
			info := n.topo.infos[id]
			if info == nil || info.Ipv4Addr == nil {
				continue
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], info.Ipv4Addr.Addr)
			addr := netip.AddrFrom4(b)
			used[addr] = true
			if info.NetworkLength <= 30 {
				candidates = append(candidates, netip.PrefixFrom(addr, int(info.NetworkLength)).Masked())
			}
		}
		n.mu.RUnlock()
		if hasPeers {
			pool := subnet
			if !pool.IsValid() {
				sort.Slice(candidates, func(i, j int) bool { return candidates[i].String() < candidates[j].String() })
				if len(candidates) > 0 {
					pool = candidates[0]
				} else {
					pool = netip.MustParsePrefix("10.0.0.0/24")
				}
			}
			next, err := SelectIPv4(pool, current, used)
			if err != nil {
				return err
			}
			if next != current {
				if err = apply(current, next); err != nil {
					return err
				}
				n.setDHCP(next)
				n.log("DHCP address %s -> %s", current, next)
				current = next
			}
		}
		delay := time.Second
		if hasPeers {
			delay = 5*time.Second + time.Duration(randomID()%5000)*time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
