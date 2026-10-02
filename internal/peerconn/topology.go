package peerconn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/route"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type topology struct {
	infos   map[uint32]*pb.RoutePeerInfo
	edges   map[uint32]*pb.RouteConnPeerList_PeerConnInfo
	touched map[uint32]time.Time
	hops    map[uint32]uint32
}

func newTopology(id uint32) *topology {
	return &topology{infos: map[uint32]*pb.RoutePeerInfo{id: {PeerId: id, InstId: newUUID(), Version: 1, PeerRouteId: randomID(), LastUpdate: timestamppb.Now(), EasytierVersion: "go-minimal", FeatureFlag: &pb.PeerFeatureFlag{SupportConnListSync: true, DisableP2P: true}}}, edges: map[uint32]*pb.RouteConnPeerList_PeerConnInfo{id: {PeerId: &pb.PeerIdVersion{PeerId: id, Version: 1}}}, touched: make(map[uint32]time.Time), hops: make(map[uint32]uint32)}
}
func (t *topology) localLinks(id uint32, peers map[uint32]*Conn) {
	ids := make([]uint32, 0, len(peers))
	for p := range peers {
		ids = append(ids, p)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	e := t.edges[id]
	e.PeerId.Version++
	e.ConnectedPeerIds = ids
	info := t.infos[id]
	info.Version++
	info.LastUpdate = timestamppb.Now()
}
func (t *topology) merge(id uint32, request *pb.SyncRouteInfoRequest) error {
	for _, info := range request.GetPeerInfos().GetItems() {
		if info.PeerId == id {
			if !proto.Equal(t.infos[id].InstId, info.InstId) {
				return errors.New("duplicate local peer ID")
			}
			continue
		}
		t.touched[info.PeerId] = time.Now()
		prev := t.infos[info.PeerId]
		if prev == nil || prev.Version < info.Version {
			t.infos[info.PeerId] = proto.Clone(info).(*pb.RoutePeerInfo)
			t.touched[info.PeerId] = time.Now()
		}
	}
	var rows []*pb.RouteConnPeerList_PeerConnInfo
	if list := request.GetConnPeerList(); list != nil {
		rows = list.PeerConnInfos
	}
	if b := request.GetConnBitmap(); b != nil {
		size := len(b.PeerIds)
		if size > 4096 || len(b.Bitmap) < (size*size+7)/8 {
			return errors.New("invalid topology bitmap")
		}
		for i, p := range b.PeerIds {
			row := &pb.RouteConnPeerList_PeerConnInfo{PeerId: p}
			for j, d := range b.PeerIds {
				bit := i*size + j
				if b.Bitmap[bit/8]&(1<<uint(bit%8)) != 0 {
					row.ConnectedPeerIds = append(row.ConnectedPeerIds, d.PeerId)
				}
			}
			rows = append(rows, row)
		}
	}
	for _, row := range rows {
		if row.PeerId == nil || row.PeerId.PeerId == id || row.PeerId.Version == 0 {
			continue
		}
		p := row.PeerId.PeerId
		t.touched[p] = time.Now()
		prev := t.edges[p]
		if prev == nil || prev.PeerId.Version < row.PeerId.Version {
			t.edges[p] = proto.Clone(row).(*pb.RouteConnPeerList_PeerConnInfo)
			t.touched[p] = time.Now()
		}
	}
	return nil
}
func (t *topology) rebuild(id uint32, peers map[uint32]*Conn) []route.Entry {
	for p, at := range t.touched {
		if time.Since(at) > 120*time.Second && peers[p] == nil {
			delete(t.infos, p)
			delete(t.edges, p)
			delete(t.touched, p)
		}
	}
	hops := map[uint32]uint32{id: id}
	queue := []uint32{id}
	for len(queue) > 0 {
		src := queue[0]
		queue = queue[1:]
		row := t.edges[src]
		if row == nil {
			continue
		}
		neighbors := append([]uint32(nil), row.ConnectedPeerIds...)
		sort.Slice(neighbors, func(i, j int) bool { return neighbors[i] < neighbors[j] })
		for _, dst := range neighbors {
			if _, ok := hops[dst]; ok {
				continue
			}
			if src == id && peers[dst] == nil {
				continue
			}
			h := hops[src]
			if src == id {
				h = dst
			}
			hops[dst] = h
			queue = append(queue, dst)
		}
	}
	t.hops = hops
	var entries []route.Entry
	for p, h := range hops {
		if p == id {
			continue
		}
		info := t.infos[p]
		if info == nil {
			continue
		}
		if ip := info.Ipv4Addr; ip != nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ip.Addr)
			entries = append(entries, route.Entry{Prefix: netip.PrefixFrom(netip.AddrFrom4(b), 32), PeerID: p, NextHop: h})
		}
		for _, cidr := range info.ProxyCidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err == nil {
				entries = append(entries, route.Entry{Prefix: prefix.Masked(), PeerID: p, NextHop: h})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Prefix == entries[j].Prefix {
			return entries[i].PeerID < entries[j].PeerID
		}
		return entries[i].Prefix.String() < entries[j].Prefix.String()
	})
	return entries
}
func (t *topology) snapshot(id uint32, session uint64) *pb.SyncRouteInfoRequest {
	infos := &pb.RoutePeerInfos{}
	ids := make([]uint32, 0, len(t.hops))
	for p := range t.hops {
		ids = append(ids, p)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	b := &pb.RouteConnBitmap{Bitmap: make([]byte, (len(ids)*len(ids)+7)/8)}
	for i, p := range ids {
		if info := t.infos[p]; info != nil {
			infos.Items = append(infos.Items, proto.Clone(info).(*pb.RoutePeerInfo))
		}
		row := t.edges[p]
		version := uint32(0)
		if row != nil {
			version = row.PeerId.Version
		}
		b.PeerIds = append(b.PeerIds, &pb.PeerIdVersion{PeerId: p, Version: version})
		if row != nil {
			for j, d := range ids {
				for _, neighbor := range row.ConnectedPeerIds {
					if d == neighbor {
						bit := i*len(ids) + j
						b.Bitmap[bit/8] |= 1 << uint(bit%8)
						break
					}
				}
			}
		}
	}
	return &pb.SyncRouteInfoRequest{MyPeerId: id, MySessionId: session, IsInitiator: true, PeerInfos: infos, ConnInfo: &pb.SyncRouteInfoRequest_ConnBitmap{ConnBitmap: b}}
}
