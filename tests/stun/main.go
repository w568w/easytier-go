// Local-only STUN fixture for isolated NAT acceptance tests.
package main

import (
	"encoding/binary"
	"net"
	"os"
)

func main() {
	a, e := net.ResolveUDPAddr("udp4", os.Args[1])
	if e != nil {
		panic(e)
	}
	s, e := net.ListenUDP("udp4", a)
	if e != nil {
		panic(e)
	}
	defer s.Close()
	b := make([]byte, 2048)
	for {
		n, peer, e := s.ReadFromUDP(b)
		if e != nil {
			return
		}
		if n < 20 || binary.BigEndian.Uint16(b) != 1 || binary.BigEndian.Uint32(b[4:8]) != 0x2112a442 {
			continue
		}
		reply := make([]byte, 32)
		copy(reply, b[:20])
		binary.BigEndian.PutUint16(reply, 0x101)
		binary.BigEndian.PutUint16(reply[2:], 12)
		binary.BigEndian.PutUint16(reply[20:], 0x20)
		binary.BigEndian.PutUint16(reply[22:], 8)
		reply[25] = 1
		binary.BigEndian.PutUint16(reply[26:], uint16(peer.Port)^0x2112)
		binary.BigEndian.PutUint32(reply[28:], binary.BigEndian.Uint32(peer.IP.To4())^0x2112a442)
		s.WriteToUDP(reply, peer)
	}
}
