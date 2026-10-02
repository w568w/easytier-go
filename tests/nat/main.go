//go:build linux

// A deterministic endpoint-dependent UDP NAT fixture. PREROUTING redirects
// inside packets here; mappings key on both inside and destination endpoints.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	public := flag.String("public", "", "outside IPv4")
	base := flag.Int("base", 40000, "first allocated port")
	decrement := flag.Bool("decrement", false, "allocate descending ports")
	flag.Parse()
	listener := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		e := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			if err == nil {
				err = unix.SetsockoptInt(int(fd), unix.SOL_IP, 20, 1)
			}
		})
		if e != nil {
			return e
		}
		return err
	}}
	pc, err := listener.ListenPacket(context.Background(), "udp4", "0.0.0.0:19999")
	if err != nil {
		panic(err)
	}
	defer pc.Close()
	in := pc.(*net.UDPConn)
	type mapping struct {
		socket      *net.UDPConn
		destination *net.UDPAddr
	}
	mappings := make(map[string]mapping)
	replySockets := make(map[string]*net.UDPConn)
	var replyMu sync.Mutex
	next := *base
	payload, oob := make([]byte, 65536), make([]byte, 256)
	for {
		n, on, _, inside, err := in.ReadMsgUDP(payload, oob)
		if err != nil {
			panic(err)
		}
		var target *net.UDPAddr
		messages, err := unix.ParseSocketControlMessage(oob[:on])
		if err != nil {
			panic(err)
		}
		for _, m := range messages {
			if m.Header.Level == unix.SOL_IP && m.Header.Type == 20 && len(m.Data) >= 16 {
				target = &net.UDPAddr{IP: net.IPv4(m.Data[4], m.Data[5], m.Data[6], m.Data[7]), Port: int(binary.BigEndian.Uint16(m.Data[2:4]))}
			}
		}
		if target != nil && target.Port == 19999 {
			panic("original destination was rewritten")
		}
		if target == nil {
			panic("missing original destination")
		}
		key := inside.String() + ">" + target.String()
		v, ok := mappings[key]
		if !ok {
			var outbound *net.UDPConn
			for {
				if next < 1024 || next > 65535 {
					panic("NAT ports exhausted")
				}
				outbound, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(*public), Port: next})
				if *decrement {
					next--
				} else {
					next++
				}
				if err == nil {
					break
				}
			}
			v = mapping{outbound, target}
			mappings[key] = v
			fmt.Fprintf(os.Stdout, "map %s -> %s\n", key, outbound.LocalAddr())
			go func(v mapping, inside *net.UDPAddr) {
				buf := make([]byte, 65536)
				for {
					n, remote, e := v.socket.ReadFromUDP(buf)
					if e != nil {
						return
					}
					if remote.String() != v.destination.String() {
						continue
					}
					replyMu.Lock()
					reply := replySockets[remote.String()]
					if reply == nil {
						config := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
							var e error
							c.Control(func(fd uintptr) {
								e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
								if e == nil {
									e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
								}
							})
							return e
						}}
						p, e := config.ListenPacket(context.Background(), "udp4", remote.String())
						if e != nil {
							panic(e)
						}
						reply = p.(*net.UDPConn)
						replySockets[remote.String()] = reply
					}
					replyMu.Unlock()
					if _, e = reply.WriteToUDP(buf[:n], inside); e != nil {
						panic(e)
					}
				}
			}(v, inside)
		}
		if _, err = v.socket.WriteToUDP(payload[:n], target); err != nil {
			panic(err)
		}
	}
}
