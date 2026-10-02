package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/easytier/easytier-go/internal/hostnet"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// UDP multiplexes EasyTier datagram sessions on one socket. The same socket is
// retained for STUN, punching and data, preserving the NAT mapping.
type UDP struct {
	socket   net.PacketConn
	host     hostnet.Network
	mu       sync.Mutex
	sessions map[udpKey]*DatagramConn
	stun     map[[12]byte]chan []byte
	punches  map[uint32]chan string
	accepts  chan *DatagramConn
	done     chan struct{}
	readDone chan struct{}
	once     sync.Once
}
type udpKey struct {
	addr string
	id   uint32
}
type DatagramConn struct {
	endpoint                    *UDP
	remote                      *net.UDPAddr
	id                          uint32
	magic                       [8]byte
	incoming                    chan []byte
	ack                         chan struct{}
	done                        chan struct{}
	once                        sync.Once
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
	buffer                      []byte
}

func ListenUDP(address string) (*UDP, error) {
	return ListenUDPWithHost(context.Background(), hostnet.System{}, address)
}
func ListenUDPWithHost(ctx context.Context, host hostnet.Network, address string) (*UDP, error) {
	host = hostnet.OrSystem(host)
	address, err := hostnet.Resolve(ctx, host, "udp4", address)
	if err != nil {
		return nil, err
	}
	socket, err := host.ListenPacket(ctx, "udp4", address)
	if err != nil {
		return nil, err
	}
	u := &UDP{socket: socket, host: host, sessions: make(map[udpKey]*DatagramConn), stun: make(map[[12]byte]chan []byte), punches: make(map[uint32]chan string), accepts: make(chan *DatagramConn, 64), done: make(chan struct{}), readDone: make(chan struct{})}
	go u.receive()
	return u, nil
}
func (u *UDP) Addr() net.Addr { return u.socket.LocalAddr() }
func (u *UDP) Close() error   { err := u.shutdown(); <-u.readDone; return err }
func (u *UDP) shutdown() error {
	var err error
	u.once.Do(func() {
		close(u.done)
		err = u.socket.Close()
		u.mu.Lock()
		sessions := u.sessions
		u.sessions = make(map[udpKey]*DatagramConn)
		u.mu.Unlock()
		for _, c := range sessions {
			c.Close()
		}
	})
	return err
}
func (u *UDP) makeConn(addr *net.UDPAddr, id uint32) *DatagramConn {
	return &DatagramConn{endpoint: u, remote: addr, id: id, incoming: make(chan []byte, 128), ack: make(chan struct{}, 1), done: make(chan struct{}), changed: make(chan struct{})}
}
func (u *UDP) packet(addr *net.UDPAddr, id uint32, kind byte, payload []byte) error {
	if len(payload) > 65507-8 {
		return errors.New("UDP packet too large")
	}
	b := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint32(b, id)
	b[4] = kind
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(payload)))
	copy(b[8:], payload)
	_, err := u.socket.WriteTo(b, addr)
	return err
}
func (u *UDP) receive() {
	defer close(u.readDone)
	defer u.shutdown()
	buf := make([]byte, 65536)
	for {
		n, rawAddr, err := u.socket.ReadFrom(buf)
		var addr *net.UDPAddr
		if err == nil {
			addr, err = numericUDP(rawAddr.String())
		}
		if err != nil {
			return
		}
		b := buf[:n]
		if n >= 20 && binary.BigEndian.Uint32(b[4:8]) == 0x2112a442 && b[0]&0xc0 == 0 {
			var tx [12]byte
			copy(tx[:], b[8:20])
			u.mu.Lock()
			ch := u.stun[tx]
			u.mu.Unlock()
			if ch != nil {
				select {
				case ch <- append([]byte(nil), b...):
				default:
				}
			}
			continue
		}
		if n < 8 || int(binary.LittleEndian.Uint16(b[6:8])) != n-8 {
			continue
		}
		id := binary.LittleEndian.Uint32(b)
		if b[4] == 5 && n == 24 {
			u.mu.Lock()
			ch := u.punches[id]
			u.mu.Unlock()
			if ch != nil {
				select {
				case ch <- addr.String():
				default:
				}
			}
			continue
		}
		key := udpKey{addr.String(), id}
		kind := b[4]
		u.mu.Lock()
		c := u.sessions[key]
		created := false
		if kind == 1 && n == 16 && c == nil && len(u.sessions) < 256 {
			c = u.makeConn(addr, id)
			u.sessions[key] = c
			created = true
		}
		u.mu.Unlock()
		if c == nil {
			continue
		}
		switch kind {
		case 1:
			if n != 16 {
				continue
			}
			if err = u.packet(addr, id, 2, b[8:]); err != nil {
				c.Close()
				continue
			}
			if created {
				select {
				case u.accepts <- c:
				default:
					c.Close()
				}
			}
		case 2:
			if n == 16 && string(b[8:]) == string(c.magic[:]) {
				select {
				case c.ack <- struct{}{}:
				default:
				}
			}
		case 3:
			if n < 24 {
				continue
			}
			frame := make([]byte, 4+n-8)
			binary.LittleEndian.PutUint32(frame, uint32(n-8))
			copy(frame[4:], b[8:])
			select {
			case c.incoming <- frame:
			default:
			}
		case 4:
			c.Close()
		}
	}
}
func (u *UDP) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.done:
		return nil, net.ErrClosed
	case c := <-u.accepts:
		return c, nil
	}
}
func (u *UDP) Dial(ctx context.Context, address string) (net.Conn, error) {
	addr, err := numericUDP(address)
	if err != nil {
		return nil, err
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := binary.LittleEndian.Uint32(random[:4])
	c := u.makeConn(addr, id)
	copy(c.magic[:], random[4:])
	key := udpKey{addr.String(), id}
	u.mu.Lock()
	u.sessions[key] = c
	u.mu.Unlock()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err = u.packet(addr, id, 1, c.magic[:]); err != nil {
			c.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			c.Close()
			return nil, ctx.Err()
		case <-u.done:
			c.Close()
			return nil, net.ErrClosed
		case <-c.ack:
			return c, nil
		case <-ticker.C:
		}
	}
}
func (u *UDP) Punch(ctx context.Context, address string, tid uint32, count int, interval time.Duration) error {
	if count < 1 || count > 20 || interval < 10*time.Millisecond || interval > time.Second {
		return errors.New("invalid punch batch")
	}
	addr, err := numericUDP(address)
	if err != nil {
		return err
	}
	var payload [16]byte
	if _, err = rand.Read(payload[:]); err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		if err = u.packet(addr, tid, 5, payload[:]); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-u.done:
			timer.Stop()
			return net.ErrClosed
		case <-timer.C:
		}
	}
	return nil
}
func (c *DatagramConn) LocalAddr() net.Addr  { return c.endpoint.Addr() }
func (c *DatagramConn) RemoteAddr() net.Addr { return c.remote }
func (c *DatagramConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.endpoint.mu.Lock()
		delete(c.endpoint.sessions, udpKey{c.remote.String(), c.id})
		c.endpoint.mu.Unlock()
	})
	return nil
}
func (c *DatagramConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *DatagramConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *DatagramConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}
func (c *DatagramConn) Read(p []byte) (int, error) {
	for len(c.buffer) == 0 {
		c.mu.Lock()
		deadline, changed := c.readDeadline, c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-changed:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case b := <-c.incoming:
			c.buffer = b
		}
		if timer != nil {
			timer.Stop()
		}
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}
func (c *DatagramConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) < 4 || int(binary.LittleEndian.Uint32(p)) != len(p)-4 {
		return 0, io.ErrShortWrite
	}
	if err := c.endpoint.packet(c.remote, c.id, 3, p[4:]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// MappedAddress queries server for the data socket's mapped IPv4 address
// using RFC 5389 Binding.
func (u *UDP) MappedAddress(ctx context.Context, server string) (string, error) {
	server, err := hostnet.Resolve(ctx, u.host, "udp4", server)
	if err != nil {
		return "", err
	}
	addr, err := numericUDP(server)
	if err != nil {
		return "", err
	}
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, 1)
	binary.BigEndian.PutUint32(b[4:8], 0x2112a442)
	if _, err = rand.Read(b[8:20]); err != nil {
		return "", err
	}
	var tx [12]byte
	copy(tx[:], b[8:])
	ch := make(chan []byte, 1)
	u.mu.Lock()
	u.stun[tx] = ch
	u.mu.Unlock()
	defer func() { u.mu.Lock(); delete(u.stun, tx); u.mu.Unlock() }()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err = u.socket.WriteTo(b, addr); err != nil {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-u.done:
			return "", net.ErrClosed
		case <-ticker.C:
			continue
		case resp := <-ch:
			if binary.BigEndian.Uint16(resp) != 0x101 {
				return "", errors.New("STUN binding rejected")
			}
			size := int(binary.BigEndian.Uint16(resp[2:4])) + 20
			if size > len(resp) {
				return "", errors.New("truncated STUN response")
			}
			for offset := 20; offset+4 <= size; {
				typ := binary.BigEndian.Uint16(resp[offset:])
				length := int(binary.BigEndian.Uint16(resp[offset+2:]))
				offset += 4
				if offset+length > size {
					return "", errors.New("invalid STUN attribute")
				}
				v := resp[offset : offset+length]
				if (typ == 0x20 || typ == 1) && length >= 8 && v[1] == 1 {
					port := binary.BigEndian.Uint16(v[2:])
					ip := binary.BigEndian.Uint32(v[4:])
					if typ == 0x20 {
						port ^= 0x2112
						ip ^= 0x2112a442
					}
					out := make(net.IP, 4)
					binary.BigEndian.PutUint32(out, ip)
					return (&net.UDPAddr{IP: out, Port: int(port)}).String(), nil
				}
				offset += (length + 3) &^ 3
			}
			return "", errors.New("STUN response has no IPv4 mapping")
		}
	}
}

func (u *UDP) WatchPunch(id uint32) (<-chan string, func()) {
	u.mu.Lock()
	ch := make(chan string, 16)
	u.punches[id] = ch
	u.mu.Unlock()
	return ch, func() { u.mu.Lock(); delete(u.punches, id); u.mu.Unlock() }
}
func (u *UDP) Probe(address string, tid uint32) error {
	addr, err := numericUDP(address)
	if err != nil {
		return err
	}
	var body [16]byte
	if _, err = rand.Read(body[:]); err != nil {
		return err
	}
	return u.packet(addr, tid, 5, body[:])
}
func (u *UDP) SessionCount() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.sessions) }

func numericUDP(address string) (*net.UDPAddr, error) {
	a, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(a), nil
}
