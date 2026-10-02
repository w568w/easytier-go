// Package peerconn manages EasyTier peer connections and overlay routing.
package peerconn

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"github.com/easytier/easytier-go/internal/hostnet"
	"github.com/easytier/easytier-go/internal/lifecycle"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"

	"google.golang.org/protobuf/proto"
)

const handshakeMagic = 0xd1e1a5e1

type Config struct {
	HostNetwork   hostnet.Network
	PeerID        uint32
	NetworkName   string
	NetworkSecret string
	Timeout       time.Duration
	Security      *Security
}

type Conn struct {
	socket            net.Conn
	localID, remoteID uint32
	timeout           time.Duration
	cipher            *Encryptor
	session           *Session
	running           atomic.Bool
	writeMu           sync.Mutex
	security          *Security
}

func (c Config) validate() error {
	if c.PeerID == 0 || c.NetworkName == "" || c.Timeout <= 0 {
		return errors.New("peer ID, network name and positive timeout required")
	}
	return nil
}

func newConn(socket net.Conn, config Config) (*Conn, error) {
	cipher, err := NewEncryptor(config.NetworkSecret)
	if err != nil {
		return nil, err
	}
	return &Conn{socket: socket, localID: config.PeerID, timeout: config.Timeout, cipher: cipher, security: config.Security}, nil
}

func Dial(ctx context.Context, address string, config Config) (*Conn, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	host := hostnet.OrSystem(config.HostNetwork)
	address, err := hostnet.Resolve(dialCtx, host, "tcp", address)
	if err != nil {
		return nil, err
	}
	socket, err := host.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	c, err := newConn(socket, config)
	if err != nil {
		socket.Close()
		return nil, err
	}
	stop := lifecycle.OnCancel(ctx, func() { socket.Close() })
	defer stop()
	if err = c.handshake(config); err != nil {
		socket.Close()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		socket.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) handshake(config Config) error {
	if err := c.socket.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	if config.Security != nil {
		if err := c.noiseClient(config); err != nil {
			return err
		}
		return c.socket.SetDeadline(time.Time{})
	}
	digest := NetworkDigest(config.NetworkName, config.NetworkSecret)
	payload, err := proto.Marshal(&peerpb.HandshakeRequest{
		Magic: handshakeMagic, MyPeerId: c.localID, Version: 1,
		NetworkName: config.NetworkName, NetworkSecretDigest: digest[:],
	})
	if err != nil {
		return err
	}
	if err = transport.Write(c.socket, wire.Packet{Header: wire.Header{
		FromPeerID: c.localID, PacketType: wire.PacketHandshake, ForwardCounter: 1,
	}, Payload: payload}); err != nil {
		return err
	}
	packet, err := transport.Read(c.socket)
	if err != nil {
		return err
	}
	if packet.Header.PacketType != wire.PacketHandshake || packet.Header.Flags != 0 {
		return errors.New("expected legacy handshake response")
	}
	var response peerpb.HandshakeRequest
	if err = proto.Unmarshal(packet.Payload, &response); err != nil {
		return err
	}
	if response.Magic != handshakeMagic || response.Version != 1 {
		return errors.New("unsupported handshake magic/version")
	}
	if response.MyPeerId == 0 || response.MyPeerId == c.localID || response.MyPeerId != packet.Header.FromPeerID {
		return errors.New("invalid or conflicting remote peer ID")
	}
	if response.NetworkName != config.NetworkName {
		return errors.New("foreign networks are not supported")
	}
	if subtle.ConstantTimeCompare(response.NetworkSecretDigest, digest[:]) != 1 {
		return errors.New("network secret mismatch")
	}
	c.remoteID = response.MyPeerId
	return c.socket.SetDeadline(time.Time{})
}

func (c *Conn) Close() error { return c.socket.Close() }

// write serializes whole frames and their deadlines, including control traffic.
func (c *Conn) write(ctx context.Context, p wire.Packet) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.socket.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := transport.Write(c.socket, p)
	if err != nil {
		c.Close()
	}
	return err
}
func (c *Conn) SendRaw(ctx context.Context, p wire.Packet) error {
	if p.Header.ForwardCounter > 7 {
		return errors.New("forward counter exceeded")
	}
	if p.Header.ForwardCounter > 2 {
		p.Header.Flags &^= wire.FlagLatencyFirst
	}
	p.Header.ForwardCounter++
	return c.write(ctx, p)
}
func (c *Conn) sendRPC(ctx context.Context, p wire.Packet) error {
	if c.session != nil {
		if err := c.session.Encrypt(&p); err != nil {
			return err
		}
	}
	return c.write(ctx, p)
}

// run owns the reader and heartbeat; handle receives every other wire packet.
func (c *Conn) run(ctx context.Context, interval time.Duration, handle func(context.Context, *Conn, wire.Packet) error) (err error) {
	if interval <= 0 {
		return errors.New("positive ping interval required")
	}
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("Run may only be called once")
	}
	runCtx, cancel := context.WithCancel(ctx)
	type result struct {
		packet wire.Packet
		err    error
	}
	incoming := make(chan result)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			p, e := transport.Read(c.socket)
			select {
			case incoming <- result{p, e}:
			case <-runCtx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	defer func() { cancel(); c.Close(); <-done }()
	stop := lifecycle.OnCancel(runCtx, func() { c.Close() })
	defer stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	var seq uint32
	pending := false
	ping := func() error {
		seq++
		payload := make([]byte, 4)
		binary.LittleEndian.PutUint32(payload, seq)
		pending = true
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(c.timeout)
		return c.write(ctx, wire.Packet{Header: wire.Header{FromPeerID: c.localID, ToPeerID: c.remoteID, PacketType: wire.PacketPing, ForwardCounter: 1}, Payload: payload})
	}
	if err = ping(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !pending {
				if err = ping(); err != nil {
					return err
				}
			}
		case <-timer.C:
			return errors.New("pong timeout")
		case r := <-incoming:
			if r.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return r.err
			}
			p := r.packet
			switch p.Header.PacketType {
			case wire.PacketPing:
				if p.Header.FromPeerID != c.remoteID || p.Header.ToPeerID != c.localID || len(p.Payload) != 4 || p.Header.Flags&wire.FlagEncrypted != 0 {
					return errors.New("invalid ping")
				}
				p.Header.PacketType = wire.PacketPong
				if err = c.write(ctx, p); err != nil {
					return err
				}
				continue
			case wire.PacketPong:
				if pending && p.Header.FromPeerID == c.localID && p.Header.ToPeerID == c.remoteID && len(p.Payload) == 4 && binary.LittleEndian.Uint32(p.Payload) == seq {
					pending = false
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				}
				continue
			}
			if err = handle(ctx, c, p); err != nil {
				return err
			}
		}
	}
}
