package peerconn

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/easytier/easytier-go/internal/hostnet"
	"github.com/easytier/easytier-go/internal/lifecycle"
	"net"
	"time"

	pb "github.com/easytier/easytier-go/internal/peerpb"
	"github.com/easytier/easytier-go/internal/transport"
	"github.com/easytier/easytier-go/internal/wire"
	"google.golang.org/protobuf/proto"
)

type Listener struct {
	listener net.Listener
	config   Config
}

func Listen(address string, config Config) (*Listener, error) {
	return ListenContext(context.Background(), address, config)
}
func ListenContext(ctx context.Context, address string, config Config) (*Listener, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	host := hostnet.OrSystem(config.HostNetwork)
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	address, err := hostnet.Resolve(ctx, host, "tcp", address)
	if err != nil {
		return nil, err
	}
	l, err := host.Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return &Listener{listener: l, config: config}, nil
}
func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error   { return l.listener.Close() }

// Cancelling Accept closes the listener and interrupts an in-flight handshake.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	stop := lifecycle.OnCancel(ctx, func() { l.Close() })
	defer stop()
	socket, err := l.listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	stopConn := lifecycle.OnCancel(ctx, func() { socket.Close() })
	defer stopConn()
	c, err := newConn(socket, l.config)
	if err == nil {
		err = c.acceptHandshake(l.config)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		socket.Close()
		return nil, err
	}
	return c, nil
}
func (c *Conn) acceptHandshake(config Config) error {
	if err := c.socket.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	p, err := transport.Read(c.socket)
	if err != nil {
		return err
	}
	if config.Security != nil {
		if p.Header.PacketType != wire.PacketNoiseHandshakeMsg1 {
			return errors.New("secure mode requires Noise")
		}
		if err = c.noiseServer(config, p); err != nil {
			return err
		}
		return c.socket.SetDeadline(time.Time{})
	}
	if p.Header.PacketType != wire.PacketHandshake || p.Header.Flags != 0 {
		return errors.New("expected legacy handshake")
	}
	var req pb.HandshakeRequest
	if err = proto.Unmarshal(p.Payload, &req); err != nil {
		return err
	}
	digest := NetworkDigest(config.NetworkName, config.NetworkSecret)
	if req.Magic != handshakeMagic || req.Version != 1 || req.MyPeerId == 0 || req.MyPeerId == c.localID || req.MyPeerId != p.Header.FromPeerID || req.NetworkName != config.NetworkName {
		return errors.New("invalid handshake")
	}
	if subtle.ConstantTimeCompare(req.NetworkSecretDigest, digest[:]) != 1 {
		return errors.New("network secret mismatch")
	}
	payload, err := proto.Marshal(&pb.HandshakeRequest{Magic: handshakeMagic, MyPeerId: c.localID, Version: 1, NetworkName: config.NetworkName, NetworkSecretDigest: digest[:]})
	if err != nil {
		return err
	}
	if err = transport.Write(c.socket, wire.Packet{Header: wire.Header{FromPeerID: c.localID, PacketType: wire.PacketHandshake, ForwardCounter: 1}, Payload: payload}); err != nil {
		return err
	}
	c.remoteID = req.MyPeerId
	return c.socket.SetDeadline(time.Time{})
}
