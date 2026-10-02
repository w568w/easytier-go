// Package transport implements EasyTier TCP packet framing.
package transport

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/easytier/easytier-go/internal/wire"
)

// Rust's TCP reader limits the entire peer packet, excluding the length prefix.
const MaxFrameSize = 2000

func Read(r io.Reader) (wire.Packet, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return wire.Packet{}, err
	}
	size := binary.LittleEndian.Uint32(prefix[:])
	if size < wire.PeerManagerHeaderSize || size > MaxFrameSize {
		return wire.Packet{}, fmt.Errorf("TCP frame length %d outside [%d, %d]", size, wire.PeerManagerHeaderSize, MaxFrameSize)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return wire.Packet{}, err
	}
	header, err := wire.ParseHeader(body)
	// Header.Length records the size before compression/encryption.
	// The TCP length prefix determines the wire frame length.
	return wire.Packet{Header: header, Payload: body[wire.PeerManagerHeaderSize:]}, err
}

// Write requires serialized access to w, like net.Conn writes of a whole frame.
func Write(w io.Writer, p wire.Packet) error {
	if len(p.Payload) > MaxFrameSize-wire.PeerManagerHeaderSize {
		return fmt.Errorf("TCP frame too large")
	}
	body, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
