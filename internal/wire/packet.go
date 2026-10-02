// Package wire implements the fixed EasyTier peer packet header.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const PeerManagerHeaderSize = 16

type PacketType uint8

const (
	PacketInvalid PacketType = iota
	PacketData
	PacketHandshake
	PacketRoutePacket
	PacketPing
	PacketPong
	PacketTARPC
	PacketRoute
	PacketRPCRequest
	PacketRPCResponse
)

const (
	PacketNoiseHandshakeMsg1 PacketType = 13
	PacketNoiseHandshakeMsg2 PacketType = 14
	PacketNoiseHandshakeMsg3 PacketType = 15
	PacketRelayHandshake     PacketType = 20
	PacketRelayHandshakeAck  PacketType = 21
)

type Flags uint8

const (
	FlagEncrypted Flags = 1 << iota
	FlagLatencyFirst
	FlagExitNode
	FlagNoProxy
	FlagCompressed
	FlagLivenessProbe
	FlagNotSendToTun
	FlagLivenessEcho
)

// Header is the 16-byte little-endian PeerManagerHeader.
type Header struct {
	FromPeerID     uint32
	ToPeerID       uint32
	PacketType     PacketType
	Flags          Flags
	ForwardCounter uint8
	Reserved       uint8
	Length         uint32
}

func (h Header) MarshalBinary() [PeerManagerHeaderSize]byte {
	var b [PeerManagerHeaderSize]byte
	binary.LittleEndian.PutUint32(b[0:4], h.FromPeerID)
	binary.LittleEndian.PutUint32(b[4:8], h.ToPeerID)
	b[8] = byte(h.PacketType)
	b[9] = byte(h.Flags)
	b[10] = h.ForwardCounter
	b[11] = h.Reserved
	binary.LittleEndian.PutUint32(b[12:16], h.Length)
	return b
}

func ParseHeader(b []byte) (Header, error) {
	if len(b) < PeerManagerHeaderSize {
		return Header{}, fmt.Errorf("peer header: need %d bytes, got %d", PeerManagerHeaderSize, len(b))
	}
	return Header{
		FromPeerID:     binary.LittleEndian.Uint32(b[0:4]),
		ToPeerID:       binary.LittleEndian.Uint32(b[4:8]),
		PacketType:     PacketType(b[8]),
		Flags:          Flags(b[9]),
		ForwardCounter: b[10],
		Reserved:       b[11],
		Length:         binary.LittleEndian.Uint32(b[12:16]),
	}, nil
}

type Packet struct {
	Header  Header
	Payload []byte
}

func (p Packet) MarshalBinary() ([]byte, error) {
	if uint64(len(p.Payload)) > uint64(^uint32(0)) {
		return nil, errors.New("packet payload exceeds uint32 length")
	}
	h := p.Header
	if h.Flags&(FlagEncrypted|FlagCompressed) == 0 {
		h.Length = uint32(len(p.Payload))
	}
	b := make([]byte, PeerManagerHeaderSize+len(p.Payload))
	hdr := h.MarshalBinary()
	copy(b, hdr[:])
	copy(b[PeerManagerHeaderSize:], p.Payload)
	return b, nil
}

func ParsePacket(b []byte) (Packet, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Packet{}, err
	}
	want := uint64(PeerManagerHeaderSize) + uint64(h.Length)
	if h.Flags&(FlagEncrypted|FlagCompressed) == 0 && want != uint64(len(b)) {
		return Packet{}, fmt.Errorf("packet length: header declares %d bytes, got %d", h.Length, len(b)-PeerManagerHeaderSize)
	}
	payload := make([]byte, len(b)-PeerManagerHeaderSize)
	copy(payload, b[PeerManagerHeaderSize:])
	return Packet{Header: h, Payload: payload}, nil
}

func NewData(from, to uint32, payload []byte) Packet {
	return Packet{Header: Header{FromPeerID: from, ToPeerID: to, PacketType: PacketData, ForwardCounter: 1}, Payload: payload}
}
