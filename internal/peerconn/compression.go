package peerconn

import (
	"errors"
	"github.com/easytier/easytier-go/internal/wire"
	"github.com/klauspost/compress/zstd"
)

func decompress(b []byte) ([]byte, error) {
	d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(8<<20), zstd.WithDecoderMaxWindow(8<<20))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.DecodeAll(b, nil)
}
func decompressData(p *wire.Packet) error {
	if p.Header.Flags&wire.FlagCompressed == 0 {
		return nil
	}
	if len(p.Payload) == 0 || p.Payload[len(p.Payload)-1] != 1 {
		return errors.New("invalid compression tail")
	}
	b, err := decompress(p.Payload[:len(p.Payload)-1])
	if err != nil {
		return err
	}
	if uint32(len(b)) != p.Header.Length {
		return errors.New("decompressed length mismatch")
	}
	p.Payload = b
	p.Header.Flags &^= wire.FlagCompressed
	return nil
}
