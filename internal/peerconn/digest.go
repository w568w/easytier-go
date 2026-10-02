package peerconn

import (
	"encoding/binary"
	"math/bits"
)

// Rust DefaultHasher::new is SipHash-1-3 with zero keys. Each finish is a
// snapshot: subsequent writes continue hashing the original stream.
func NetworkDigest(name, secret string) [32]byte {
	stream := append([]byte(name), []byte(secret)...)
	var digest [32]byte
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(digest[i*8:], sipHash13(stream))
		stream = append(stream, digest[:(i+1)*8]...)
	}
	return digest
}

func DeriveKey128(secret string) [16]byte {
	var key [16]byte
	stream := []byte(secret)
	binary.BigEndian.PutUint64(key[:8], sipHash13(stream))
	stream = append(stream, key[:8]...)
	binary.BigEndian.PutUint64(key[8:], sipHash13(stream))
	return key
}

func sipHash13(data []byte) uint64 {
	v0, v1 := uint64(0x736f6d6570736575), uint64(0x646f72616e646f6d)
	v2, v3 := uint64(0x6c7967656e657261), uint64(0x7465646279746573)
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}
	tail := uint64(len(data)) << 56
	for len(data) >= 8 {
		m := binary.LittleEndian.Uint64(data)
		v3 ^= m
		round()
		v0 ^= m
		data = data[8:]
	}
	for i, b := range data {
		tail |= uint64(b) << (8 * i)
	}
	v3 ^= tail
	round()
	v0 ^= tail
	v2 ^= 0xff
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}
