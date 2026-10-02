package peerconn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/easytier/easytier-go/internal/wire"
)

type Encryptor struct{ cipher cipher.AEAD }

func NewEncryptor(secret string) (*Encryptor, error) {
	key := DeriveKey128(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{cipher: aead}, nil
}

func (e *Encryptor) Encrypt(p *wire.Packet) error {
	if p.Header.Flags&wire.FlagEncrypted != 0 {
		return nil
	}
	p.Header.Length = uint32(len(p.Payload))
	nonce := make([]byte, e.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	p.Payload = append(e.cipher.Seal(nil, nonce, p.Payload, nil), nonce...)
	p.Header.Flags |= wire.FlagEncrypted
	return nil
}

func (e *Encryptor) Decrypt(p *wire.Packet) error {
	if p.Header.Flags&wire.FlagEncrypted == 0 {
		return errors.New("packet is not encrypted")
	}
	n := e.cipher.NonceSize()
	if len(p.Payload) < n+e.cipher.Overhead() {
		return errors.New("encrypted packet is too short")
	}
	plain, err := e.cipher.Open(nil, p.Payload[len(p.Payload)-n:], p.Payload[:len(p.Payload)-n], nil)
	if err != nil {
		return err
	}
	p.Payload = plain
	p.Header.Flags &^= wire.FlagEncrypted
	return nil
}
