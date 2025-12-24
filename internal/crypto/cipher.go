package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Cipher provides encryption and decryption using a precomputed cipher.AEAD instance.
type Cipher struct {
	key  []byte
	aead cipher.AEAD
}

// NewCipher creates a new Cipher instance with the given key.
func NewCipher(key []byte) (*Cipher, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, fmt.Errorf("invalid key length: must be 16, 24, or 32 bytes for AES")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		key:  key,
		aead: aead,
	}, nil
}

// Encrypt encrypts the given data.
func (t *Cipher) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, t.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := t.aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given data.
func (t *Cipher) Decrypt(data []byte) ([]byte, error) {
	nonceSize := t.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data length is less than nonce size")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := t.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
