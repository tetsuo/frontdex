// Package crypto provides an AES-GCM based implementation for frontdex.Crypto.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// AESCipher provides encryption and decryption using a precomputed cipher.AEAD instance.
type AESCipher struct {
	key  []byte
	aead cipher.AEAD
}

// NewAESCipher creates a new Cipher instance with the given key.
func NewAESCipher(key []byte) (*AESCipher, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESCipher{
		key:  key,
		aead: aead,
	}, nil
}

// Encrypt encrypts the given data.
func (t *AESCipher) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, t.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := t.aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given data.
func (t *AESCipher) Decrypt(data []byte) ([]byte, error) {
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
