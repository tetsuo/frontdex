package crypto_test

import (
	"bytes"
	"testing"

	"github.com/tetsuo/frontdex/internal/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("example key 12345678901234567890") // 32 bytes
	c, err := crypto.NewAESCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("hello world")
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data does not match original: got %s, want %s", decrypted, plaintext)
	}
}

func TestDecryptInvalidData(t *testing.T) {
	key := []byte("example key 12345678901234567890")
	c, err := crypto.NewAESCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Test with data shorter than nonce size
	shortData := []byte("short")
	_, err = c.Decrypt(shortData)
	if err == nil {
		t.Error("Expected error for short data, got nil")
	}

	// Test with invalid ciphertext (tampered)
	plaintext := []byte("test")
	ciphertext, _ := c.Encrypt(plaintext)
	// Tamper with ciphertext
	ciphertext[0] ^= 1
	_, err = c.Decrypt(ciphertext)
	if err == nil {
		t.Error("Expected error for tampered ciphertext, got nil")
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := []byte("example key 12345678901234567890")
	c, err := crypto.NewAESCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("")
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted empty data does not match: got %s, want %s", decrypted, plaintext)
	}
}

func TestDifferentKeys(t *testing.T) {
	key1 := []byte("example key 12345678901234567890")
	key2 := []byte("different key 123456789012345678")

	c1, _ := crypto.NewAESCipher(key1)
	c2, _ := crypto.NewAESCipher(key2)

	plaintext := []byte("test message")
	ciphertext, _ := c1.Encrypt(plaintext)

	// Try to decrypt with different key
	_, err := c2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key, got nil")
	}
}
