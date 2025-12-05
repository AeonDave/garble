package runtimecrypto

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD wraps a cipher.AEAD implementation for runtime encryption.
// Uses ChaCha20-Poly1305 for authenticated encryption.
type AEAD struct {
	aead cipher.AEAD
}

// NewAEAD constructs a ChaCha20-Poly1305 AEAD using the provided 32-byte key.
func NewAEAD(key []byte) (AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return AEAD{}, fmt.Errorf("runtimecrypto: invalid key length %d", len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return AEAD{}, fmt.Errorf("runtimecrypto: create aead: %w", err)
	}
	return AEAD{aead: aead}, nil
}

// NonceSize reports the nonce length required by the underlying construction.
func (a AEAD) NonceSize() int {
	return a.aead.NonceSize()
}

// Overhead reports the MAC size added to sealed ciphertexts.
func (a AEAD) Overhead() int {
	return a.aead.Overhead()
}

// Seal encrypts and authenticates plaintext using the supplied nonce and AAD.
func (a AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return a.aead.Seal(dst, nonce, plaintext, additionalData)
}

// Open verifies and decrypts ciphertext produced by Seal.
func (a AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := a.aead.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("runtimecrypto: aead open: %w", err)
	}
	return plaintext, nil
}
