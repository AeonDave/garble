package cache

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"

	"github.com/AeonDave/garble/internal/literals"
)

const (
	// NonceSize is the size in bytes of the randomly generated nonce used for ASCON cache encryption.
	NonceSize = 16
	// TagSize is the size in bytes of the authentication tag appended by ASCON encryption.
	TagSize = 16
)

func deriveKey(seed []byte) [16]byte {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("garble-cache-encryption-v1"))
	sum := h.Sum(nil)

	var key [16]byte
	copy(key[:], sum[:16])
	return key
}

// Encrypt serializes data with gob and protects it using ASCON-128 authenticated encryption.
func Encrypt(data any, seed []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return nil, fmt.Errorf("cache serialization failed: %v", err)
	}

	key := deriveKey(seed)

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}

	ciphertext := literals.AsconEncrypt(key[:], nonce, buf.Bytes())

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt verifies and decodes encrypted cache data into the provided destination value.
func Decrypt(encrypted, seed []byte, out any) error {
	if len(encrypted) < NonceSize {
		return fmt.Errorf("invalid encrypted cache: payload too short (%d bytes)", len(encrypted))
	}

	nonce := encrypted[:NonceSize]
	ciphertextAndTag := encrypted[NonceSize:]

	key := deriveKey(seed)

	plaintext, ok := literals.AsconDecrypt(key[:], nonce, ciphertextAndTag)
	if !ok {
		return fmt.Errorf("decryption failed (cache tampered or wrong key)")
	}

	if err := gob.NewDecoder(bytes.NewReader(plaintext)).Decode(out); err != nil {
		return fmt.Errorf("cache deserialization failed: %v", err)
	}

	return nil
}

// DeriveKey exposes the deterministic ASCON key derivation for testing and diagnostics.
func DeriveKey(seed []byte) [16]byte {
	return deriveKey(seed)
}
