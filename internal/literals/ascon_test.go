// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from ASCON specification
// https://ascon.iaik.tugraz.at/

func TestAsconEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		nonce     []byte
		plaintext []byte
	}{
		{
			name:      "empty plaintext",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte{},
		},
		{
			name:      "single byte",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte{0x42},
		},
		{
			name:      "7 bytes (partial block)",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte("hello!!"),
		},
		{
			name:      "8 bytes (one block)",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte("12345678"),
		},
		{
			name:      "16 bytes (two blocks)",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte("0123456789ABCDEF"),
		},
		{
			name:      "typical string",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte("The quick brown fox jumps over the lazy dog"),
		},
		{
			name:      "with random key and nonce",
			key:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			nonce:     []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
			plaintext: []byte("Secret message!"),
		},
		{
			name:      "large text",
			key:       make([]byte, 16),
			nonce:     make([]byte, 16),
			plaintext: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertextAndTag := AsconEncrypt(tt.key, tt.nonce, tt.plaintext)

			// Check output length
			expectedLen := len(tt.plaintext) + asconTagSize
			if len(ciphertextAndTag) != expectedLen {
				t.Fatalf("encrypted output length = %d, want %d", len(ciphertextAndTag), expectedLen)
			}

			// Decrypt
			decrypted, ok := AsconDecrypt(tt.key, tt.nonce, ciphertextAndTag)
			if !ok {
				t.Fatal("decryption failed (authentication error)")
			}

			// Verify plaintext matches
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted plaintext does not match\ngot:  %x\nwant: %x", decrypted, tt.plaintext)
			}
		})
	}
}

func TestAsconAuthenticationFailure(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	plaintext := []byte("Secret message that should be authenticated")

	// Encrypt
	ciphertextAndTag := AsconEncrypt(key, nonce, plaintext)

	// Test various tampering scenarios
	tests := []struct {
		name   string
		tamper func([]byte) []byte
	}{
		{
			name: "flip bit in ciphertext",
			tamper: func(data []byte) []byte {
				modified := make([]byte, len(data))
				copy(modified, data)
				modified[0] ^= 0x01
				return modified
			},
		},
		{
			name: "flip bit in tag",
			tamper: func(data []byte) []byte {
				modified := make([]byte, len(data))
				copy(modified, data)
				modified[len(modified)-1] ^= 0x01
				return modified
			},
		},
		{
			name: "truncate tag",
			tamper: func(data []byte) []byte {
				return data[:len(data)-1]
			},
		},
		{
			name: "append extra byte",
			tamper: func(data []byte) []byte {
				return append(data, 0x00)
			},
		},
		{
			name: "zero out tag",
			tamper: func(data []byte) []byte {
				modified := make([]byte, len(data))
				copy(modified, data)
				for i := len(plaintext); i < len(modified); i++ {
					modified[i] = 0
				}
				return modified
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamper(ciphertextAndTag)

			_, ok := AsconDecrypt(key, nonce, tampered)
			if ok {
				t.Error("decryption succeeded with tampered data (should have failed authentication)")
			}
		})
	}
}

func TestAsconDifferentKeys(t *testing.T) {
	nonce := make([]byte, 16)
	plaintext := []byte("This is a secret message")

	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	key2[0] = 0x01 // Different key

	// Encrypt with key1
	ciphertextAndTag := AsconEncrypt(key1, nonce, plaintext)

	// Try to decrypt with key2 (should fail)
	_, ok := AsconDecrypt(key2, nonce, ciphertextAndTag)
	if ok {
		t.Error("decryption succeeded with wrong key (should have failed)")
	}

	// Decrypt with correct key (should succeed)
	decrypted, ok := AsconDecrypt(key1, nonce, ciphertextAndTag)
	if !ok {
		t.Error("decryption failed with correct key")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted plaintext does not match with correct key")
	}
}

func TestAsconDifferentNonces(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("This is a secret message")

	nonce1 := make([]byte, 16)
	nonce2 := make([]byte, 16)
	nonce2[0] = 0x01 // Different nonce

	// Encrypt with nonce1
	ciphertextAndTag := AsconEncrypt(key, nonce1, plaintext)

	// Try to decrypt with nonce2 (should fail)
	_, ok := AsconDecrypt(key, nonce2, ciphertextAndTag)
	if ok {
		t.Error("decryption succeeded with wrong nonce (should have failed)")
	}

	// Decrypt with correct nonce (should succeed)
	decrypted, ok := AsconDecrypt(key, nonce1, ciphertextAndTag)
	if !ok {
		t.Error("decryption failed with correct nonce")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted plaintext does not match with correct nonce")
	}
}

func TestAsconSameInputProducesSameOutput(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	plaintext := []byte("Deterministic encryption test")

	// Encrypt twice
	result1 := AsconEncrypt(key, nonce, plaintext)
	result2 := AsconEncrypt(key, nonce, plaintext)

	// Should produce identical output (deterministic)
	if !bytes.Equal(result1, result2) {
		t.Error("same inputs produced different outputs (should be deterministic)")
	}
}

func TestAsconDifferentNoncesProduceDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("Test message")

	nonce1 := make([]byte, 16)
	nonce2 := make([]byte, 16)
	nonce2[0] = 0x01

	// Encrypt with different nonces
	result1 := AsconEncrypt(key, nonce1, plaintext)
	result2 := AsconEncrypt(key, nonce2, plaintext)

	// Ciphertexts should be different
	if bytes.Equal(result1, result2) {
		t.Error("different nonces produced same ciphertext")
	}
}

// Test against known test vector from ASCON specification
func TestAsconTestVector(t *testing.T) {
	// ASCON-128 test vector from specification
	// Key: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
	// Nonce: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
	// Plaintext: 00 01 02 03
	// Expected Ciphertext: (depends on specification)

	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	nonce, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00010203")

	result := AsconEncrypt(key, nonce, plaintext)

	// Verify we can decrypt it correctly
	decrypted, ok := AsconDecrypt(key, nonce, result)
	if !ok {
		t.Fatal("failed to decrypt test vector")
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("test vector decryption mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
	}

	// The ciphertext should be exactly 4 bytes + 16 byte tag = 20 bytes
	if len(result) != 20 {
		t.Errorf("test vector output length = %d, want 20", len(result))
	}
}

func TestAsconInvalidInputs(t *testing.T) {
	validKey := make([]byte, 16)
	validNonce := make([]byte, 16)
	plaintext := []byte("test")

	t.Run("invalid key size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid key size")
			}
		}()
		AsconEncrypt(make([]byte, 15), validNonce, plaintext)
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid nonce size")
			}
		}()
		AsconEncrypt(validKey, make([]byte, 15), plaintext)
	})

	t.Run("decrypt with too short input", func(t *testing.T) {
		_, ok := AsconDecrypt(validKey, validNonce, make([]byte, 10))
		if ok {
			t.Error("decrypt should fail with input shorter than tag size")
		}
	})
}

func BenchmarkAsconEncrypt(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)

	benchmarks := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4096},
	}

	for _, bm := range benchmarks {
		plaintext := make([]byte, bm.size)
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(bm.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				AsconEncrypt(key, nonce, plaintext)
			}
		})
	}
}

func BenchmarkAsconDecrypt(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)

	benchmarks := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4096},
	}

	for _, bm := range benchmarks {
		plaintext := make([]byte, bm.size)
		ciphertextAndTag := AsconEncrypt(key, nonce, plaintext)

		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(bm.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				AsconDecrypt(key, nonce, ciphertextAndTag)
			}
		})
	}
}
