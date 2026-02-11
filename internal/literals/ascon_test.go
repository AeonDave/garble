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

// TestAsconNISTKATVectors validates ASCON-128 against reference test vectors
// generated by the official pyascon implementation (https://github.com/meichlseder/pyascon).
// These are Known Answer Tests (KAT) — if any vector fails, our ASCON-128
// implementation diverges from the NIST LWC standard.
func TestAsconNISTKATVectors(t *testing.T) {
	vectors := []struct {
		name      string
		key       string
		nonce     string
		plaintext string
		expected  string // ciphertext || tag (hex)
	}{
		{
			name:      "TV1_empty_plaintext",
			key:       "00000000000000000000000000000000",
			nonce:     "00000000000000000000000000000000",
			plaintext: "",
			expected:  "42213f50a811d2d1d7e4092aa2a42ba4",
		},
		{
			name:      "TV2_4byte_plaintext",
			key:       "000102030405060708090a0b0c0d0e0f",
			nonce:     "000102030405060708090a0b0c0d0e0f",
			plaintext: "00010203",
			expected:  "bc820dbd218c5c93e3850e974a3704d1223bdefb",
		},
		{
			name:      "TV3_16byte_plaintext",
			key:       "000102030405060708090a0b0c0d0e0f",
			nonce:     "000102030405060708090a0b0c0d0e0f",
			plaintext: "000102030405060708090a0b0c0d0e0f",
			expected:  "bc820dbdf7a4631c5b29884ad69175c3f58e28436dd71556d58dfa56ac890beb",
		},
	}

	for _, tv := range vectors {
		t.Run(tv.name, func(t *testing.T) {
			key, err := hex.DecodeString(tv.key)
			if err != nil {
				t.Fatalf("bad key hex: %v", err)
			}
			nonce, err := hex.DecodeString(tv.nonce)
			if err != nil {
				t.Fatalf("bad nonce hex: %v", err)
			}
			plaintext, err := hex.DecodeString(tv.plaintext)
			if err != nil {
				t.Fatalf("bad plaintext hex: %v", err)
			}
			expected, err := hex.DecodeString(tv.expected)
			if err != nil {
				t.Fatalf("bad expected hex: %v", err)
			}

			got := AsconEncrypt(key, nonce, plaintext)

			if !bytes.Equal(got, expected) {
				t.Fatalf("ASCON-128 KAT mismatch\n  key:       %s\n  nonce:     %s\n  plaintext: %s\n  got:       %x\n  want:      %x",
					tv.key, tv.nonce, tv.plaintext, got, expected)
			}

			// Verify roundtrip
			decrypted, ok := AsconDecrypt(key, nonce, got)
			if !ok {
				t.Fatal("KAT roundtrip: decrypt returned !ok")
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("KAT roundtrip mismatch\n  got:  %x\n  want: %x", decrypted, plaintext)
			}
		})
	}
}

// TestAsconTagForgeryResistance verifies that flipping any single bit in the
// ciphertext+tag causes authentication failure. This is a basic forgery test.
func TestAsconTagForgeryResistance(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
	}

	plaintext := []byte("Forgery resistance test message!")
	ct := AsconEncrypt(key, nonce, plaintext)

	for bitPos := 0; bitPos < len(ct)*8; bitPos++ {
		tampered := append([]byte(nil), ct...)
		tampered[bitPos/8] ^= 1 << (bitPos % 8)

		_, ok := AsconDecrypt(key, nonce, tampered)
		if ok {
			t.Fatalf("forgery accepted: flipping bit %d in ciphertext+tag was not detected", bitPos)
		}
	}
}

// TestAsconAvalancheEffect verifies that a single-bit change in the plaintext
// causes significant change in the full output (ciphertext + tag).
func TestAsconAvalancheEffect(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	plaintext := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range nonce {
		nonce[i] = byte(i * 7)
	}

	base := AsconEncrypt(key, nonce, plaintext)

	totalBitDiffs := 0
	totalBitsCompared := 0

	for bitPos := 0; bitPos < len(plaintext)*8; bitPos++ {
		modified := append([]byte(nil), plaintext...)
		modified[bitPos/8] ^= 1 << (bitPos % 8)

		result := AsconEncrypt(key, nonce, modified)

		// Compare the full output including tag (authenticated cipher)
		for i := 0; i < len(base); i++ {
			diff := base[i] ^ result[i]
			for diff != 0 {
				totalBitDiffs++
				diff &= diff - 1
			}
		}
		totalBitsCompared += len(base) * 8
	}

	ratio := float64(totalBitDiffs) / float64(totalBitsCompared)
	t.Logf("avalanche ratio (CT+tag): %.4f (%d/%d bits differ)", ratio, totalBitDiffs, totalBitsCompared)
	// ASCON is a streaming cipher: bit changes only propagate forward through
	// subsequent blocks + tag. A ratio >= 0.25 is expected for CT+tag combined.
	if ratio < 0.25 {
		t.Fatalf("avalanche effect too weak: %.4f (want >= 0.25)", ratio)
	}
}

// FuzzAsconEncryptDecrypt fuzzes the ASCON encrypt/decrypt roundtrip with
// arbitrary keys, nonces, and plaintexts.
func FuzzAsconEncryptDecrypt(f *testing.F) {
	// Seed corpus
	f.Add(make([]byte, 16), make([]byte, 16), []byte("hello"))
	f.Add(bytes.Repeat([]byte{0xff}, 16), bytes.Repeat([]byte{0xff}, 16), []byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		[]byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		[]byte("The quick brown fox jumps over the lazy dog"))

	f.Fuzz(func(t *testing.T, key, nonce, plaintext []byte) {
		if len(key) != 16 || len(nonce) != 16 {
			t.Skip()
		}

		ct := AsconEncrypt(key, nonce, plaintext)

		// Length invariant: ciphertext = plaintext + 16 byte tag
		if len(ct) != len(plaintext)+16 {
			t.Fatalf("output length %d, want %d", len(ct), len(plaintext)+16)
		}

		// Roundtrip invariant
		pt, ok := AsconDecrypt(key, nonce, ct)
		if !ok {
			t.Fatal("decrypt returned !ok for valid ciphertext")
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("roundtrip mismatch:\n  got:  %x\n  want: %x", pt, plaintext)
		}

		// Wrong key must fail
		wrongKey := append([]byte(nil), key...)
		wrongKey[0] ^= 0x01
		if _, ok := AsconDecrypt(wrongKey, nonce, ct); ok {
			t.Fatal("decrypt succeeded with wrong key")
		}
	})
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
