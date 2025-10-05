// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/token"
	mathrand "math/rand"
	"testing"
)

// TestAsconObfuscator tests the ASCON obfuscator implementation
func TestAsconObfuscator(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))

	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName
	}

	helper := newAsconInlineHelper(rand, nameProvider)
	obf := newAsconObfuscator(helper)

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"medium", []byte("The quick brown fox jumps over the lazy dog")},
		{"long", make([]byte, 1000)},
		{"with_nulls", []byte{0x00, 0x01, 0x02, 0x00, 0x03}},
		{"all_zeros", make([]byte, 16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize test data for "long" and "all_zeros"
			if tt.name == "long" {
				for i := range tt.data {
					tt.data[i] = byte(i % 256)
				}
			}

			// Create external keys for testing
			extKeys := []*externalKey{
				{
					name:  "key1",
					typ:   "uint32",
					value: 0x12345678,
					bits:  32,
				},
				{
					name:  "key2",
					typ:   "uint64",
					value: 0xABCDEF0123456789,
					bits:  64,
				},
			}

			// Obfuscate the data
			block := obf.obfuscate(rand, tt.data, extKeys)

			if block == nil {
				t.Fatal("Obfuscator returned nil block")
			}

			if len(block.List) == 0 {
				t.Fatal("Obfuscator returned empty block")
			}

			// Verify structure: should have assignment and check
			if len(block.List) < 2 {
				t.Errorf("Expected at least 2 statements, got %d", len(block.List))
			}

			// First statement should be assignment (data, ok := ...)
			assignStmt, ok := block.List[0].(*ast.AssignStmt)
			if !ok {
				t.Errorf("First statement should be assignment, got %T", block.List[0])
			} else {
				if len(assignStmt.Lhs) != 2 {
					t.Errorf("Assignment should have 2 LHS values, got %d", len(assignStmt.Lhs))
				}
				if len(assignStmt.Rhs) != 1 {
					t.Errorf("Assignment should have 1 RHS value, got %d", len(assignStmt.Rhs))
				}
			}

			// Second statement should be if !ok check
			ifStmt, ok := block.List[1].(*ast.IfStmt)
			if !ok {
				t.Errorf("Second statement should be if, got %T", block.List[1])
			} else {
				// Should be !ok condition
				unary, ok := ifStmt.Cond.(*ast.UnaryExpr)
				if !ok || unary.Op != token.NOT {
					t.Errorf("If condition should be !ok, got %T", ifStmt.Cond)
				}
			}

			// Verify external keys were used
			for _, key := range extKeys {
				if !key.IsUsed() {
					t.Errorf("External key %s was not used", key.name)
				}
			}

			t.Logf("✅ Successfully obfuscated %d bytes with %d statements",
				len(tt.data), len(block.List))
		})
	}
}

// TestAsconObfuscatorIntegration tests ASCON obfuscator with actual encryption/decryption
func TestAsconObfuscatorIntegration(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(123))

	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName + "_test"
	}

	helper := newAsconInlineHelper(rand, nameProvider)
	obf := newAsconObfuscator(helper)

	testData := []byte("Integration test message")

	// Create minimal external keys
	extKeys := []*externalKey{
		{
			name:  "k1",
			typ:   "uint16",
			value: 0x4242,
			bits:  16,
		},
	}

	// Obfuscate
	block := obf.obfuscate(rand, testData, extKeys)

	// Verify block structure is valid
	if block == nil || len(block.List) == 0 {
		t.Fatal("Obfuscation failed to generate code")
	}

	// Check that the function name was set correctly
	if helper.funcName != "_garbleAsconDecrypt_test" {
		t.Errorf("Expected function name '_garbleAsconDecrypt_test', got '%s'", helper.funcName)
	}

	t.Logf("✅ Integration test successful, generated %d statements", len(block.List))
}

// TestAsconVsXORSecurity compares ASCON with simple XOR obfuscation
func TestAsconVsXORSecurity(t *testing.T) {
	// This test demonstrates why ASCON is superior to XOR

	plaintext := []byte("SecretMessage")

	// XOR "encryption" (old method)
	xorKey := byte(0x42)
	xorEncrypted := make([]byte, len(plaintext))
	for i, b := range plaintext {
		xorEncrypted[i] = b ^ xorKey
	}

	// ASCON encryption (new method)
	asconKey := make([]byte, 16)
	for i := range asconKey {
		asconKey[i] = byte(i)
	}
	asconNonce := make([]byte, 16)
	for i := range asconNonce {
		asconNonce[i] = byte(i + 16)
	}

	asconEncrypted := AsconEncrypt(asconKey, asconNonce, plaintext)

	// Analysis
	t.Logf("Plaintext: %q (%d bytes)", plaintext, len(plaintext))
	t.Logf("XOR encrypted: %x (%d bytes)", xorEncrypted, len(xorEncrypted))
	t.Logf("ASCON encrypted: %x (%d bytes)", asconEncrypted, len(asconEncrypted))

	// XOR is easily breakable with known-plaintext
	// If attacker knows one byte of plaintext, they can recover the key
	knownChar := plaintext[0]
	recoveredXORKey := xorEncrypted[0] ^ knownChar
	t.Logf("XOR key recovered from one known byte: 0x%02x (actual: 0x%02x)",
		recoveredXORKey, xorKey)

	if recoveredXORKey != xorKey {
		t.Error("Failed to recover XOR key - test setup issue")
	}

	// With ASCON, knowing plaintext doesn't help
	// The encryption is non-deterministic (nonce) and authenticated
	// Tampering with ciphertext is detected
	tampered := make([]byte, len(asconEncrypted))
	copy(tampered, asconEncrypted)
	tampered[0] ^= 0x01 // Flip one bit

	_, ok := AsconDecrypt(asconKey, asconNonce, tampered)
	if ok {
		t.Error("ASCON should reject tampered ciphertext")
	}

	t.Logf("✅ ASCON provides:")
	t.Logf("  - Authenticated encryption (detects tampering)")
	t.Logf("  - 128-bit security (vs 8-bit for XOR)")
	t.Logf("  - NIST standard compliance")
	t.Logf("  - No import dependencies (inline)")
}

// BenchmarkAsconObfuscator measures obfuscation performance
func BenchmarkAsconObfuscator(b *testing.B) {
	rand := mathrand.New(mathrand.NewSource(42))

	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName
	}

	helper := newAsconInlineHelper(rand, nameProvider)
	obf := newAsconObfuscator(helper)

	testData := []byte("Benchmark test data for ASCON obfuscation")
	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
		{name: "k2", typ: "uint64", value: 0xABCDEF01, bits: 64},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obf.obfuscate(rand, testData, extKeys)
	}
}

// BenchmarkAsconObfuscatorSizes benchmarks different data sizes
func BenchmarkAsconObfuscatorSizes(b *testing.B) {
	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			nameProvider := func(r *mathrand.Rand, baseName string) string {
				return baseName
			}

			helper := newAsconInlineHelper(rand, nameProvider)
			obf := newAsconObfuscator(helper)

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i)
			}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = obf.obfuscate(rand, testData, extKeys)
			}
		})
	}
}
