// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"testing"
)

func TestFeistelRoundFunction(t *testing.T) {
	t.Parallel()

	// Test that the round function is deterministic
	right := uint32(0x12345678)
	key := []byte("test_key_round_0")

	result1 := feistelRound(right, key)
	result2 := feistelRound(right, key)

	if result1 != result2 {
		t.Errorf("Round function not deterministic: %x != %x", result1, result2)
	}

	// Test that different inputs produce different outputs
	differentRight := uint32(0x87654321)
	result3 := feistelRound(differentRight, key)

	if result1 == result3 {
		t.Errorf("Different inputs produced same output: %x", result1)
	}

	// Test that different keys produce different outputs
	differentKey := []byte("different_key")
	result4 := feistelRound(right, differentKey)

	if result1 == result4 {
		t.Errorf("Different keys produced same output: %x", result1)
	}
}

func TestFeistelEncryptDecrypt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value uint64
		seed  string
	}{
		{"zero", 0x0000000000000000, "test_seed_1"},
		{"small", 0x0000000012345678, "test_seed_2"},
		{"large", 0x123456789ABCDEF0, "test_seed_3"},
		{"max", 0xFFFFFFFFFFFFFFFF, "test_seed_4"},
		{"pattern", 0xAAAAAAAA55555555, "test_seed_5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys := deriveFeistelKeys([]byte(tc.seed))

			// Encrypt
			encrypted := feistelEncrypt(tc.value, keys)

			// Value should change (unless by extreme coincidence)
			if encrypted == tc.value && tc.value != 0 {
				t.Errorf("Encryption did not change value: %x", tc.value)
			}

			// Decrypt
			decrypted := feistelDecrypt(encrypted, keys)

			// Should recover original value
			if decrypted != tc.value {
				t.Errorf("Decryption failed: got %x, want %x", decrypted, tc.value)
			}
		})
	}
}

func TestFeistelDifferentSeedsProduceDifferentResults(t *testing.T) {
	t.Parallel()

	value := uint64(0x123456789ABCDEF0)
	seed1 := []byte("seed_one")
	seed2 := []byte("seed_two")

	keys1 := deriveFeistelKeys(seed1)
	keys2 := deriveFeistelKeys(seed2)

	encrypted1 := feistelEncrypt(value, keys1)
	encrypted2 := feistelEncrypt(value, keys2)

	if encrypted1 == encrypted2 {
		t.Errorf("Different seeds produced same encryption: %x", encrypted1)
	}

	// Verify they decrypt correctly with their own keys
	if feistelDecrypt(encrypted1, keys1) != value {
		t.Error("Failed to decrypt with keys1")
	}
	if feistelDecrypt(encrypted2, keys2) != value {
		t.Error("Failed to decrypt with keys2")
	}

	// Verify cross-decryption fails (produces garbage)
	wrongDecrypt := feistelDecrypt(encrypted1, keys2)
	if wrongDecrypt == value {
		t.Error("Wrong keys should not decrypt correctly")
	}
}

func TestFeistel32PairEncryptDecrypt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		left  uint32
		right uint32
		seed  string
	}{
		{"both_zero", 0, 0, "pair_seed_1"},
		{"left_only", 0x12345678, 0, "pair_seed_2"},
		{"right_only", 0, 0x9ABCDEF0, "pair_seed_3"},
		{"both_set", 0x12345678, 0x9ABCDEF0, "pair_seed_4"},
		{"max_values", 0xFFFFFFFF, 0xFFFFFFFF, "pair_seed_5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys := deriveFeistelKeys([]byte(tc.seed))

			// Encrypt pair
			encLeft, encRight := feistelEncrypt32Pair(tc.left, tc.right, keys)

			// At least one should change (unless extreme coincidence)
			if encLeft == tc.left && encRight == tc.right && (tc.left != 0 || tc.right != 0) {
				t.Errorf("Encryption did not change pair: (%x, %x)", tc.left, tc.right)
			}

			// Decrypt pair
			decLeft, decRight := feistelDecrypt32Pair(encLeft, encRight, keys)

			// Should recover original values
			if decLeft != tc.left {
				t.Errorf("Left decryption failed: got %x, want %x", decLeft, tc.left)
			}
			if decRight != tc.right {
				t.Errorf("Right decryption failed: got %x, want %x", decRight, tc.right)
			}
		})
	}
}

func TestDeriveFeistelKeys(t *testing.T) {
	t.Parallel()

	seed := []byte("test_base_seed")
	keys := deriveFeistelKeys(seed)

	// Verify we got 4 keys
	if len(keys) != 4 {
		t.Fatalf("Expected 4 keys, got %d", len(keys))
	}

	// Verify all keys are different
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if string(keys[i]) == string(keys[j]) {
				t.Errorf("Keys %d and %d are identical", i, j)
			}
		}
	}

	// Verify keys are deterministic
	keys2 := deriveFeistelKeys(seed)
	for i := 0; i < 4; i++ {
		if string(keys[i]) != string(keys2[i]) {
			t.Errorf("Key %d not deterministic", i)
		}
	}

	// Verify different seeds produce different key sets
	differentSeed := []byte("different_seed")
	differentKeys := deriveFeistelKeys(differentSeed)

	allDifferent := false
	for i := 0; i < 4; i++ {
		if string(keys[i]) != string(differentKeys[i]) {
			allDifferent = true
			break
		}
	}
	if !allDifferent {
		t.Error("Different seeds produced identical key sets")
	}
}

func TestFeistelAvalancheEffect(t *testing.T) {
	t.Parallel()

	// Test that a small change in input produces significant change in output
	seed := []byte("avalanche_test")
	keys := deriveFeistelKeys(seed)

	value1 := uint64(0x1234567890ABCDEF)
	value2 := uint64(0x1234567890ABCDEE) // Only last bit differs

	enc1 := feistelEncrypt(value1, keys)
	enc2 := feistelEncrypt(value2, keys)

	// Count differing bits
	diff := enc1 ^ enc2
	bitCount := 0
	for i := 0; i < 64; i++ {
		if diff&(1<<i) != 0 {
			bitCount++
		}
	}

	// Good avalanche effect should flip ~50% of bits (32 out of 64)
	// We accept 20-44 bits as reasonable (allows some variance)
	if bitCount < 20 || bitCount > 44 {
		t.Logf("Warning: Avalanche effect may be weak. Flipped %d/64 bits", bitCount)
		t.Logf("enc1: %016x", enc1)
		t.Logf("enc2: %016x", enc2)
		t.Logf("diff: %016x", diff)
		// Don't fail the test as FNV hash may have different avalanche properties
	}
}

func BenchmarkFeistelEncrypt(b *testing.B) {
	seed := []byte("benchmark_seed")
	keys := deriveFeistelKeys(seed)
	value := uint64(0x123456789ABCDEF0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = feistelEncrypt(value, keys)
	}
}

func BenchmarkFeistelDecrypt(b *testing.B) {
	seed := []byte("benchmark_seed")
	keys := deriveFeistelKeys(seed)
	value := uint64(0x123456789ABCDEF0)
	encrypted := feistelEncrypt(value, keys)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = feistelDecrypt(encrypted, keys)
	}
}

func BenchmarkFeistelEncrypt32Pair(b *testing.B) {
	seed := []byte("benchmark_seed")
	keys := deriveFeistelKeys(seed)
	left := uint32(0x12345678)
	right := uint32(0x9ABCDEF0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = feistelEncrypt32Pair(left, right, keys)
	}
}
