package main

import (
	"testing"
)

// TestFeistelIntegration verifies that linker encryption and runtime decryption are compatible
func TestFeistelIntegration(t *testing.T) {
	seed := [32]byte{}
	copy(seed[:], "test_seed_for_feistel_cipher")

	keys := feistelKeysFromSeed(seed)

	testCases := []struct {
		value uint32
		tweak uint32
	}{
		{0x12345678, 0xABCDEF00},
		{0x00000000, 0x00000000},
		{0xFFFFFFFF, 0xFFFFFFFF},
		{0x80000000, 0x00000001},
		{100, 200},
	}

	for _, tc := range testCases {
		encrypted := feistelEncrypt32(tc.value, tc.tweak, keys)
		decrypted := feistelDecrypt32(encrypted, tc.tweak, keys)

		if decrypted != tc.value {
			t.Errorf("Feistel encrypt/decrypt failed: value=%08x tweak=%08x encrypted=%08x decrypted=%08x",
				tc.value, tc.tweak, encrypted, decrypted)
		}
	}
}
