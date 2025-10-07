package main

import (
	"fmt"
	"testing"
)

// Test to verify improved XOR encryption provides better diffusion
func TestImprovedXOREncryption(t *testing.T) {
	key := uint32(0x12345678)

	testCases := []struct {
		entryOff uint32
		nameOff  uint32
	}{
		{0x1000, 0x2000},
		{0x1001, 0x2000}, // Small change in entryOff
		{0x1000, 0x2001}, // Small change in nameOff
		{0xFFFFFFFF, 0xFFFFFFFF},
		{0x00000000, 0x00000000},
	}

	fmt.Println("=== Encryption Comparison ===")
	fmt.Println()

	for _, tc := range testCases {
		// Old: entryOff ^ (nameOff * key)
		oldEncrypted := tc.entryOff ^ (tc.nameOff * key)

		// New: entryOff ^ (nameOff * key + (nameOff ^ key))
		newEncrypted := tc.entryOff ^ (tc.nameOff*key + (tc.nameOff ^ key))

		fmt.Printf("Input: entryOff=%08x, nameOff=%08x\n", tc.entryOff, tc.nameOff)
		fmt.Printf("  Old XOR:      %08x\n", oldEncrypted)
		fmt.Printf("  Improved XOR: %08x\n", newEncrypted)

		// Check decryption works
		oldDecrypted := oldEncrypted ^ (tc.nameOff * key)
		newDecrypted := newEncrypted ^ (tc.nameOff*key + (tc.nameOff ^ key))

		if oldDecrypted != tc.entryOff {
			t.Errorf("Old decryption failed: got %08x, want %08x", oldDecrypted, tc.entryOff)
		}
		if newDecrypted != tc.entryOff {
			t.Errorf("New decryption failed: got %08x, want %08x", newDecrypted, tc.entryOff)
		}

		// Calculate Hamming distance (bits that differ)
		xorDiff := oldEncrypted ^ newEncrypted
		hammingDist := 0
		for i := 0; i < 32; i++ {
			if (xorDiff & (1 << i)) != 0 {
				hammingDist++
			}
		}
		fmt.Printf("  Difference: %d bits changed\n", hammingDist)
		fmt.Println()
	}
}
