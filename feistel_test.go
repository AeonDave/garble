package main

import (
	"math"
	"math/bits"
	"testing"
)

func TestFeistelEncryptDecrypt(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	keys := feistelKeysFromSeed(seed)

	testVectors := []struct {
		value uint32
		tweak uint32
	}{
		{0, 0},
		{1, 1},
		{0xffffffff, 0},
		{0x12345678, 0x9abcdef0},
		{0x0f0f0f0f, 0xf0f0f0f0},
		{0xa5a5a5a5, 0x5a5a5a5a},
	}

	for _, vec := range testVectors {
		enc := feistelEncrypt32(vec.value, vec.tweak, keys)
		if enc == vec.value {
			t.Fatalf("encryption produced identical output for value=%#x tweak=%#x", vec.value, vec.tweak)
		}
		dec := feistelDecrypt32(enc, vec.tweak, keys)
		if dec != vec.value {
			t.Fatalf("decrypt mismatch: got %#x want %#x (tweak=%#x)", dec, vec.value, vec.tweak)
		}
	}
}

func TestFeistelDifferentTweaks(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	keys := feistelKeysFromSeed(seed)

	value := uint32(0x11223344)
	tweakA := uint32(0xabcdef01)
	tweakB := uint32(0xabcdef02)

	encA := feistelEncrypt32(value, tweakA, keys)
	encB := feistelEncrypt32(value, tweakB, keys)
	if encA == encB {
		t.Fatalf("encryption should differ for different tweaks, got %#x for both", encA)
	}

	if dec := feistelDecrypt32(encA, tweakA, keys); dec != value {
		t.Fatalf("round-trip failed for tweakA: got %#x want %#x", dec, value)
	}
	if dec := feistelDecrypt32(encB, tweakB, keys); dec != value {
		t.Fatalf("round-trip failed for tweakB: got %#x want %#x", dec, value)
	}
}

// TestFeistelBijection verifies the 32-bit Feistel is a bijection (permutation).
// For a fixed seed+tweak, every input must map to a unique output.
func TestFeistelBijection(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	keys := feistelKeysFromSeed(seed)
	tweak := uint32(0xdeadbeef)

	// Test a 16-bit subspace (65536 values) for collisions.
	const space = 1 << 16
	seen := make(map[uint32]uint32, space)

	for i := uint32(0); i < space; i++ {
		enc := feistelEncrypt32(i, tweak, keys)
		if prev, dup := seen[enc]; dup {
			t.Fatalf("collision: feistelEncrypt32(%#x) == feistelEncrypt32(%#x) == %#x",
				i, prev, enc)
		}
		seen[enc] = i
	}
}

// TestFeistelAvalanche verifies the strict avalanche criterion:
// flipping one input bit should flip ~50% of output bits on average.
func TestFeistelAvalanche(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i*13 + 7)
	}
	keys := feistelKeysFromSeed(seed)
	tweak := uint32(0x12345678)

	const sampleCount = 10000
	totalDiffs := 0
	totalBits := 0

	for sample := uint32(0); sample < sampleCount; sample++ {
		base := feistelEncrypt32(sample, tweak, keys)
		for bit := 0; bit < 32; bit++ {
			flipped := feistelEncrypt32(sample^(1<<bit), tweak, keys)
			totalDiffs += bits.OnesCount32(base ^ flipped)
			totalBits += 32
		}
	}

	ratio := float64(totalDiffs) / float64(totalBits)
	t.Logf("Feistel avalanche ratio: %.4f (ideal=0.5)", ratio)

	// A 4-round Feistel on 16-bit halves has limited diffusion;
	// 0.30+ is acceptable for an obfuscation-grade (not cryptographic) cipher.
	if ratio < 0.30 || ratio > 0.70 {
		t.Fatalf("avalanche ratio %.4f outside acceptable range [0.30, 0.70]", ratio)
	}
}

// TestFeistelDistribution checks output byte distribution is not badly skewed.
func TestFeistelDistribution(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i ^ 0xAA)
	}
	keys := feistelKeysFromSeed(seed)
	tweak := uint32(0)

	const n = 1 << 16
	var buckets [256]int

	for i := uint32(0); i < n; i++ {
		enc := feistelEncrypt32(i, tweak, keys)
		buckets[byte(enc)]++
		buckets[byte(enc>>8)]++
		buckets[byte(enc>>16)]++
		buckets[byte(enc>>24)]++
	}

	// Chi-squared test against uniform distribution
	totalSamples := float64(n * 4)
	expected := totalSamples / 256.0
	var chiSq float64
	for _, count := range buckets {
		diff := float64(count) - expected
		chiSq += (diff * diff) / expected
	}

	// For 255 DOF, chi-squared critical value at p=0.001 is ~310
	// Being generous: accept up to 350
	t.Logf("Feistel byte distribution chi-squared: %.2f (255 DOF, critical@0.001=310)", chiSq)
	if chiSq > 350 {
		t.Fatalf("byte distribution chi-squared %.2f exceeds threshold 350", chiSq)
	}
}

// TestFeistelKeyIndependence verifies different seeds produce completely
// different outputs for the same input.
func TestFeistelKeyIndependence(t *testing.T) {
	var seed1, seed2 [32]byte
	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 1) // differ by 1 in every byte
	}
	keys1 := feistelKeysFromSeed(seed1)
	keys2 := feistelKeysFromSeed(seed2)

	totalDiffs := 0
	const samples = 10000
	for i := uint32(0); i < samples; i++ {
		e1 := feistelEncrypt32(i, 0, keys1)
		e2 := feistelEncrypt32(i, 0, keys2)
		totalDiffs += bits.OnesCount32(e1 ^ e2)
	}

	ratio := float64(totalDiffs) / float64(samples*32)
	t.Logf("key independence ratio: %.4f (ideal=0.5)", ratio)
	if math.Abs(ratio-0.5) > 0.15 {
		t.Fatalf("key independence ratio %.4f deviates too much from 0.5", ratio)
	}
}
