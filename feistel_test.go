package main

import "testing"

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
