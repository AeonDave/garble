// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"bytes"
	"testing"
)

func TestCacheEncryption(t *testing.T) {
	seed := []byte("test-seed-1234567890123456789012")

	// Create test cache
	original := &sharedCacheType{
		GOGARBLE: "test-pattern-sensitive",
		ListedPackages: map[string]*listedPackage{
			"example.com/main": {
				ImportPath: "example.com/main",
				Name:       "main",
				BuildID:    "test-build-id-12345",
			},
			"example.com/pkg": {
				ImportPath:  "example.com/pkg",
				Name:        "pkg",
				ToObfuscate: true,
			},
		},
		BuildNonce: []byte("build-nonce-123456"),
	}

	// Encrypt
	encrypted, err := encryptCacheWithASCON(original, seed)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify encrypted (no plaintext leakage)
	if bytes.Contains(encrypted, []byte("test-pattern")) {
		t.Error("plaintext 'test-pattern' leaked in encrypted cache")
	}
	if bytes.Contains(encrypted, []byte("example.com")) {
		t.Error("plaintext 'example.com' leaked in encrypted cache")
	}
	if bytes.Contains(encrypted, []byte("test-build-id")) {
		t.Error("plaintext 'test-build-id' leaked in encrypted cache")
	}
	if bytes.Contains(encrypted, []byte("build-nonce")) {
		t.Error("plaintext 'build-nonce' leaked in encrypted cache")
	}

	// Verify format: [nonce 16 bytes][ciphertext][tag 16 bytes]
	if len(encrypted) < 32 {
		t.Errorf("encrypted cache too short: %d bytes (expected at least 32)", len(encrypted))
	}

	// Decrypt
	decrypted, err := decryptCacheIntoShared(encrypted, seed)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify roundtrip
	if decrypted.GOGARBLE != original.GOGARBLE {
		t.Errorf("GOGARBLE mismatch: got %q, want %q", decrypted.GOGARBLE, original.GOGARBLE)
	}
	if len(decrypted.ListedPackages) != len(original.ListedPackages) {
		t.Errorf("ListedPackages count mismatch: got %d, want %d",
			len(decrypted.ListedPackages), len(original.ListedPackages))
	}
	if pkg := decrypted.ListedPackages["example.com/main"]; pkg == nil {
		t.Error("ListedPackages['example.com/main'] missing after decrypt")
	} else {
		if pkg.ImportPath != "example.com/main" {
			t.Errorf("ImportPath mismatch: got %q, want %q", pkg.ImportPath, "example.com/main")
		}
		if pkg.BuildID != "test-build-id-12345" {
			t.Errorf("BuildID mismatch: got %q, want %q", pkg.BuildID, "test-build-id-12345")
		}
	}

	t.Logf("✅ Cache encryption/decryption successful (%d bytes encrypted)", len(encrypted))
}

func TestCacheTamperingDetection(t *testing.T) {
	seed := []byte("test-seed-1234567890123456789012")
	original := &sharedCacheType{
		GOGARBLE: "test-data",
	}

	encrypted, err := encryptCacheWithASCON(original, seed)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Tamper with ciphertext (flip bit in middle of ciphertext)
	if len(encrypted) > 20 {
		tampered := make([]byte, len(encrypted))
		copy(tampered, encrypted)
		tampered[20] ^= 0x01 // Flip one bit

		// Should fail authentication
		_, err = decryptCacheIntoShared(tampered, seed)
		if err == nil {
			t.Error("tampering not detected! ASCON authentication failed")
		} else {
			t.Logf("✅ Tampering detected: %v", err)
		}
	}

	// Tamper with tag (last 16 bytes)
	if len(encrypted) > 16 {
		tamperedTag := make([]byte, len(encrypted))
		copy(tamperedTag, encrypted)
		tamperedTag[len(tamperedTag)-1] ^= 0xFF // Flip bits in tag

		_, err = decryptCacheIntoShared(tamperedTag, seed)
		if err == nil {
			t.Error("tag tampering not detected!")
		} else {
			t.Logf("✅ Tag tampering detected: %v", err)
		}
	}
}

func TestCacheKeyDerivation(t *testing.T) {
	seed1 := []byte("seed-1234567890123456789012345")
	seed2 := []byte("seed-9999999999999999999999999")

	key1 := deriveCacheKey(seed1)
	key2 := deriveCacheKey(seed2)

	// Different seeds should produce different keys
	if bytes.Equal(key1[:], key2[:]) {
		t.Error("different seeds produced same cache key!")
	}

	// Same seed should produce same key (deterministic)
	key1_again := deriveCacheKey(seed1)
	if !bytes.Equal(key1[:], key1_again[:]) {
		t.Error("same seed produced different keys (not deterministic)")
	}

	t.Logf("✅ Key derivation working correctly")
	t.Logf("   Seed 1 → Key: %x...", key1[:4])
	t.Logf("   Seed 2 → Key: %x...", key2[:4])
}

func TestCacheWrongKey(t *testing.T) {
	seed1 := []byte("correct-seed-123456789012345678")
	seed2 := []byte("wrong-seed-9999999999999999999999")

	original := &sharedCacheType{
		GOGARBLE: "secret-data",
	}

	// Encrypt with seed1
	encrypted, err := encryptCacheWithASCON(original, seed1)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Try to decrypt with wrong seed2
	_, err = decryptCacheIntoShared(encrypted, seed2)
	if err == nil {
		t.Error("decryption with wrong key should fail!")
	} else {
		t.Logf("✅ Wrong key rejected: %v", err)
	}

	// Decrypt with correct seed1 should work
	decrypted, err := decryptCacheIntoShared(encrypted, seed1)
	if err != nil {
		t.Errorf("decryption with correct key failed: %v", err)
	}
	if decrypted.GOGARBLE != "secret-data" {
		t.Errorf("data mismatch: got %q, want %q", decrypted.GOGARBLE, "secret-data")
	}
}

func TestCacheEmptyData(t *testing.T) {
	seed := []byte("test-seed-1234567890123456789012")

	// Encrypt empty cache
	empty := &sharedCacheType{
		ListedPackages: make(map[string]*listedPackage),
	}

	encrypted, err := encryptCacheWithASCON(empty, seed)
	if err != nil {
		t.Fatalf("encryption of empty cache failed: %v", err)
	}

	// Should still have nonce + tag (32 bytes minimum)
	if len(encrypted) < 32 {
		t.Errorf("encrypted empty cache too short: %d bytes", len(encrypted))
	}

	// Decrypt
	decrypted, err := decryptCacheIntoShared(encrypted, seed)
	if err != nil {
		t.Fatalf("decryption of empty cache failed: %v", err)
	}

	if len(decrypted.ListedPackages) != 0 {
		t.Errorf("expected empty ListedPackages, got %d entries", len(decrypted.ListedPackages))
	}

	t.Logf("✅ Empty cache encryption works (%d bytes)", len(encrypted))
}

func TestCacheEncryptionSeedSelection(t *testing.T) {
	originalFlag := flagCacheEncrypt
	originalSeed := flagSeed
	originalShared := sharedCache
	t.Cleanup(func() {
		flagCacheEncrypt = originalFlag
		flagSeed = originalSeed
		sharedCache = originalShared
	})

	// Case 1: Encryption disabled entirely
	flagCacheEncrypt = false
	sharedCache = &sharedCacheType{OriginalSeed: []byte("should-not-be-used")}
	flagSeed = seedFlag{bytes: []byte("should-not-be-used")}
	if got := cacheEncryptionSeed(); got != nil {
		t.Fatalf("expected nil seed when encryption disabled, got %x", got)
	}

	// Case 2: Shared cache provides canonical seed
	flagCacheEncrypt = true
	sharedSeed := []byte("shared-seed")
	sharedCache = &sharedCacheType{OriginalSeed: sharedSeed}
	flagSeed = seedFlag{bytes: []byte("fallback-seed")}
	if got := cacheEncryptionSeed(); !bytes.Equal(got, sharedSeed) {
		t.Fatalf("expected shared seed %q, got %x", sharedSeed, got)
	}

	// Case 3: Fall back to CLI seed when shared cache missing
	sharedCache = nil
	cliSeedRaw := []byte("cli-seed")
	flagSeed = seedFlag{bytes: cliSeedRaw}
	if got := cacheEncryptionSeed(); !bytes.Equal(got, cliSeedRaw) {
		t.Fatalf("expected CLI seed %q, got %x", cliSeedRaw, got)
	}

	// Case 4: No seeds available -> nil result
	flagSeed = seedFlag{}
	if got := cacheEncryptionSeed(); got != nil {
		t.Fatalf("expected nil when no seeds available, got %x", got)
	}
}
