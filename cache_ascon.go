// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"

	"mvdan.cc/garble/internal/literals"
)

const (
	asconCacheNonceSize = 16
	asconCacheTagSize   = 16
)

// deriveCacheKey derives a 16-byte ASCON key from the user seed
// Uses domain separation to ensure cache keys are distinct from
// literal obfuscation keys and Feistel round keys
func deriveCacheKey(seed []byte) [16]byte {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("garble-cache-encryption-v1"))
	sum := h.Sum(nil)

	var key [16]byte
	copy(key[:], sum[:16])
	return key
}

// encryptCacheWithASCON encrypts the cache using ASCON-128 authenticated encryption
// Returns: [16-byte nonce][ciphertext][16-byte tag]
func encryptCacheWithASCON(data interface{}, seed []byte) ([]byte, error) {
	// 1. Serialize to bytes using gob
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return nil, fmt.Errorf("cache serialization failed: %v", err)
	}

	// 2. Derive encryption key from seed
	key := deriveCacheKey(seed)

	// 3. Generate random nonce (16 bytes for ASCON-128)
	nonce := make([]byte, asconCacheNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}

	// 4. Encrypt with ASCON-128 (includes authentication tag)
	ciphertext := literals.AsconEncrypt(key[:], nonce, buf.Bytes())

	// 5. Prepend nonce (needed for decryption)
	// Format: [nonce 16 bytes][ciphertext][tag 16 bytes]
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// decryptCacheIntoShared decrypts cache data directly into sharedCacheType
func decryptCacheIntoShared(encrypted []byte, seed []byte) (*sharedCacheType, error) {
	if len(encrypted) < asconCacheNonceSize {
		return nil, fmt.Errorf("invalid encrypted cache (too short: %d bytes)", len(encrypted))
	}

	// 1. Extract nonce and ciphertext+tag
	nonce := encrypted[:asconCacheNonceSize]
	ciphertextAndTag := encrypted[asconCacheNonceSize:]

	// 2. Derive decryption key
	key := deriveCacheKey(seed)

	// 3. Decrypt and verify
	plaintext, ok := literals.AsconDecrypt(key[:], nonce, ciphertextAndTag)
	if !ok {
		return nil, fmt.Errorf("decryption failed (cache tampered or wrong key)")
	}

	// 4. Deserialize directly into sharedCacheType
	var cache sharedCacheType
	if err := gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&cache); err != nil {
		return nil, fmt.Errorf("cache deserialization failed: %v", err)
	}

	return &cache, nil
}
