// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

// ASCON-128 Authenticated Encryption
// Based on the NIST Lightweight Cryptography standard winner (2023)
// Specification: https://ascon.iaik.tugraz.at/
//
// This implementation provides ASCON-128 in a simple, inline-friendly format
// suitable for code generation in garble's literal obfuscation.
//
// ASCON-128 Parameters:
// - Key size: 128 bits (16 bytes)
// - Nonce size: 128 bits (16 bytes)
// - Tag size: 128 bits (16 bytes)
// - Security level: 128-bit

const (
	asconKeySize   = 16 // 128 bits
	asconNonceSize = 16 // 128 bits
	asconTagSize   = 16 // 128 bits
	asconRate      = 8  // 64 bits per block
)

// ASCON-128 initialization vector
var asconIV = uint64(0x80400c0600000000)

// asconState represents the 320-bit (5x64) ASCON permutation state
type asconState [5]uint64

// rotateRight performs right rotation of a 64-bit value
func rotateRight(x uint64, n int) uint64 {
	return (x >> n) | (x << (64 - n))
}

// asconPermutation performs the ASCON permutation with 'rounds' rounds
// This is the core cryptographic primitive of ASCON
func (s *asconState) permute(rounds int) {
	for i := 0; i < rounds; i++ {
		// Addition of round constant
		s[2] ^= uint64(0xf0 - uint64(i)*0x10 + uint64(i)*0x1)

		// Substitution layer (5-bit S-box applied to each bit position)
		s[0] ^= s[4]
		s[4] ^= s[3]
		s[2] ^= s[1]

		t0 := s[0]
		t1 := s[1]
		t2 := s[2]
		t3 := s[3]
		t4 := s[4]

		s[0] = t0 ^ (^t1 & t2)
		s[1] = t1 ^ (^t2 & t3)
		s[2] = t2 ^ (^t3 & t4)
		s[3] = t3 ^ (^t4 & t0)
		s[4] = t4 ^ (^t0 & t1)

		s[1] ^= s[0]
		s[0] ^= s[4]
		s[3] ^= s[2]
		s[2] = ^s[2]

		// Linear diffusion layer
		s[0] ^= rotateRight(s[0], 19) ^ rotateRight(s[0], 28)
		s[1] ^= rotateRight(s[1], 61) ^ rotateRight(s[1], 39)
		s[2] ^= rotateRight(s[2], 1) ^ rotateRight(s[2], 6)
		s[3] ^= rotateRight(s[3], 10) ^ rotateRight(s[3], 17)
		s[4] ^= rotateRight(s[4], 7) ^ rotateRight(s[4], 41)
	}
}

// bytesToUint64 converts 8 bytes to uint64 (big-endian)
func bytesToUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// uint64ToBytes converts uint64 to 8 bytes (big-endian)
func uint64ToBytes(x uint64, b []byte) {
	b[0] = byte(x >> 56)
	b[1] = byte(x >> 48)
	b[2] = byte(x >> 40)
	b[3] = byte(x >> 32)
	b[4] = byte(x >> 24)
	b[5] = byte(x >> 16)
	b[6] = byte(x >> 8)
	b[7] = byte(x)
}

// asconInitialize initializes the ASCON state with key and nonce
func asconInitialize(key, nonce []byte) asconState {
	var s asconState

	// Initialize state with IV, Key, and Nonce
	s[0] = asconIV
	s[1] = bytesToUint64(key[0:8])
	s[2] = bytesToUint64(key[8:16])
	s[3] = bytesToUint64(nonce[0:8])
	s[4] = bytesToUint64(nonce[8:16])

	// Initial permutation with 12 rounds (p^12)
	s.permute(12)

	// XOR key at the end
	s[3] ^= bytesToUint64(key[0:8])
	s[4] ^= bytesToUint64(key[8:16])

	return s
}

// asconFinalize generates the authentication tag
func asconFinalize(s *asconState, key []byte) []byte {
	// XOR key
	s[1] ^= bytesToUint64(key[0:8])
	s[2] ^= bytesToUint64(key[8:16])

	// Final permutation with 12 rounds (p^12)
	s.permute(12)

	// Extract tag
	s[3] ^= bytesToUint64(key[0:8])
	s[4] ^= bytesToUint64(key[8:16])

	tag := make([]byte, asconTagSize)
	uint64ToBytes(s[3], tag[0:8])
	uint64ToBytes(s[4], tag[8:16])

	return tag
}

// AsconEncrypt performs ASCON-128 authenticated encryption
// Returns: ciphertext || tag (ciphertext length = plaintext length, tag = 16 bytes)
func AsconEncrypt(key, nonce, plaintext []byte) []byte {
	if len(key) != asconKeySize {
		panic("ascon: invalid key size")
	}
	if len(nonce) != asconNonceSize {
		panic("ascon: invalid nonce size")
	}

	// Initialize state
	s := asconInitialize(key, nonce)

	// Domain separation: required by ASCON-128 spec before processing payload
	// This is needed even with empty Associated Data (AD)
	s[4] ^= 1

	// Process plaintext (encryption)
	ciphertext := make([]byte, len(plaintext))
	offset := 0

	// Process complete 8-byte blocks
	for offset+asconRate <= len(plaintext) {
		// XOR plaintext block with state
		block := bytesToUint64(plaintext[offset : offset+asconRate])
		s[0] ^= block

		// Extract ciphertext
		uint64ToBytes(s[0], ciphertext[offset:offset+asconRate])

		// Permutation with 6 rounds (p^6)
		s.permute(6)

		offset += asconRate
	}

	// Process final partial block if any
	if offset < len(plaintext) {
		remaining := len(plaintext) - offset

		// Pad the plaintext block
		var paddedBlock [8]byte
		copy(paddedBlock[:], plaintext[offset:])
		paddedBlock[remaining] = 0x80

		// XOR padded plaintext with state
		s[0] ^= bytesToUint64(paddedBlock[:])

		// Extract ciphertext (only the non-padding part)
		var ciphertextBlock [8]byte
		uint64ToBytes(s[0], ciphertextBlock[:])
		copy(ciphertext[offset:], ciphertextBlock[:remaining])
	} else {
		// Empty final block - apply domain separation
		s[0] ^= 0x8000000000000000
	}

	// Finalization - generate tag
	tag := asconFinalize(&s, key)

	// Return ciphertext || tag
	result := make([]byte, len(ciphertext)+asconTagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)

	return result
}

// AsconDecrypt performs ASCON-128 authenticated decryption
// Input: ciphertext || tag
// Returns: plaintext, success (false if authentication fails)
func AsconDecrypt(key, nonce, ciphertextAndTag []byte) ([]byte, bool) {
	if len(key) != asconKeySize {
		panic("ascon: invalid key size")
	}
	if len(nonce) != asconNonceSize {
		panic("ascon: invalid nonce size")
	}
	if len(ciphertextAndTag) < asconTagSize {
		return nil, false
	}

	// Split ciphertext and tag
	ciphertextLen := len(ciphertextAndTag) - asconTagSize
	ciphertext := ciphertextAndTag[:ciphertextLen]
	receivedTag := ciphertextAndTag[ciphertextLen:]

	// Initialize state
	s := asconInitialize(key, nonce)

	// Domain separation: required by ASCON-128 spec before processing payload
	// This is needed even with empty Associated Data (AD)
	s[4] ^= 1

	// Process ciphertext (decryption)
	plaintext := make([]byte, len(ciphertext))
	offset := 0

	// Process complete 8-byte blocks
	for offset+asconRate <= len(ciphertext) {
		// Extract ciphertext block
		ciphertextBlock := bytesToUint64(ciphertext[offset : offset+asconRate])

		// XOR with state to get plaintext
		plaintextBlock := s[0] ^ ciphertextBlock
		uint64ToBytes(plaintextBlock, plaintext[offset:offset+asconRate])

		// Update state with ciphertext
		s[0] = ciphertextBlock

		// Permutation with 6 rounds (p^6)
		s.permute(6)

		offset += asconRate
	}

	// Process final partial block if any
	if offset < len(ciphertext) {
		remaining := len(ciphertext) - offset

		// Get state as bytes for XOR
		var stateBytes [8]byte
		uint64ToBytes(s[0], stateBytes[:])

		// Decrypt: plaintext = ciphertext XOR state (only the ciphertext bytes)
		var plaintextBlock [8]byte
		for i := 0; i < remaining; i++ {
			plaintextBlock[i] = ciphertext[offset+i] ^ stateBytes[i]
			plaintext[offset+i] = plaintextBlock[i]
		}

		// Add padding for tag computation
		plaintextBlock[remaining] = 0x80

		// Reconstruct what was XORed during encryption for tag verification
		// state_new = state_old XOR (plaintext || 0x80 || padding)
		s[0] ^= bytesToUint64(plaintextBlock[:])
	} else {
		// Empty final block - apply domain separation
		s[0] ^= 0x8000000000000000
	}

	// Finalization - compute expected tag
	expectedTag := asconFinalize(&s, key)

	// Constant-time tag comparison (branchless to prevent timing attacks)
	var diff byte
	for i := 0; i < asconTagSize; i++ {
		diff |= receivedTag[i] ^ expectedTag[i]
	}
	tagMatch := diff == 0

	if !tagMatch {
		// Authentication failed - clear plaintext for security
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, false
	}

	return plaintext, true
}
