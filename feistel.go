// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"encoding/binary"
	"hash/fnv"
)

// feistelRound applies a single Feistel round.
// F(R, K) = hash(R || K) truncated to 32 bits
func feistelRound(right uint32, key []byte) uint32 {
	h := fnv.New32a()
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], right)
	h.Write(buf[:])
	h.Write(key)
	return h.Sum32()
}

// feistelEncrypt applies a 4-round Feistel cipher to encrypt a 64-bit value.
// The input is split into left (high 32 bits) and right (low 32 bits).
// Returns the encrypted 64-bit value.
//
// Feistel structure:
//
//	For each round i:
//	  newLeft = right
//	  newRight = left XOR F(right, key[i])
//
// This is a balanced Feistel network - both halves get transformed.
func feistelEncrypt(value uint64, keys [4][]byte) uint64 {
	left := uint32(value >> 32)
	right := uint32(value & 0xFFFFFFFF)

	for i := 0; i < 4; i++ {
		newLeft := right
		newRight := left ^ feistelRound(right, keys[i])
		left = newLeft
		right = newRight
	}

	return (uint64(left) << 32) | uint64(right)
}

// feistelDecrypt applies a 4-round Feistel cipher to decrypt a 64-bit value.
// The decryption process uses the same round function but in reverse order.
func feistelDecrypt(value uint64, keys [4][]byte) uint64 {
	left := uint32(value >> 32)
	right := uint32(value & 0xFFFFFFFF)

	// Apply rounds in reverse order for decryption
	for i := 3; i >= 0; i-- {
		newRight := left
		newLeft := right ^ feistelRound(left, keys[i])
		left = newLeft
		right = newRight
	}

	return (uint64(left) << 32) | uint64(right)
}

// deriveFeistelKeys derives 4 round keys from a base seed.
// Each key is derived by hashing: seed || "round_N"
func deriveFeistelKeys(baseSeed []byte) [4][]byte {
	var keys [4][]byte
	for i := range 4 {
		h := fnv.New32a()
		h.Write(baseSeed)
		h.Write([]byte("round_"))
		h.Write([]byte{byte('0' + i)})
		sum := h.Sum(nil)
		keys[i] = sum
	}
	return keys
}

// feistelEncrypt32Pair encrypts two uint32 values as a single 64-bit block.
// This is useful for encrypting (entryOff, nameOff) pairs.
func feistelEncrypt32Pair(left, right uint32, keys [4][]byte) (uint32, uint32) {
	value := (uint64(left) << 32) | uint64(right)
	encrypted := feistelEncrypt(value, keys)
	return uint32(encrypted >> 32), uint32(encrypted & 0xFFFFFFFF)
}

// feistelDecrypt32Pair decrypts two uint32 values from a single 64-bit block.
func feistelDecrypt32Pair(left, right uint32, keys [4][]byte) (uint32, uint32) {
	value := (uint64(left) << 32) | uint64(right)
	decrypted := feistelDecrypt(value, keys)
	return uint32(decrypted >> 32), uint32(decrypted & 0xFFFFFFFF)
}
