package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

const feistelRounds = 4

func feistelKeysFromSeed(seed [32]byte) [feistelRounds]uint32 {
	var keys [feistelRounds]uint32
	for i := 0; i < feistelRounds; i++ {
		hasher := sha256.New()
		hasher.Write(seed[:])
		hasher.Write([]byte{byte(i)})
		sum := hasher.Sum(nil)
		keys[i] = binary.LittleEndian.Uint32(sum[:4])
	}
	return keys
}

func feistelEncrypt32(value, tweak uint32, keys [feistelRounds]uint32) uint32 {
	left := uint16(value >> 16)
	right := uint16(value)
	for i := 0; i < feistelRounds; i++ {
		f := feistelRound(right, tweak, keys[i])
		left, right = right, left^f
	}
	return (uint32(left) << 16) | uint32(right)
}

func feistelDecrypt32(value, tweak uint32, keys [feistelRounds]uint32) uint32 {
	left := uint16(value >> 16)
	right := uint16(value)
	for round := feistelRounds - 1; round >= 0; round-- {
		f := feistelRound(left, tweak, keys[round])
		left, right = right^f, left
	}
	return (uint32(left) << 16) | uint32(right)
}

func feistelRound(right uint16, tweak uint32, key uint32) uint16 {
	x := uint32(right)
	x ^= tweak
	x += key*0x9e3779b1 + 0x7f4a7c15
	x = bits.RotateLeft32(x^key, int(key&31))
	x ^= x >> 16
	return uint16(x)
}
