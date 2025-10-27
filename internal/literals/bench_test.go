package literals

import (
	"fmt"
	mathrand "math/rand"
	"testing"
)

// BenchmarkObfuscatorPerformance compares all obfuscators with various sizes
func BenchmarkObfuscatorPerformance(b *testing.B) {
	sizes := []int{16, 64, 128, 256, 512, 1024, 2048}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("ASCON_%dB", size), func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			nameProvider := func(r *mathrand.Rand, baseName string) string {
				return baseName
			}

			helper := newAsconInlineHelper(rand, nameProvider)
			obf := newAsconObfuscator(helper)

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i)
			}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = obf.obfuscate(rand, testData, extKeys)
			}
		})

		b.Run(fmt.Sprintf("Simple_%dB", size), func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			obf := simple{}

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i)
			}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = obf.obfuscate(rand, testData, extKeys)
			}
		})

		b.Run(fmt.Sprintf("Swap_%dB", size), func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			obf := &swap{}

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i)
			}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = obf.obfuscate(rand, testData, extKeys)
			}
		})

		b.Run(fmt.Sprintf("Split_%dB", size), func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			obf := &split{}

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i)
			}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = obf.obfuscate(rand, testData, extKeys)
			}
		})
	}
}

// BenchmarkASCONCore benchmarks ASCON-128 encrypt/decrypt cycle
func BenchmarkASCONCore(b *testing.B) {
	sizes := []int{16, 64, 128, 256, 512, 1024, 2048}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}

			key := make([]byte, 16)
			nonce := make([]byte, 16)

			// Encrypt once to get ciphertext
			ciphertext := AsconEncrypt(key, nonce, plaintext)

			b.ResetTimer()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_, ok := AsconDecrypt(key, nonce, ciphertext)
				if !ok {
					b.Fatal("decryption failed")
				}
			}
		})
	}
}
