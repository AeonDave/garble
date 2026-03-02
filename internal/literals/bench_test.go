package literals

import (
	"fmt"
	mathrand "math/rand"
	"testing"
)

func newBenchmarkContext(r *mathrand.Rand) *obfRand {
	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName
	}
	return &obfRand{
		Rand:            r,
		proxyDispatcher: newProxyDispatcher(r, nameProvider),
	}
}

// BenchmarkObfuscatorPerformance compares all obfuscators with various sizes
func BenchmarkObfuscatorPerformance(b *testing.B) {
	sizes := []int{16, 64, 128, 256, 512, 1024, 2048}

	strategies := []struct {
		name string
		obf  obfuscator
	}{
		{"Swap", &swap{}},
		{"Split", &split{}},
		{"Shuffle", shuffle{}},
		{"Seed", seed{}},
	}

	for _, size := range sizes {
		for _, s := range strategies {
			b.Run(fmt.Sprintf("%s_%dB", s.name, size), func(b *testing.B) {
				rand := mathrand.New(mathrand.NewSource(42))
				ctx := newBenchmarkContext(rand)
				obf := s.obf

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
					_ = obf.obfuscate(ctx, testData, extKeys)
				}
			})
		}
	}
}
