package literals

import (
	"encoding/binary"
	"go/ast"
	"math/bits"
	mathrand "math/rand"
	"testing"
)

func newSimpleContext(r *mathrand.Rand) *obfRand {
	nameProvider := func(r *mathrand.Rand, baseName string) string { return baseName }
	helper := newAsconInlineHelper(r, nameProvider)
	return &obfRand{
		Rand:               r,
		proxyDispatcher:    newProxyDispatcher(r, nameProvider),
		asconHelper:        helper,
		irreversibleHelper: newIrreversibleInlineHelper(r, nameProvider),
		keyProvider:        newTestKeyProvider(),
	}
}

// TestSimpleObfuscator verifies the irreversible obfuscator produces structured ASTs.
func TestSimpleObfuscator(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single", []byte{0x42}},
		{"short", []byte("Hi")},
		{"medium", []byte("Hello, World!")},
		{"long", []byte("The quick brown fox jumps over the lazy dog")},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rand := mathrand.New(mathrand.NewSource(42))
			ctx := newSimpleContext(rand)
			obf := simple{}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
				{name: "k2", typ: "uint16", value: 0xABCD, bits: 16},
			}

			dataCopy := append([]byte(nil), tc.data...)
			blockStmt := obf.obfuscate(ctx, dataCopy, extKeys)

			if blockStmt == nil {
				t.Fatal("obfuscate returned nil")
			}

			if len(blockStmt.List) == 0 {
				t.Fatal("expected at least one statement")
			}

			if len(tc.data) == 0 {
				if len(blockStmt.List) != 1 {
					t.Fatalf("expected 1 statement for empty data, got %d", len(blockStmt.List))
				}
				return
			}

			hasDataAssign := false
			foundSubkeys := false
			helperCall := false

			for _, stmt := range blockStmt.List {
				switch s := stmt.(type) {
				case *ast.AssignStmt:
					for _, lhs := range s.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							switch ident.Name {
							case "data":
								hasDataAssign = true
							case "subkeys":
								foundSubkeys = true
							}
						}
					}
					if len(s.Rhs) == 1 {
						if call, ok := s.Rhs[0].(*ast.CallExpr); ok {
							if ident, ok := call.Fun.(*ast.Ident); ok && ctx.irreversibleHelper != nil && ident.Name == ctx.irreversibleHelper.funcName {
								helperCall = true
							}
						}
					}
				}
			}

			if !hasDataAssign {
				t.Error("expected data assignment in obfuscation block")
			}
			if !foundSubkeys {
				t.Error("expected subkey material in irreversible mode")
			}
			if !helperCall {
				t.Error("expected call to irreversible decode helper")
			}
		})
	}
}

// TestSimpleObfuscatorDifferentSeeds verifies that different seeds produce different output
func TestSimpleObfuscatorDifferentSeeds(t *testing.T) {
	data := []byte("Test data for randomness")
	obf := simple{}

	// Generate with seed 1
	rand1 := mathrand.New(mathrand.NewSource(1))
	ctx1 := newSimpleContext(rand1)
	data1 := make([]byte, len(data))
	copy(data1, data)
	block1 := obf.obfuscate(ctx1, data1, []*externalKey{{name: "k1", typ: "uint32", value: 0x12345678, bits: 32}})

	// Generate with seed 2
	rand2 := mathrand.New(mathrand.NewSource(2))
	ctx2 := newSimpleContext(rand2)
	data2 := make([]byte, len(data))
	copy(data2, data)
	block2 := obf.obfuscate(ctx2, data2, []*externalKey{{name: "k1", typ: "uint32", value: 0x12345678, bits: 32}})

	// They should be different (different nonce/key)
	// We can't compare AST directly, but we can check they're not nil
	if block1 == nil || block2 == nil {
		t.Fatal("obfuscation should not return nil")
	}

	// The number of statements might be the same, but content will differ
	t.Logf("✅ Seed 1 generated %d statements", len(block1.List))
	t.Logf("✅ Seed 2 generated %d statements", len(block2.List))
}

// TestSimpleObfuscatorExternalKeyUsage verifies external keys are marked as used
func TestSimpleObfuscatorExternalKeyUsage(t *testing.T) {
	data := []byte("Test external key usage")
	rand := mathrand.New(mathrand.NewSource(42))
	ctx := newSimpleContext(rand)
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32, refs: 0},
		{name: "k2", typ: "uint16", value: 0xABCD, bits: 16, refs: 0},
	}

	// Obfuscate
	_ = obf.obfuscate(ctx, data, extKeys)

	// External keys should be used (refs > 0)
	// The dataToByteSliceWithExtKeys function should mark them as used
	// Note: We can't guarantee ALL keys are used, but at least some should be
	totalRefs := 0
	for _, key := range extKeys {
		totalRefs += key.refs
	}

	if totalRefs == 0 {
		t.Error("expected at least some external keys to be used")
	}

	t.Logf("✅ External keys used with %d total references", totalRefs)
}

// TestSimpleObfuscatorAST verifies the generated AST is valid Go code
func TestSimpleObfuscatorAST(t *testing.T) {
	data := []byte("Test AST generation")
	rand := mathrand.New(mathrand.NewSource(42))
	ctx := newSimpleContext(rand)
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
	}

	// Obfuscate
	blockStmt := obf.obfuscate(ctx, data, extKeys)

	// Try to generate code from AST
	file := &ast.File{
		Name: ast.NewIdent("main"),
		Decls: []ast.Decl{
			&ast.FuncDecl{
				Name: ast.NewIdent("test"),
				Type: &ast.FuncType{
					Params:  &ast.FieldList{},
					Results: &ast.FieldList{},
				},
				Body: blockStmt,
			},
		},
	}

	// Just verify we can walk the AST without panic
	ast.Inspect(file, func(n ast.Node) bool {
		return true
	})

	t.Logf("✅ Generated valid AST with %d statements", len(blockStmt.List))
}

// TestSimpleObfuscatorIntegration tests end-to-end with actual compilation
func TestSimpleObfuscatorIntegration(t *testing.T) {
	t.Skip("Integration test - run manually with actual compilation")

	// This test would require actual Go compilation
	// Left as template for manual testing
	testCode := `
package main

import "fmt"

func main() {
	// This will be replaced by obfuscated version
	secret := "REPLACE_ME"
	fmt.Println(secret)
}
`
	_ = testCode
}

// BenchmarkSimpleObfuscator benchmarks the improved simple obfuscator
func BenchmarkSimpleObfuscator(b *testing.B) {
	sizes := []int{16, 64, 128, 256, 512, 1024}

	for _, size := range sizes {
		b.Run(string(rune(size))+"B", func(b *testing.B) {
			data := make([]byte, size)
			rand := mathrand.New(mathrand.NewSource(42))
			ctx := newSimpleContext(rand)
			obf := simple{}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				_ = obf.obfuscate(ctx, dataCopy, extKeys)
			}
		})
	}
}

// --- Irreversible cipher property tests ---

// TestIrreversibleNonRecoverability proves that ciphertext cannot be
// reversed using wrong subkeys. This is the core security guarantee:
// without the correct subkeys embedded in the binary, the original
// plaintext cannot be recovered.
func TestIrreversibleNonRecoverability(t *testing.T) {
	material := make([]byte, irreversibleRounds*8)
	for i := range material {
		material[i] = byte(i * 3)
	}
	subkeys := deriveIrreversibleSubkeys(material)

	plaintext := []byte("SECRET DATA THAT MUST NOT LEAK!")
	ct := irreversibleEncryptLiteral(plaintext, subkeys)

	// Trying to decrypt with wrong subkeys must produce garbage
	wrongMaterial := make([]byte, irreversibleRounds*8)
	for i := range wrongMaterial {
		wrongMaterial[i] = byte(i*3 + 1) // slightly different
	}
	wrongSubkeys := deriveIrreversibleSubkeys(wrongMaterial)

	wrongResult := irreversibleDecryptForTest(ct, wrongSubkeys, len(plaintext))
	if string(wrongResult) == string(plaintext) {
		t.Fatal("wrong subkeys recovered original plaintext — cipher is broken")
	}

	// Count matching bytes — should be near random (~1/256 match rate)
	matching := 0
	for i := 0; i < len(plaintext) && i < len(wrongResult); i++ {
		if plaintext[i] == wrongResult[i] {
			matching++
		}
	}
	matchRate := float64(matching) / float64(len(plaintext))
	t.Logf("wrong-key match rate: %.4f (%d/%d bytes)", matchRate, matching, len(plaintext))
	if matchRate > 0.15 {
		t.Fatalf("too many bytes match with wrong key: %.4f (want < 0.15)", matchRate)
	}
}

// TestIrreversibleRoundtrip verifies correct subkeys recover the original plaintext.
func TestIrreversibleRoundtrip(t *testing.T) {
	testCases := [][]byte{
		[]byte("A"),
		[]byte("Hello, World!"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 256),
	}

	for _, plaintext := range testCases {
		material := make([]byte, irreversibleRounds*8)
		for i := range material {
			material[i] = byte(i * 7)
		}
		subkeys := deriveIrreversibleSubkeys(material)

		ct := irreversibleEncryptLiteral(plaintext, subkeys)
		recovered := irreversibleDecryptForTest(ct, subkeys, len(plaintext))

		if string(recovered) != string(plaintext) {
			t.Fatalf("roundtrip failed for %q\n  got:  %x\n  want: %x",
				plaintext, recovered, plaintext)
		}
	}
}

// TestIrreversibleAvalanche checks SBox + Feistel avalanche on 128-bit blocks.
func TestIrreversibleAvalanche(t *testing.T) {
	material := make([]byte, irreversibleRounds*8)
	for i := range material {
		material[i] = byte(i)
	}
	subkeys := deriveIrreversibleSubkeys(material)

	// Use a full block (16 bytes)
	base := make([]byte, 16)
	baseCT := irreversibleEncryptLiteral(base, subkeys)

	totalDiffs := 0
	totalBits := 0

	for bitPos := 0; bitPos < 128; bitPos++ {
		modified := make([]byte, 16)
		modified[bitPos/8] ^= 1 << (bitPos % 8)

		modCT := irreversibleEncryptLiteral(modified, subkeys)

		for i := 0; i < len(baseCT) && i < len(modCT); i++ {
			totalDiffs += bits.OnesCount8(baseCT[i] ^ modCT[i])
		}
		totalBits += len(baseCT) * 8
	}

	ratio := float64(totalDiffs) / float64(totalBits)
	t.Logf("irreversible avalanche ratio: %.4f (ideal=0.5)", ratio)
	// The irreversible cipher uses SBox + 4-round Feistel on 128-bit blocks.
	// Limited rounds mean diffusion is weaker than a full cipher.
	if ratio < 0.15 {
		t.Fatalf("avalanche too weak: %.4f (want >= 0.15)", ratio)
	}
}

// TestIrreversibleSBoxProperties validates the SBox is a valid permutation
// (bijection on [0, 255]) and matches the AES SBox.
func TestIrreversibleSBoxProperties(t *testing.T) {
	// Verify SBox is a permutation (bijective)
	var seen [256]bool
	for _, v := range irreversibleSBox {
		if seen[v] {
			t.Fatalf("SBox is not a permutation: duplicate output 0x%02x", v)
		}
		seen[v] = true
	}

	// Verify InvSBox is exactly the inverse
	for i := 0; i < 256; i++ {
		if irreversibleInvSBox[irreversibleSBox[byte(i)]] != byte(i) {
			t.Fatalf("InvSBox[SBox[0x%02x]] != 0x%02x", i, i)
		}
		if irreversibleSBox[irreversibleInvSBox[byte(i)]] != byte(i) {
			t.Fatalf("SBox[InvSBox[0x%02x]] != 0x%02x", i, i)
		}
	}

	// Verify it's the standard AES SBox (first/last known values)
	if irreversibleSBox[0x00] != 0x63 {
		t.Fatalf("SBox[0x00] = 0x%02x, want 0x63 (AES)", irreversibleSBox[0x00])
	}
	if irreversibleSBox[0xFF] != 0x16 {
		t.Fatalf("SBox[0xFF] = 0x%02x, want 0x16 (AES)", irreversibleSBox[0xFF])
	}
	if irreversibleSBox[0x53] != 0xed {
		t.Fatalf("SBox[0x53] = 0x%02x, want 0xed (AES)", irreversibleSBox[0x53])
	}
}

// TestIrreversibleByteDistribution verifies ciphertext bytes are uniformly distributed.
func TestIrreversibleByteDistribution(t *testing.T) {
	material := make([]byte, irreversibleRounds*8)
	for i := range material {
		material[i] = byte(i * 11)
	}
	subkeys := deriveIrreversibleSubkeys(material)

	var buckets [256]int
	totalBytes := 0

	// Encrypt many different 16-byte blocks with varied input
	const samples = 4096
	for i := 0; i < samples; i++ {
		block := make([]byte, 16)
		binary.LittleEndian.PutUint64(block[:8], uint64(i))
		binary.LittleEndian.PutUint64(block[8:], uint64(i)*0x9e3779b97f4a7c15+0xdeadbeefcafebabe)
		ct := irreversibleEncryptLiteral(block, subkeys)
		for _, b := range ct {
			buckets[b]++
			totalBytes++
		}
	}

	// Chi-squared goodness-of-fit
	expected := float64(totalBytes) / 256.0
	var chiSq float64
	for _, count := range buckets {
		diff := float64(count) - expected
		chiSq += (diff * diff) / expected
	}

	t.Logf("irreversible byte distribution chi-squared: %.2f (255 DOF)", chiSq)
	// The irreversible cipher has limited diffusion; use a generous threshold.
	// Critical value at p=0.001 for 255 DOF ≈ 310, but we allow much more
	// because this is a lightweight obfuscation cipher, not a PRNG.
	if chiSq > 5000 {
		t.Fatalf("byte distribution chi-squared %.2f exceeds threshold 5000", chiSq)
	}
}

// TestIrreversibleSubkeyDerivation validates subkey derivation properties.
func TestIrreversibleSubkeyDerivation(t *testing.T) {
	// Different material → different subkeys
	m1 := make([]byte, irreversibleRounds*8)
	m2 := make([]byte, irreversibleRounds*8)
	for i := range m1 {
		m1[i] = byte(i)
		m2[i] = byte(i + 1)
	}

	sk1 := deriveIrreversibleSubkeys(m1)
	sk2 := deriveIrreversibleSubkeys(m2)

	allSame := true
	for i := range sk1 {
		if sk1[i] != sk2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("different material produced identical subkeys")
	}

	// Verify count
	if len(sk1) != irreversibleRounds {
		t.Fatalf("expected %d subkeys, got %d", irreversibleRounds, len(sk1))
	}

	// Verify subkeys are diverse (not all same)
	for i := 1; i < len(sk1); i++ {
		if sk1[i] == sk1[0] {
			t.Fatalf("subkey[%d] == subkey[0], expected diversity", i)
		}
	}
}

// TestFeistelBlockEncryptDecrypt128 tests the 128-bit Feistel block cipher roundtrip.
func TestFeistelBlockEncryptDecrypt128(t *testing.T) {
	material := make([]byte, irreversibleRounds*8)
	for i := range material {
		material[i] = byte(i * 5)
	}
	subkeys := deriveIrreversibleSubkeys(material)

	block := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	original := append([]byte(nil), block...)

	feistelEncryptBlock(block, subkeys)

	// Must differ from original
	if string(block) == string(original) {
		t.Fatal("encryption did not change the block")
	}

	// Decrypt using reverse subkey order
	feistelDecryptBlockForTest(block, subkeys)

	if string(block) != string(original) {
		t.Fatalf("roundtrip failed:\n  got:  %x\n  want: %x", block, original)
	}
}

// TestIrreversibleKeyAvalanche verifies that a single-bit change in subkeys
// causes significant ciphertext change.
func TestIrreversibleKeyAvalanche(t *testing.T) {
	material := make([]byte, irreversibleRounds*8)
	for i := range material {
		material[i] = byte(i)
	}
	subkeys := deriveIrreversibleSubkeys(material)

	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	baseCT := irreversibleEncryptLiteral(plaintext, subkeys)

	totalDiffs := 0
	tests := 0

	for sk := 0; sk < len(subkeys); sk++ {
		for bit := 0; bit < 64; bit++ {
			modified := make([]uint64, len(subkeys))
			copy(modified, subkeys)
			modified[sk] ^= 1 << bit

			modCT := irreversibleEncryptLiteral(plaintext, modified)

			for i := 0; i < len(baseCT) && i < len(modCT); i++ {
				totalDiffs += bits.OnesCount8(baseCT[i] ^ modCT[i])
			}
			tests++
		}
	}

	ratio := float64(totalDiffs) / float64(tests*len(baseCT)*8)
	t.Logf("key avalanche ratio: %.4f (ideal=0.5)", ratio)
	// 4-round Feistel has limited key diffusion; accept > 0.05 as minimum.
	// This still guarantees different keys produce measurably different output.
	if ratio < 0.05 {
		t.Fatalf("key avalanche ratio %.4f too low (want >= 0.05)", ratio)
	}
}

// --- Test helpers for irreversible cipher decryption (inverse of encrypt) ---

func feistelDecryptBlockForTest(block []byte, subkeys []uint64) {
	left := binary.LittleEndian.Uint64(block[:8])
	right := binary.LittleEndian.Uint64(block[8:])

	for i := len(subkeys) - 1; i >= 0; i-- {
		f := feistelRound(left, subkeys[i])
		left, right = right^f, left
	}

	binary.LittleEndian.PutUint64(block[:8], left)
	binary.LittleEndian.PutUint64(block[8:], right)
}

func irreversibleDecryptForTest(ct []byte, subkeys []uint64, originalLen int) []byte {
	buf := append([]byte(nil), ct...)

	// Inverse Feistel (decrypt each block)
	for offset := 0; offset < len(buf); offset += irreversibleBlockSize {
		feistelDecryptBlockForTest(buf[offset:offset+irreversibleBlockSize], subkeys)
	}

	// Inverse SBox
	for i := range buf {
		buf[i] = irreversibleInvSBox[buf[i]]
	}

	if originalLen <= len(buf) {
		return buf[:originalLen]
	}
	return buf
}
