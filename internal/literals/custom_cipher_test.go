package literals

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	mathrand "math/rand"
	"strings"
	"testing"
)

func TestCustomCipherRoundtrip(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"single", []byte{0x42}},
		{"short", []byte("hello")},
		{"medium", []byte("the quick brown fox jumps over the lazy dog")},
		{"binary", []byte{0, 1, 2, 255, 254, 253, 128, 127}},
		{"256bytes", bytes.Repeat([]byte{0xAB}, 256)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rand := mathrand.New(mathrand.NewSource(42))
			params := newCustomCipherParams(rand)

			original := make([]byte, len(tc.data))
			copy(original, tc.data)

			encrypted := make([]byte, len(tc.data))
			copy(encrypted, tc.data)
			customCipherEncrypt(params, encrypted)

			// Non-empty data should be different after encryption
			if len(tc.data) > 0 && bytes.Equal(encrypted, original) {
				t.Fatal("encryption did not change data")
			}

			customCipherDecrypt(params, encrypted)
			if !bytes.Equal(encrypted, original) {
				t.Fatalf("roundtrip failed: got %v, want %v", encrypted, original)
			}
		})
	}
}

func TestCustomCipherDifferentSeeds(t *testing.T) {
	data := []byte("test data for cipher")

	rand1 := mathrand.New(mathrand.NewSource(1))
	params1 := newCustomCipherParams(rand1)
	enc1 := make([]byte, len(data))
	copy(enc1, data)
	customCipherEncrypt(params1, enc1)

	rand2 := mathrand.New(mathrand.NewSource(2))
	params2 := newCustomCipherParams(rand2)
	enc2 := make([]byte, len(data))
	copy(enc2, data)
	customCipherEncrypt(params2, enc2)

	if bytes.Equal(enc1, enc2) {
		t.Fatal("different seeds should produce different ciphertexts")
	}
}

func TestCustomCipherSboxIsPermutation(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(99))
	params := newCustomCipherParams(rand)

	// Check S-box is a valid permutation
	seen := make(map[byte]bool)
	for _, v := range params.sbox {
		if seen[v] {
			t.Fatalf("duplicate value in S-box: %d", v)
		}
		seen[v] = true
	}

	// Check inverse S-box correctness
	for i := 0; i < 256; i++ {
		if params.invSbox[params.sbox[byte(i)]] != byte(i) {
			t.Fatalf("invSbox[sbox[%d]] != %d", i, i)
		}
	}
}

func TestCustomCipherRounds(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	params := newCustomCipherParams(rand)

	if params.rounds < 4 || params.rounds > 6 {
		t.Fatalf("expected 4-6 rounds, got %d", params.rounds)
	}
	if len(params.keys) != params.rounds {
		t.Fatalf("expected %d round keys, got %d", params.rounds, len(params.keys))
	}
}

func TestCustomCipherInlineDecryptGeneratesCode(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	params := newCustomCipherParams(rand)

	block := customCipherInlineDecrypt(rand, params, "data")
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if len(block.List) < 3 {
		t.Fatalf("expected at least 3 statements (invSbox + keys + loop), got %d", len(block.List))
	}

	// Format and verify it contains expected elements
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, block); err != nil {
		t.Fatalf("failed to format: %v", err)
	}
	code := buf.String()

	if !strings.Contains(code, "[256]byte") {
		t.Fatal("expected [256]byte (invSbox type) in generated code")
	}
	if !strings.Contains(code, "uint32") {
		t.Fatal("expected uint32 (round keys type) in generated code")
	}
	if !strings.Contains(code, "for") {
		t.Fatal("expected for loop in generated code")
	}
}

func TestCustomCipherObfuscatorProducesBlock(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	nameFunc := func(r *mathrand.Rand, base string) string { return base }
	ctx := &obfRand{Rand: rand, proxyDispatcher: newProxyDispatcher(rand, nameFunc)}

	obf := customCipherObfuscator{}
	data := []byte("secret message")
	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
	}

	block := obf.obfuscate(ctx, data, extKeys)
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if len(block.List) == 0 {
		t.Fatal("expected non-empty block")
	}

	// Verify it contains the data assignment and decrypt code
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, block); err != nil {
		t.Fatalf("failed to format: %v", err)
	}
	code := buf.String()

	if !strings.Contains(code, "[256]byte") {
		t.Fatal("expected [256]byte in obfuscated code")
	}
}

func TestCustomCipherKeyFromSeed(t *testing.T) {
	seed := []byte("test-seed-that-is-32-bytes-long!")[:32]
	k1 := customCipherKeyFromSeed(seed, 0)
	k2 := customCipherKeyFromSeed(seed, 1)
	k3 := customCipherKeyFromSeed(seed, 0)

	if k1 == k2 {
		t.Fatal("different counters should produce different keys")
	}
	if k1 != k3 {
		t.Fatal("same inputs should produce same key")
	}
}

func TestCustomCipherObfuscatorInterface(t *testing.T) {
	// Verify it satisfies the obfuscator interface
	var _ obfuscator = customCipherObfuscator{}

	// Verify the obfuscate method doesn't panic with minimal data
	rand := mathrand.New(mathrand.NewSource(1))
	nameFunc := func(r *mathrand.Rand, base string) string { return base }
	ctx := &obfRand{Rand: rand, proxyDispatcher: newProxyDispatcher(rand, nameFunc)}

	for _, data := range [][]byte{
		{0},
		{1, 2},
		[]byte("a"),
		bytes.Repeat([]byte{0xFF}, 100),
	} {
		block := customCipherObfuscator{}.obfuscate(ctx, data, nil)
		if block == nil || len(block.List) == 0 {
			t.Fatalf("empty block for data len %d", len(data))
		}
	}
}

// TestCustomCipherNoFixedConstants verifies the inline code contains
// no well-known cryptographic constants (AES S-box values, ASCON IV, etc.)
func TestCustomCipherNoFixedConstants(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	params := newCustomCipherParams(rand)
	block := customCipherInlineDecrypt(rand, params, "data")

	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, block); err != nil {
		t.Fatalf("failed to format: %v", err)
	}
	code := buf.String()

	// These are known AES S-box entries that findcrypt looks for
	aesSignatures := []string{
		"0x637c777b", // first 4 AES S-box bytes
		"0x80400c06", // ASCON IV
	}
	for _, sig := range aesSignatures {
		if strings.Contains(code, sig) {
			t.Fatalf("generated code contains known crypto constant: %s", sig)
		}
	}

	// Verify S-box is NOT the identity or AES S-box
	if params.sbox[0] == 0x63 && params.sbox[1] == 0x7c {
		t.Fatal("S-box looks like AES S-box")
	}
}

// BenchmarkCustomCipher benchmarks encrypt/decrypt cycle
func BenchmarkCustomCipher(b *testing.B) {
	sizes := []int{16, 64, 256, 1024}
	for _, size := range sizes {
		b.Run("encrypt", func(b *testing.B) {
			rand := mathrand.New(mathrand.NewSource(42))
			params := newCustomCipherParams(rand)
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i)
			}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				customCipherEncrypt(params, data)
			}
		})
	}
}

// Verify the generated code is syntactically valid Go.
func TestCustomCipherInlineIsSyntacticallyValid(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	params := newCustomCipherParams(rand)
	block := customCipherInlineDecrypt(rand, params, "data")

	// Wrap in a function to form a complete Go source file
	fset := token.NewFileSet()
	funcDecl := &ast.FuncDecl{
		Name: ast.NewIdent("decrypt"),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			// data := []byte{1, 2, 3}
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("data")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{&ast.CompositeLit{
					Type: &ast.ArrayType{Elt: ast.NewIdent("byte")},
					Elts: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "1"}},
				}},
			},
		}},
	}
	funcDecl.Body.List = append(funcDecl.Body.List, block.List...)

	var buf bytes.Buffer
	if err := format.Node(&buf, fset, funcDecl); err != nil {
		t.Fatalf("generated code is not valid Go: %v", err)
	}
}

// TestMBAXOREquivalence verifies that all MBA variants produce
// the same result as plain XOR for every possible byte pair.
func TestMBAXOREquivalence(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			expected := byte(a) ^ byte(b)

			// Variant 1: (a | b) - (a & b)
			v1 := (byte(a) | byte(b)) - (byte(a) & byte(b))
			if v1 != expected {
				t.Fatalf("MBA v1 failed: %d ^ %d = %d, got %d", a, b, expected, v1)
			}

			// Variant 2: (a + b) - 2*(a & b)
			v2 := (byte(a) + byte(b)) - 2*(byte(a)&byte(b))
			if v2 != expected {
				t.Fatalf("MBA v2 failed: %d ^ %d = %d, got %d", a, b, expected, v2)
			}
		}
	}
}

// TestCustomCipherInlineDecryptPolymorphic verifies that different
// random seeds produce different generated code (variable names and
// MBA expression forms vary per invocation).
func TestCustomCipherInlineDecryptPolymorphic(t *testing.T) {
	fset := token.NewFileSet()
	formatBlock := func(seed int64) string {
		r := mathrand.New(mathrand.NewSource(seed))
		params := newCustomCipherParams(r)
		block := customCipherInlineDecrypt(r, params, "data")
		var buf bytes.Buffer
		if err := format.Node(&buf, fset, block); err != nil {
			t.Fatalf("format failed for seed %d: %v", seed, err)
		}
		return buf.String()
	}

	code1 := formatBlock(100)
	code2 := formatBlock(200)

	if code1 == code2 {
		t.Fatal("different seeds should produce different generated code (polymorphic names/MBA)")
	}
}

// TestRandomVarNameUniqueness verifies that generated variable names
// are valid Go identifiers and that a set of 6 names has no duplicates.
func TestRandomVarNameUniqueness(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(42))
	names := newCipherVarNames(rand)

	all := []string{names.invSbox, names.rkeys, names.round, names.key, names.keyBytes, names.idx}
	seen := make(map[string]bool)
	for _, n := range all {
		if len(n) != 4 || n[0] != '_' {
			t.Fatalf("unexpected variable name format: %q", n)
		}
		if seen[n] {
			t.Fatalf("duplicate variable name: %q", n)
		}
		seen[n] = true
	}
}
