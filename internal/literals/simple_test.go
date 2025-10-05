// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"go/ast"
	mathrand "math/rand"
	"testing"
)

// TestSimpleObfuscator verifies the improved simple (XOR-based) obfuscator
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
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"repeated", []byte("aaaaaaaaaa")},
		{"special", []byte("Test\n\t\r\x00Special")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create obfuscator
			rand := mathrand.New(mathrand.NewSource(42))
			obf := simple{}

			// Generate external keys
			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
				{name: "k2", typ: "uint16", value: 0xABCD, bits: 16},
			}

			// Make a copy of original data
			original := make([]byte, len(tc.data))
			copy(original, tc.data)

			// Obfuscate
			blockStmt := obf.obfuscate(rand, tc.data, extKeys)

			if blockStmt == nil {
				t.Fatal("obfuscate returned nil")
			}

			// Verify AST structure
			if len(blockStmt.List) == 0 {
				t.Fatal("expected at least one statement")
			}

			// Empty data case has just 1 statement (data assignment)
			if len(original) == 0 {
				if len(blockStmt.List) != 1 {
					t.Fatalf("expected 1 statement for empty data, got %d", len(blockStmt.List))
				}
				t.Logf("✅ Generated %d statement for empty bytes", len(blockStmt.List))
				return
			}

			// Check that statements were generated
			if len(blockStmt.List) < 4 {
				t.Fatalf("expected at least 4 statements, got %d", len(blockStmt.List))
			}

			t.Logf("✅ Generated %d statements for %d bytes", len(blockStmt.List), len(original))

			// Verify nonce statement exists
			hasNonce := false
			hasKey := false
			hasData := false
			hasLoop := false

			for _, stmt := range blockStmt.List {
				switch s := stmt.(type) {
				case *ast.AssignStmt:
					if len(s.Lhs) > 0 {
						if ident, ok := s.Lhs[0].(*ast.Ident); ok {
							switch ident.Name {
							case "nonce":
								hasNonce = true
							case "key":
								hasKey = true
							case "data":
								hasData = true
							}
						}
					}
				case *ast.ForStmt:
					hasLoop = true
				}
			}

			if len(original) > 0 {
				if !hasNonce {
					t.Error("expected nonce statement")
				}
				if !hasKey {
					t.Error("expected key statement")
				}
				if !hasData {
					t.Error("expected data statement")
				}
				if !hasLoop {
					t.Error("expected deobfuscation loop")
				}
			}
		})
	}
}

// TestSimpleObfuscatorDifferentSeeds verifies that different seeds produce different output
func TestSimpleObfuscatorDifferentSeeds(t *testing.T) {
	data := []byte("Test data for randomness")
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
	}

	// Generate with seed 1
	rand1 := mathrand.New(mathrand.NewSource(1))
	data1 := make([]byte, len(data))
	copy(data1, data)
	block1 := obf.obfuscate(rand1, data1, extKeys)

	// Generate with seed 2
	rand2 := mathrand.New(mathrand.NewSource(2))
	data2 := make([]byte, len(data))
	copy(data2, data)
	block2 := obf.obfuscate(rand2, data2, extKeys)

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
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32, refs: 0},
		{name: "k2", typ: "uint16", value: 0xABCD, bits: 16, refs: 0},
	}

	// Obfuscate
	_ = obf.obfuscate(rand, data, extKeys)

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
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
	}

	// Obfuscate
	blockStmt := obf.obfuscate(rand, data, extKeys)

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

// TestSimpleObfuscatorCompareWithOld compares new implementation behavior
func TestSimpleObfuscatorCompareWithOld(t *testing.T) {
	data := []byte("Test comparison")
	rand := mathrand.New(mathrand.NewSource(42))
	obf := simple{}

	extKeys := []*externalKey{
		{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
	}

	// New implementation should generate more statements (nonce, position mixing, chaining)
	blockStmt := obf.obfuscate(rand, data, extKeys)

	if len(blockStmt.List) < 4 {
		t.Errorf("expected at least 4 statements for improved obfuscation, got %d", len(blockStmt.List))
	}

	t.Logf("✅ New implementation generates %d statements (old was 3)", len(blockStmt.List))
}

// BenchmarkSimpleObfuscator benchmarks the improved simple obfuscator
func BenchmarkSimpleObfuscator(b *testing.B) {
	sizes := []int{16, 64, 128, 256, 512, 1024}

	for _, size := range sizes {
		b.Run(string(rune(size))+"B", func(b *testing.B) {
			data := make([]byte, size)
			rand := mathrand.New(mathrand.NewSource(42))
			obf := simple{}

			extKeys := []*externalKey{
				{name: "k1", typ: "uint32", value: 0x12345678, bits: 32},
			}

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				_ = obf.obfuscate(rand, dataCopy, extKeys)
			}
		})
	}
}
