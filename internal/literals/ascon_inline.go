// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	mathrand "math/rand"
)

// asconInlineHelper generates inline ASCON-128 decryption code
// This avoids any crypto package imports by inlining the entire implementation
type asconInlineHelper struct {
	rand     *mathrand.Rand
	nameFunc NameProviderFunc
	funcName string
	used     bool // Set to true when ASCON obfuscation is used
	inserted bool // Set to true when the inline code has been inserted
}

func newAsconInlineHelper(rand *mathrand.Rand, nameFunc NameProviderFunc) *asconInlineHelper {
	return &asconInlineHelper{
		rand:     rand,
		nameFunc: nameFunc,
		funcName: nameFunc(rand, "_garbleAsconDecrypt"),
	}
}

// generateInlineAsconCode generates the complete ASCON-128 implementation as Go source
// This is inserted once per file that uses literal obfuscation
func (h *asconInlineHelper) generateInlineAsconCode() string {
	// Use obfuscated names for all internal functions
	rotateRightName := h.nameFunc(h.rand, "rotRight")
	permuteName := h.nameFunc(h.rand, "perm")
	b2uName := h.nameFunc(h.rand, "b2u")
	u2bName := h.nameFunc(h.rand, "u2b")
	initName := h.nameFunc(h.rand, "init")
	finalizeName := h.nameFunc(h.rand, "final")

	return fmt.Sprintf(`
// Inline ASCON-128 authenticated decryption
func %s(key, nonce, ciphertextAndTag []byte) ([]byte, bool) {
	%s := func(x uint64, n int) uint64 {
		return (x >> n) | (x << (64 - n))
	}
	
	%s := func(s *[5]uint64, rounds int) {
		for i := 0; i < rounds; i++ {
			s[2] ^= uint64(0xf0 - uint64(i)*0x10 + uint64(i)*0x1)
			s[0] ^= s[4]
			s[4] ^= s[3]
			s[2] ^= s[1]
			t0, t1, t2, t3, t4 := s[0], s[1], s[2], s[3], s[4]
			s[0] = t0 ^ (^t1 & t2)
			s[1] = t1 ^ (^t2 & t3)
			s[2] = t2 ^ (^t3 & t4)
			s[3] = t3 ^ (^t4 & t0)
			s[4] = t4 ^ (^t0 & t1)
			s[1] ^= s[0]
			s[0] ^= s[4]
			s[3] ^= s[2]
			s[2] = ^s[2]
			s[0] ^= %s(s[0], 19) ^ %s(s[0], 28)
			s[1] ^= %s(s[1], 61) ^ %s(s[1], 39)
			s[2] ^= %s(s[2], 1) ^ %s(s[2], 6)
			s[3] ^= %s(s[3], 10) ^ %s(s[3], 17)
			s[4] ^= %s(s[4], 7) ^ %s(s[4], 41)
		}
	}
	
	%s := func(b []byte) uint64 {
		return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	}
	
	%s := func(x uint64, b []byte) {
		b[0], b[1], b[2], b[3] = byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32)
		b[4], b[5], b[6], b[7] = byte(x>>24), byte(x>>16), byte(x>>8), byte(x)
	}
	
	%s := func(key, nonce []byte) [5]uint64 {
		var s [5]uint64
		s[0] = 0x80400c0600000000
		s[1] = %s(key[0:8])
		s[2] = %s(key[8:16])
		s[3] = %s(nonce[0:8])
		s[4] = %s(nonce[8:16])
		%s(&s, 12)
		s[3] ^= %s(key[0:8])
		s[4] ^= %s(key[8:16])
		return s
	}
	
	%s := func(s *[5]uint64, key []byte) []byte {
		s[1] ^= %s(key[0:8])
		s[2] ^= %s(key[8:16])
		%s(s, 12)
		s[3] ^= %s(key[0:8])
		s[4] ^= %s(key[8:16])
		tag := make([]byte, 16)
		%s(s[3], tag[0:8])
		%s(s[4], tag[8:16])
		return tag
	}
	
	if len(ciphertextAndTag) < 16 {
		return nil, false
	}
	
	ciphertextLen := len(ciphertextAndTag) - 16
	ciphertext := ciphertextAndTag[:ciphertextLen]
	receivedTag := ciphertextAndTag[ciphertextLen:]
	
	s := %s(key, nonce)
	plaintext := make([]byte, len(ciphertext))
	offset := 0
	
	for offset+8 <= len(ciphertext) {
		ciphertextBlock := %s(ciphertext[offset : offset+8])
		plaintextBlock := s[0] ^ ciphertextBlock
		%s(plaintextBlock, plaintext[offset:offset+8])
		s[0] = ciphertextBlock
		%s(&s, 6)
		offset += 8
	}
	
	if offset < len(ciphertext) {
		remaining := len(ciphertext) - offset
		var stateBytes [8]byte
		%s(s[0], stateBytes[:])
		var plaintextBlock [8]byte
		for i := 0; i < remaining; i++ {
			plaintextBlock[i] = ciphertext[offset+i] ^ stateBytes[i]
			plaintext[offset+i] = plaintextBlock[i]
		}
		plaintextBlock[remaining] = 0x80
		s[0] ^= %s(plaintextBlock[:])
	} else {
		s[0] ^= 0x8000000000000000
	}
	
	expectedTag := %s(&s, key)
	tagMatch := true
	for i := 0; i < 16; i++ {
		if receivedTag[i] != expectedTag[i] {
			tagMatch = false
		}
	}
	
	if !tagMatch {
		return nil, false
	}
	
	return plaintext, true
}
`, h.funcName,
		rotateRightName,
		permuteName,
		rotateRightName, rotateRightName, // s[0]
		rotateRightName, rotateRightName, // s[1]
		rotateRightName, rotateRightName, // s[2]
		rotateRightName, rotateRightName, // s[3]
		rotateRightName, rotateRightName, // s[4]
		b2uName,
		u2bName,
		initName, b2uName, b2uName, b2uName, b2uName, permuteName, b2uName, b2uName,
		finalizeName, b2uName, b2uName, permuteName, b2uName, b2uName, u2bName, u2bName,
		initName,
		b2uName,
		u2bName,
		permuteName,
		u2bName,
		b2uName,
		finalizeName,
	)
}

// encryptStringLiteral encrypts a string using ASCON-128
func (h *asconInlineHelper) encryptStringLiteral(value string) ast.Expr {
	if !h.inserted {
		panic("ascon inline helper not inserted into file")
	}

	data := []byte(value)

	// Generate random key and nonce for this literal
	key := make([]byte, 16)
	h.rand.Read(key)
	nonce := make([]byte, 16)
	h.rand.Read(nonce)

	// Encrypt with ASCON
	encrypted := AsconEncrypt(key, nonce, data)

	// Generate call: _garbleAsconDecrypt(key, nonce, encrypted)
	return &ast.CallExpr{
		Fun: &ast.CallExpr{
			Fun: ast.NewIdent("string"),
			Args: []ast.Expr{
				&ast.CallExpr{
					Fun: &ast.IndexExpr{
						X: &ast.CallExpr{
							Fun: ast.NewIdent(h.funcName),
							Args: []ast.Expr{
								bytesToByteSliceLiteral(key),
								bytesToByteSliceLiteral(nonce),
								bytesToByteSliceLiteral(encrypted),
							},
						},
						Index: ast.NewIdent("0"), // Extract plaintext (first return value)
					},
				},
			},
		},
	}
}

// encryptByteSlice encrypts a byte slice using ASCON-128
func (h *asconInlineHelper) encryptByteSlice(data []byte, pointer bool) ast.Expr {
	if !h.inserted {
		panic("ascon inline helper not inserted into file")
	}

	// Generate random key and nonce
	key := make([]byte, 16)
	h.rand.Read(key)
	nonce := make([]byte, 16)
	h.rand.Read(nonce)

	// Encrypt with ASCON
	encrypted := AsconEncrypt(key, nonce, data)

	// Generate call
	call := &ast.CallExpr{
		Fun: &ast.IndexExpr{
			X: &ast.CallExpr{
				Fun: ast.NewIdent(h.funcName),
				Args: []ast.Expr{
					bytesToByteSliceLiteral(key),
					bytesToByteSliceLiteral(nonce),
					bytesToByteSliceLiteral(encrypted),
				},
			},
			Index: ast.NewIdent("0"),
		},
	}

	if pointer {
		return &ast.UnaryExpr{
			Op: token.AND,
			X:  call,
		}
	}

	return call
}

// encryptByteArray encrypts a byte array using ASCON-128
func (h *asconInlineHelper) encryptByteArray(data []byte, length int64, pointer bool) ast.Expr {
	if !h.inserted {
		panic("ascon inline helper not inserted into file")
	}

	// For arrays, we decrypt to a slice then copy to array
	key := make([]byte, 16)
	h.rand.Read(key)
	nonce := make([]byte, 16)
	h.rand.Read(nonce)

	encrypted := AsconEncrypt(key, nonce, data)

	// Generate: func() [N]byte { var arr [N]byte; copy(arr[:], decrypt(...)); return arr }()
	arrType := &ast.ArrayType{
		Len: &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", length)},
		Elt: ast.NewIdent("byte"),
	}

	funcLit := &ast.FuncLit{
		Type: &ast.FuncType{
			Params: &ast.FieldList{},
			Results: &ast.FieldList{
				List: []*ast.Field{{Type: arrType}},
			},
		},
		Body: &ast.BlockStmt{
			List: []ast.Stmt{
				&ast.DeclStmt{
					Decl: &ast.GenDecl{
						Tok: token.VAR,
						Specs: []ast.Spec{
							&ast.ValueSpec{
								Names: []*ast.Ident{ast.NewIdent("arr")},
								Type:  arrType,
							},
						},
					},
				},
				&ast.ExprStmt{
					X: &ast.CallExpr{
						Fun: ast.NewIdent("copy"),
						Args: []ast.Expr{
							&ast.SliceExpr{
								X:      ast.NewIdent("arr"),
								Slice3: false,
							},
							&ast.CallExpr{
								Fun: &ast.IndexExpr{
									X: &ast.CallExpr{
										Fun: ast.NewIdent(h.funcName),
										Args: []ast.Expr{
											bytesToByteSliceLiteral(key),
											bytesToByteSliceLiteral(nonce),
											bytesToByteSliceLiteral(encrypted),
										},
									},
									Index: ast.NewIdent("0"),
								},
							},
						},
					},
				},
				&ast.ReturnStmt{
					Results: []ast.Expr{ast.NewIdent("arr")},
				},
			},
		},
	}

	call := &ast.CallExpr{
		Fun:  funcLit,
		Args: []ast.Expr{},
	}

	if pointer {
		return &ast.UnaryExpr{
			Op: token.AND,
			X:  call,
		}
	}

	return call
}

// Helper to convert []byte to AST byte slice literal
func bytesToByteSliceLiteral(data []byte) ast.Expr {
	elts := make([]ast.Expr, len(data))
	for i, b := range data {
		elts[i] = &ast.BasicLit{
			Kind:  token.INT,
			Value: fmt.Sprintf("0x%02x", b),
		}
	}

	return &ast.CompositeLit{
		Type: &ast.ArrayType{
			Elt: ast.NewIdent("byte"),
		},
		Elts: elts,
	}
}

// insertAsconInlineCode adds the inline ASCON decrypt function to the file
func insertAsconInlineCode(file *ast.File, helper *asconInlineHelper) {
	if helper.inserted {
		return // Already inserted
	}

	// Parse the generated ASCON code
	inlineCode := helper.generateInlineAsconCode()

	// Parse it as a function declaration
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "ascon.go", "package p\n"+inlineCode, 0)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse inline ASCON code: %v", err))
	}

	// Extract the function declaration
	if len(parsed.Decls) == 0 {
		panic("No declarations found in inline ASCON code")
	}

	funcDecl, ok := parsed.Decls[0].(*ast.FuncDecl)
	if !ok {
		panic("First declaration is not a function")
	}

	// Add the function to the file's declarations
	file.Decls = append(file.Decls, funcDecl)

	helper.inserted = true
}
