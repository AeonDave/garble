// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "github.com/AeonDave/garble/internal/asthelper"
)

// asconObfuscator implements authenticated encryption obfuscation using ASCON-128
// This provides strong cryptographic protection for literals without requiring any imports
type asconObfuscator struct {
	inlineHelper *asconInlineHelper
}

// obfuscate encrypts the data using ASCON-128 and generates decryption code
// The entire ASCON implementation is inlined to avoid import dependencies
func (a *asconObfuscator) obfuscate(obfRand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	// Mark that ASCON obfuscation is being used
	a.inlineHelper.used = true

	// Generate random 16-byte key and nonce for this literal
	key := make([]byte, 16)
	obfRand.Read(key)

	nonce := make([]byte, 16)
	obfRand.Read(nonce)

	// Apply external keys to the key material for additional obfuscation
	// This makes each literal unique even with same plaintext
	if len(extKeys) > 0 {
		for i, extKey := range extKeys {
			// Always add reference to mark as used
			extKey.AddRef()

			// Mix external key into the ASCON key and nonce
			keyByte := byte(extKey.value >> (8 * (i % 8)))
			key[i%16] ^= keyByte
			nonce[i%16] ^= keyByte
		}
	}

	// Encrypt data with ASCON-128
	ciphertextAndTag := AsconEncrypt(key, nonce, data)

	// Build the decryption block:
	// 1. Inline ASCON decrypt function (if not already inserted)
	// 2. Call decrypt with embedded key, nonce, and ciphertext
	// 3. Check authentication and extract plaintext

	block := &ast.BlockStmt{}

	// Generate the call to inline ASCON decrypt:
	// data, ok := _garbleAsconDecrypt(key, nonce, ciphertextAndTag)
	decryptCall := &ast.CallExpr{
		Fun: ast.NewIdent(a.inlineHelper.funcName),
		Args: []ast.Expr{
			bytesToByteSliceLiteral(key),
			bytesToByteSliceLiteral(nonce),
			bytesToByteSliceLiteral(ciphertextAndTag),
		},
	}

	// Assignment: data, ok := decrypt(...)
	block.List = append(block.List, &ast.AssignStmt{
		Lhs: []ast.Expr{
			ast.NewIdent("data"),
			ast.NewIdent("ok"),
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{decryptCall},
	})

	// Authentication check: if !ok { panic("garble: ASCON authentication failed") }
	// This should never happen in normal execution, but provides a safety check
	block.List = append(block.List, &ast.IfStmt{
		Cond: &ast.UnaryExpr{
			Op: token.NOT,
			X:  ast.NewIdent("ok"),
		},
		Body: ah.BlockStmt(
			&ast.ExprStmt{
				X: ah.CallExprByName("panic",
					&ast.BasicLit{
						Kind:  token.STRING,
						Value: `"garble: literal authentication failed"`,
					},
				),
			},
		),
	})

	return block
}

// newAsconObfuscator creates a new ASCON obfuscator with inline helper
func newAsconObfuscator(inlineHelper *asconInlineHelper) obfuscator {
	return &asconObfuscator{
		inlineHelper: inlineHelper,
	}
}
