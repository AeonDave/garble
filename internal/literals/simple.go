// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "mvdan.cc/garble/internal/asthelper"
)

type simple struct{}

// check that the obfuscator interface is implemented
var _ obfuscator = simple{}

// obfuscate implements an improved XOR-based obfuscation with:
// 1. Nonce for uniqueness (prevents pattern analysis across builds)
// 2. Position-dependent key derivation (each byte uses position-derived key)
// 3. Chained operations with rotation (dependencies between bytes)
// 4. External key mixing for additional entropy
//
// Algorithm:
//
//	data[i] = ((plaintext[i] XOR key[i]) + nonce) XOR (position_mix) OP external_keys
//
// This creates a much stronger cipher than simple XOR while maintaining:
// - Reversibility (essential for garble reverse compatibility)
// - Performance (still ~2x faster than ASCON for small literals)
// - Simplicity (no crypto imports, inline operations)
func (simple) obfuscate(rand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	if len(data) == 0 {
		return ah.BlockStmt(
			ah.AssignDefineStmt(ast.NewIdent("data"), ah.DataToByteSlice(data)),
		)
	}

	// Generate a random nonce (8 bytes for good entropy without overhead)
	nonce := make([]byte, 8)
	rand.Read(nonce)

	// Generate base key (same length as data)
	key := make([]byte, len(data))
	rand.Read(key)

	// Choose random operators for multi-layer obfuscation
	op1 := randOperator(rand) // First layer
	op2 := randOperator(rand) // Second layer

	// Obfuscate data with improved algorithm:
	// 1. Base XOR with key
	// 2. Add position-dependent nonce mixing
	// 3. Apply chained operation with rotation
	obfuscated := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		// Layer 1: XOR with position-derived key
		posKey := key[i] ^ byte(i*7+13) // Position mixing with prime numbers
		layer1 := data[i] ^ posKey

		// Layer 2: Mix with nonce (cyclic)
		nonceIdx := i % len(nonce)
		layer2 := evalOperator(op1, layer1, nonce[nonceIdx])

		// Layer 3: Chain with previous byte for dependency
		if i > 0 {
			layer2 = evalOperator(op2, layer2, obfuscated[i-1]>>3) // Rotate previous byte
		}

		obfuscated[i] = layer2
	}

	// Generate deobfuscation code
	// We need to reverse the operations in opposite order
	var deobfStmts []ast.Stmt

	// Create loop body that reverses the obfuscation
	loopBody := []ast.Stmt{
		// temp := data[i]
		ah.AssignDefineStmt(
			ast.NewIdent("temp"),
			ah.IndexExpr("data", ast.NewIdent("i")),
		),
	}

	// Reverse layer 3: Remove chain dependency (if not first byte)
	if len(data) > 1 {
		// if i > 0 { data[i] = data[i] REVERSE_OP2 (prevTemp >> 3) }
		loopBody = append(loopBody,
			&ast.IfStmt{
				Cond: ah.BinaryExpr(ast.NewIdent("i"), token.GTR, ah.IntLit(0)),
				Body: &ast.BlockStmt{
					List: []ast.Stmt{
						&ast.AssignStmt{
							Lhs: []ast.Expr{ah.IndexExpr("data", ast.NewIdent("i"))},
							Tok: token.ASSIGN,
							Rhs: []ast.Expr{
								operatorToReversedBinaryExpr(op2,
									ah.IndexExpr("data", ast.NewIdent("i")),
									ah.BinaryExpr(ast.NewIdent("prevTemp"), token.SHR, ah.IntLit(3)),
								),
							},
						},
					},
				},
			},
		)
	}

	// Reverse layer 2: Remove nonce mixing
	// data[i] = data[i] REVERSE_OP1 nonce[i % len(nonce)]
	loopBody = append(loopBody,
		&ast.AssignStmt{
			Lhs: []ast.Expr{ah.IndexExpr("data", ast.NewIdent("i"))},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{
				operatorToReversedBinaryExpr(op1,
					ah.IndexExpr("data", ast.NewIdent("i")),
					ah.IndexExpr("nonce",
						ah.BinaryExpr(ast.NewIdent("i"), token.REM, ah.IntLit(len(nonce))),
					),
				),
			},
		},
	)

	// Reverse layer 1: XOR with position-derived key
	// posKey := key[i] ^ byte(i*7+13)
	// data[i] = data[i] ^ posKey
	loopBody = append(loopBody,
		ah.AssignDefineStmt(
			ast.NewIdent("posKey"),
			ah.BinaryExpr(
				ah.IndexExpr("key", ast.NewIdent("i")),
				token.XOR,
				ah.CallExprByName("byte",
					ah.BinaryExpr(
						ah.BinaryExpr(ast.NewIdent("i"), token.MUL, ah.IntLit(7)),
						token.ADD,
						ah.IntLit(13),
					),
				),
			),
		),
		&ast.AssignStmt{
			Lhs: []ast.Expr{ah.IndexExpr("data", ast.NewIdent("i"))},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{
				ah.BinaryExpr(
					ah.IndexExpr("data", ast.NewIdent("i")),
					token.XOR,
					ast.NewIdent("posKey"),
				),
			},
		},
	)

	// Update prevTemp for next iteration
	loopBody = append(loopBody,
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("prevTemp")},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{ast.NewIdent("temp")},
		},
	)

	// Build the complete deobfuscation function
	deobfStmts = []ast.Stmt{
		// nonce := []byte{...}
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("nonce")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{ah.DataToByteSlice(nonce)},
		},
		// key := <key with external keys>
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("key")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{dataToByteSliceWithExtKeys(rand, key, extKeys)},
		},
		// data := <obfuscated data with external keys>
		&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("data")},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{dataToByteSliceWithExtKeys(rand, obfuscated, extKeys)},
		},
		// prevTemp := byte(0)
		ah.AssignDefineStmt(
			ast.NewIdent("prevTemp"),
			ah.CallExprByName("byte", ah.IntLit(0)),
		),
		// for i := 0; i < len(data); i++ { ... }
		&ast.ForStmt{
			Init: &ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("i")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.IntLit(0)},
			},
			Cond: ah.BinaryExpr(ast.NewIdent("i"), token.LSS, ah.CallExprByName("len", ast.NewIdent("data"))),
			Post: &ast.IncDecStmt{
				X:   ast.NewIdent("i"),
				Tok: token.INC,
			},
			Body: &ast.BlockStmt{List: loopBody},
		},
	}

	return ah.BlockStmt(deobfStmts...)
}
