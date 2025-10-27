package literals

import (
	"encoding/binary"
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "github.com/AeonDave/garble/internal/asthelper"
)

type simple struct{}

// check that the obfuscator interface is implemented
var _ obfuscator = simple{}

const (
	irreversibleBlockSize = 16
	irreversibleRounds    = 4
)

var irreversibleRoundConstant uint64 = 0x9e3779b185ebca87

var irreversibleSBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var irreversibleInvSBox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

func deriveIrreversibleSubkeys(material []byte) []uint64 {
	if len(material) < irreversibleRounds*8 {
		panic("literals: insufficient HKDF material for irreversible subkeys")
	}
	subkeys := make([]uint64, irreversibleRounds)
	for i := 0; i < irreversibleRounds; i++ {
		subkeys[i] = binary.LittleEndian.Uint64(material[i*8 : (i+1)*8])
	}
	return subkeys
}

func irreversibleEncryptLiteral(data []byte, subkeys []uint64) []byte {
	if len(subkeys) != irreversibleRounds {
		panic("literals: unexpected irreversible subkey count")
	}

	if len(data) == 0 {
		return []byte{}
	}

	paddedLen := ((len(data) + irreversibleBlockSize - 1) / irreversibleBlockSize) * irreversibleBlockSize
	buf := make([]byte, paddedLen)
	copy(buf, data)
	pad := byte(paddedLen - len(data))
	for i := len(data); i < paddedLen; i++ {
		buf[i] = pad
	}

	for i := range buf {
		buf[i] = irreversibleSBox[buf[i]]
	}

	for offset := 0; offset < len(buf); offset += irreversibleBlockSize {
		feistelEncryptBlock(buf[offset:offset+irreversibleBlockSize], subkeys)
	}

	return buf
}

func feistelEncryptBlock(block []byte, subkeys []uint64) {
	left := binary.LittleEndian.Uint64(block[:8])
	right := binary.LittleEndian.Uint64(block[8:])

	for _, key := range subkeys {
		f := feistelRound(right, key)
		left, right = right, left^f
	}

	binary.LittleEndian.PutUint64(block[:8], left)
	binary.LittleEndian.PutUint64(block[8:], right)
}

func feistelRound(value, key uint64) uint64 {
	mix := value ^ key
	rot := uint(key&63) | 1
	mix = (mix << rot) | (mix >> (64 - rot))
	mix ^= (key << 17) | (key >> 47)
	mix += irreversibleRoundConstant
	return mix
}

// obfuscate implements an improved XOR-based obfuscation with:
// 1. Nonce for uniqueness (prevents pattern analysis across builds)
// 2. Position-dependent key derivation (each byte uses position-derived key)
// 3. Chained operations with rotation (dependencies between bytes)
// 4. External key mixing for additional entropy
//
// This function routes to either reversible or irreversible implementation
// based on the -reversible flag setting.
//
// Reversible mode (with -reversible flag):
//   - Uses symmetric operations (XOR, ADD, SUB)
//   - Supports garble reverse functionality
//   - Weaker security but maintains backward compatibility
//
// Irreversible mode (default, without -reversible flag):
//   - Byte substitution + Feistel mixing for data at rest
//   - Deterministic subkeys derived from HKDF per literal
//   - Does not support garble reverse
func (simple) obfuscate(ctx *obfRand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	if reversibleMode {
		return obfuscateReversible(ctx.Rand, data, extKeys)
	}
	return obfuscateIrreversible(ctx, data, extKeys)
}

func obfuscateIrreversible(ctx *obfRand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	if ctx == nil {
		panic("literals: nil context for irreversible obfuscator")
	}
	if len(data) == 0 {
		return ah.BlockStmt(
			ah.AssignDefineStmt(ast.NewIdent("data"), ah.DataToByteSlice(nil)),
		)
	}
	if ctx.keyProvider == nil {
		panic("literals: missing key provider for irreversible obfuscator")
	}

	material := ctx.keyProvider.NextIrreversibleMaterial(irreversibleRounds * 8)
	subkeys := deriveIrreversibleSubkeys(material)

	cipher := irreversibleEncryptLiteral(data, subkeys)
	cipherCopy := append([]byte(nil), cipher...)

	block := &ast.BlockStmt{}
	block.List = append(block.List, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("data")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{dataToByteSliceWithExtKeys(ctx.Rand, cipherCopy, extKeys)},
	})

	subkeyElts := make([]ast.Expr, len(subkeys))
	for i, sk := range subkeys {
		subkeyElts[i] = ah.UintLit(sk)
	}

	block.List = append(block.List, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("subkeys")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{
			&ast.CompositeLit{
				Type: &ast.ArrayType{Elt: ast.NewIdent("uint64")},
				Elts: subkeyElts,
			},
		},
	})

	if ctx.irreversibleHelper == nil {
		panic("literals: irreversible helper is nil")
	}
	ctx.irreversibleHelper.used = true

	block.List = append(block.List, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("data")},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{
			&ast.CallExpr{
				Fun: ast.NewIdent(ctx.irreversibleHelper.funcName),
				Args: []ast.Expr{
					ast.NewIdent("data"),
					ast.NewIdent("subkeys"),
					ah.IntLit(len(data)),
				},
			},
		},
	})

	block.List = append(block.List, ah.ReturnStmt(ast.NewIdent("data")))
	return block
}

// obfuscateReversible implements the reversible XOR-based algorithm.
// This is the original implementation that maintains full reversibility.
func obfuscateReversible(rand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
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
	loopBody := []ast.Stmt{}

	// Reverse layer 3: Remove chain dependency (if not first byte)
	hasChainDependency := len(data) > 1
	if hasChainDependency {
		// temp := data[i]
		loopBody = append(loopBody,
			ah.AssignDefineStmt(
				ast.NewIdent("temp"),
				ah.IndexExpr("data", ast.NewIdent("i")),
			),
		)
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

	// Update prevTemp for next iteration (only if chain dependency is present)
	if hasChainDependency {
		loopBody = append(loopBody,
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("prevTemp")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{ast.NewIdent("temp")},
			},
		)
	}

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
	}
	// Only declare prevTemp if chain dependency is present
	if hasChainDependency {
		deobfStmts = append(deobfStmts,
			ah.AssignDefineStmt(
				ast.NewIdent("prevTemp"),
				ah.CallExprByName("byte", ah.IntLit(0)),
			),
		)
	}
	// for i := 0; i < len(data); i++ { ... }
	deobfStmts = append(deobfStmts,
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
	)

	return ah.BlockStmt(deobfStmts...)
}
