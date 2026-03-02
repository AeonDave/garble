package literals

import (
	"crypto/sha256"
	"encoding/binary"
	"go/ast"
	"go/token"
	mathrand "math/rand"

	ah "github.com/AeonDave/garble/internal/asthelper"
)

// customCipherParams holds the per-build cipher parameters.
// Every field is randomly generated at obfuscation time and embedded
// verbatim into the generated decoder, so the output binary contains
// no fixed constants recognisable by signature scanners.
type customCipherParams struct {
	sbox    [256]byte // random permutation (Fisher-Yates)
	invSbox [256]byte // inverse permutation for decryption
	rounds  int       // number of SPN rounds (4–6)
	keys    []uint32  // per-round keys derived from seed
}

// newCustomCipherParams creates a fresh cipher parameterisation.
// The S-box is a full 256-byte permutation produced by Fisher-Yates,
// so it has no algebraic structure that AV heuristics can match.
func newCustomCipherParams(rand *mathrand.Rand) *customCipherParams {
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}
	// Fisher-Yates shuffle — produces a uniformly random permutation.
	for i := 255; i > 0; i-- {
		j := rand.Intn(i + 1)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	var invSbox [256]byte
	for i, v := range sbox {
		invSbox[v] = byte(i)
	}

	rounds := 4 + rand.Intn(3) // 4, 5, or 6 rounds
	keys := deriveRoundKeys(rand, rounds)

	return &customCipherParams{
		sbox:    sbox,
		invSbox: invSbox,
		rounds:  rounds,
		keys:    keys,
	}
}

// deriveRoundKeys produces per-round 32-bit keys from the PRNG.
func deriveRoundKeys(rand *mathrand.Rand, rounds int) []uint32 {
	keys := make([]uint32, rounds)
	for i := range keys {
		keys[i] = rand.Uint32()
	}
	return keys
}

// --- Polymorphic code generation helpers ---

// cipherVarNames holds per-stub random variable names for the inline
// decryption code. Using unique names for each literal site makes the
// generated code polymorphic, breaking pattern-matching heuristics in
// decompilers and deobfuscation tools.
type cipherVarNames struct {
	invSbox  string // inverse S-box array
	rkeys    string // round keys array
	round    string // round loop variable
	key      string // current round key
	keyBytes string // round key split into bytes
	idx      string // loop index
}

// randomVarName generates a short random Go identifier like "_a3x".
func randomVarName(rand *mathrand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	buf := [4]byte{
		'_',
		letters[rand.Intn(len(letters))],
		digits[rand.Intn(len(digits))],
		letters[rand.Intn(len(letters))],
	}
	return string(buf[:])
}

// newCipherVarNames generates a set of unique random variable names.
func newCipherVarNames(rand *mathrand.Rand) *cipherVarNames {
	seen := make(map[string]bool)
	gen := func() string {
		for {
			n := randomVarName(rand)
			if !seen[n] {
				seen[n] = true
				return n
			}
		}
	}
	return &cipherVarNames{
		invSbox:  gen(),
		rkeys:    gen(),
		round:    gen(),
		key:      gen(),
		keyBytes: gen(),
		idx:      gen(),
	}
}

// mbaXOR returns an AST expression algebraically equivalent to a ^ b,
// randomly choosing between plain XOR and Mixed Boolean-Arithmetic (MBA)
// encodings. The makeA/makeB factories are called to produce fresh AST
// nodes for each occurrence of the sub-expressions.
//
// Identity: (a | b) - (a & b) == a ^ b
// Identity: (a + b) - 2*(a & b) == a ^ b
func mbaXOR(rand *mathrand.Rand, makeA, makeB func() ast.Expr) ast.Expr {
	switch rand.Intn(3) {
	case 1: // (a | b) - (a & b)
		return ah.BinaryExpr(
			ah.BinaryExpr(makeA(), token.OR, makeB()),
			token.SUB,
			ah.BinaryExpr(makeA(), token.AND, makeB()),
		)
	case 2: // (a + b) - 2*(a & b)
		return ah.BinaryExpr(
			ah.BinaryExpr(makeA(), token.ADD, makeB()),
			token.SUB,
			ah.BinaryExpr(ah.IntLit(2), token.MUL,
				ah.BinaryExpr(makeA(), token.AND, makeB())),
		)
	default: // a ^ b
		return ah.BinaryExpr(makeA(), token.XOR, makeB())
	}
}

// mbaXORAssign returns a statement equivalent to lhs ^= rhs,
// randomly choosing between plain XOR_ASSIGN and MBA assignment forms.
func mbaXORAssign(rand *mathrand.Rand, makeLhs, makeRhs func() ast.Expr) ast.Stmt {
	switch rand.Intn(3) {
	case 1: // lhs = (lhs | rhs) - (lhs & rhs)
		return ah.AssignStmt(makeLhs(),
			ah.BinaryExpr(
				ah.BinaryExpr(makeLhs(), token.OR, makeRhs()),
				token.SUB,
				ah.BinaryExpr(makeLhs(), token.AND, makeRhs()),
			),
		)
	case 2: // lhs = (lhs + rhs) - 2*(lhs & rhs)
		return ah.AssignStmt(makeLhs(),
			ah.BinaryExpr(
				ah.BinaryExpr(makeLhs(), token.ADD, makeRhs()),
				token.SUB,
				ah.BinaryExpr(ah.IntLit(2), token.MUL,
					ah.BinaryExpr(makeLhs(), token.AND, makeRhs())),
			),
		)
	default: // lhs ^= rhs
		return &ast.AssignStmt{
			Lhs: []ast.Expr{makeLhs()},
			Tok: token.XOR_ASSIGN,
			Rhs: []ast.Expr{makeRhs()},
		}
	}
}

// --- Build-time encryption (executed during obfuscation) ---

// customCipherEncrypt encrypts data in-place using the cipher parameters.
// The algorithm is a byte-level substitution-permutation network:
//  1. Substitute each byte through the random S-box.
//  2. Apply a CBC-like diffusion pass using the round key.
//
// We repeat for `rounds` rounds.
func customCipherEncrypt(p *customCipherParams, data []byte) {
	n := len(data)
	if n == 0 {
		return
	}
	for r := 0; r < p.rounds; r++ {
		k := p.keys[r]
		kb := [4]byte{byte(k), byte(k >> 8), byte(k >> 16), byte(k >> 24)}

		// Substitution layer
		for i := range data {
			data[i] = p.sbox[data[i]]
		}

		// Diffusion layer: CBC-like chaining with round key bytes
		// First byte is XORed with kb[0]
		data[0] ^= kb[0]
		for i := 1; i < n; i++ {
			data[i] ^= data[i-1] ^ kb[i%4]
		}
	}
}

// customCipherDecrypt decrypts data in-place (inverse of encrypt).
func customCipherDecrypt(p *customCipherParams, data []byte) {
	n := len(data)
	if n == 0 {
		return
	}
	for r := p.rounds - 1; r >= 0; r-- {
		k := p.keys[r]
		kb := [4]byte{byte(k), byte(k >> 8), byte(k >> 16), byte(k >> 24)}

		// Inverse diffusion: undo CBC chaining from the end
		for i := n - 1; i >= 1; i-- {
			data[i] ^= data[i-1] ^ kb[i%4]
		}
		data[0] ^= kb[0]

		// Inverse substitution
		for i := range data {
			data[i] = p.invSbox[data[i]]
		}
	}
}

// --- Inline code generation (emitted into obfuscated Go source) ---

// customCipherInlineDecrypt generates an ast.BlockStmt that decrypts
// `dataIdent` in-place at runtime. All cipher parameters (inverse S-box,
// round keys, round count) are embedded as literals in the generated code.
// Variable names and XOR expressions are randomised per invocation to
// produce polymorphic instruction sequences in the compiled binary.
func customCipherInlineDecrypt(rand *mathrand.Rand, p *customCipherParams, dataIdent string) *ast.BlockStmt {
	names := newCipherVarNames(rand)
	stmts := make([]ast.Stmt, 0, 8)

	// Emit inverse S-box as [256]byte{...}
	invSboxElts := make([]ast.Expr, 256)
	for i, v := range p.invSbox {
		invSboxElts[i] = ah.IntLit(int(v))
	}
	invSboxLit := &ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: ah.IntLit(256),
			Elt: ast.NewIdent("byte"),
		},
		Elts: invSboxElts,
	}
	stmts = append(stmts, ah.AssignDefineStmt(ast.NewIdent(names.invSbox), invSboxLit))

	// Emit round keys as [rounds]uint32{...}
	keyElts := make([]ast.Expr, len(p.keys))
	for i, k := range p.keys {
		keyElts[i] = ah.UintLit(uint64(k))
	}
	keysLit := &ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: ah.IntLit(len(p.keys)),
			Elt: ast.NewIdent("uint32"),
		},
		Elts: keyElts,
	}
	stmts = append(stmts, ah.AssignDefineStmt(ast.NewIdent(names.rkeys), keysLit))

	// for round := rounds-1; round >= 0; round--
	di := ast.NewIdent(dataIdent)
	roundLoop := &ast.ForStmt{
		Init: ah.AssignDefineStmt(ast.NewIdent(names.round), ah.IntLit(p.rounds-1)),
		Cond: ah.BinaryExpr(ast.NewIdent(names.round), token.GEQ, ah.IntLit(0)),
		Post: &ast.IncDecStmt{X: ast.NewIdent(names.round), Tok: token.DEC},
		Body: &ast.BlockStmt{List: customCipherRoundBody(rand, di, names)},
	}
	stmts = append(stmts, roundLoop)

	return ah.BlockStmt(stmts...)
}

// customCipherRoundBody generates the body of one decryption round.
// It uses Mixed Boolean-Arithmetic (MBA) to vary XOR instruction patterns.
func customCipherRoundBody(rand *mathrand.Rand, dataIdent *ast.Ident, names *cipherVarNames) []ast.Stmt {
	stmts := make([]ast.Stmt, 0, 8)

	// key := rkeys[round]
	stmts = append(stmts, ah.AssignDefineStmt(
		ast.NewIdent(names.key),
		ah.IndexExpr(names.rkeys, ast.NewIdent(names.round)),
	))

	// keyBytes := [4]byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)}
	kbElts := []ast.Expr{
		ah.CallExprByName("byte", ast.NewIdent(names.key)),
		ah.CallExprByName("byte", ah.BinaryExpr(ast.NewIdent(names.key), token.SHR, ah.IntLit(8))),
		ah.CallExprByName("byte", ah.BinaryExpr(ast.NewIdent(names.key), token.SHR, ah.IntLit(16))),
		ah.CallExprByName("byte", ah.BinaryExpr(ast.NewIdent(names.key), token.SHR, ah.IntLit(24))),
	}
	kbLit := &ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: ah.IntLit(4),
			Elt: ast.NewIdent("byte"),
		},
		Elts: kbElts,
	}
	stmts = append(stmts, ah.AssignDefineStmt(ast.NewIdent(names.keyBytes), kbLit))

	// Inverse diffusion: for idx := len(data)-1; idx >= 1; idx--
	// The inner XOR uses MBA to vary the instruction pattern per build.
	innerXOR := mbaXOR(rand,
		func() ast.Expr {
			return ah.IndexExpr(dataIdent.Name, ah.BinaryExpr(ast.NewIdent(names.idx), token.SUB, ah.IntLit(1)))
		},
		func() ast.Expr {
			return ah.IndexExpr(names.keyBytes, ah.BinaryExpr(ast.NewIdent(names.idx), token.REM, ah.IntLit(4)))
		},
	)
	invDiffusion := &ast.ForStmt{
		Init: ah.AssignDefineStmt(
			ast.NewIdent(names.idx),
			ah.BinaryExpr(ah.CallExprByName("len", dataIdent), token.SUB, ah.IntLit(1)),
		),
		Cond: ah.BinaryExpr(ast.NewIdent(names.idx), token.GEQ, ah.IntLit(1)),
		Post: &ast.IncDecStmt{X: ast.NewIdent(names.idx), Tok: token.DEC},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			// data[idx] ^= innerXOR
			&ast.AssignStmt{
				Lhs: []ast.Expr{ah.IndexExpr(dataIdent.Name, ast.NewIdent(names.idx))},
				Tok: token.XOR_ASSIGN,
				Rhs: []ast.Expr{innerXOR},
			},
		}},
	}
	stmts = append(stmts, invDiffusion)

	// data[0] ^= keyBytes[0] — uses MBA assignment variant
	stmts = append(stmts, mbaXORAssign(rand,
		func() ast.Expr { return ah.IndexExpr(dataIdent.Name, ah.IntLit(0)) },
		func() ast.Expr { return ah.IndexExpr(names.keyBytes, ah.IntLit(0)) },
	))

	// Inverse substitution: for idx := range data
	invSubst := &ast.RangeStmt{
		Key: ast.NewIdent(names.idx),
		Tok: token.DEFINE,
		X:   dataIdent,
		Body: &ast.BlockStmt{List: []ast.Stmt{
			// data[idx] = invSbox[data[idx]]
			ah.AssignStmt(
				ah.IndexExpr(dataIdent.Name, ast.NewIdent(names.idx)),
				ah.IndexExpr(names.invSbox, ah.IndexExpr(dataIdent.Name, ast.NewIdent(names.idx))),
			),
		}},
	}
	stmts = append(stmts, invSubst)

	return stmts
}

// customCipherKeyFromSeed derives a deterministic cipher seed from a
// SHA-256 hash of the obfuscation seed and a counter.  This simple
// construction produces no recognisable constants in the output binary.
func customCipherKeyFromSeed(seed []byte, counter uint64) [32]byte {
	var buf [40]byte // 32-byte seed + 8-byte counter
	copy(buf[:], seed)
	binary.LittleEndian.PutUint64(buf[32:], counter)
	return sha256.Sum256(buf[:])
}
