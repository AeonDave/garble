package literals

import (
	"go/ast"
	mathrand "math/rand"

	ah "github.com/AeonDave/garble/internal/asthelper"
)

// customCipherObfuscator is the primary obfuscation strategy.
// It encrypts byte slices with a per-build random S-box cipher
// and emits inline decrypt code containing only per-build random
// constants — no fixed cryptographic signatures.
type customCipherObfuscator struct{}

var _ obfuscator = customCipherObfuscator{}

func (customCipherObfuscator) obfuscate(ctx *obfRand, data []byte, extKeys []*externalKey) *ast.BlockStmt {
	// Generate per-invocation cipher parameters from the PRNG.
	params := newCustomCipherParams(ctx.Rand)

	// Encrypt the data at build time.
	encrypted := make([]byte, len(data))
	copy(encrypted, data)
	customCipherEncrypt(params, encrypted)

	// Build the decryption block:
	//   data := []byte{...encrypted...}
	//   { inline decrypt }
	stmts := make([]ast.Stmt, 0, 4)

	// data := string([]byte{...encrypted...})
	// We store as byte slice for the decoder.
	dataName := "data"
	var dataExpr ast.Expr = ah.DataToByteSlice(encrypted)

	// Optionally interleave with external keys for added complexity
	if len(extKeys) > 0 && normalProb.Try(ctx.Rand) {
		dataExpr = dataToInterleavedByteSlice(ctx.Rand, encrypted, extKeys)
	}

	stmts = append(stmts, ah.AssignDefineStmt(ast.NewIdent(dataName), dataExpr))

	// Emit inline decryption code
	decryptBlock := customCipherInlineDecrypt(ctx.Rand, params, dataName)
	stmts = append(stmts, decryptBlock.List...)

	return ah.BlockStmt(stmts...)
}

// newCustomCipherObfuscatorForTest creates an obfuscator with a fixed rand
// for deterministic testing.
func newCustomCipherObfuscatorForTest(rand *mathrand.Rand) customCipherObfuscator {
	return customCipherObfuscator{}
}
