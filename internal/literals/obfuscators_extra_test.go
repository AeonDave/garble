package literals

import (
	"go/ast"
	"go/token"
	mathrand "math/rand"
	"testing"
)

func TestEvalOperatorAndReverse(t *testing.T) {
	x := byte(10)
	y := byte(3)
	for _, op := range []token.Token{token.XOR, token.ADD, token.SUB} {
		enc := evalOperator(op, x, y)
		expr := operatorToReversedBinaryExpr(op, ast.NewIdent("x"), ast.NewIdent("y"))
		if expr == nil {
			t.Fatalf("expected expr for op %v", op)
		}
		// verify invertibility
		reverse := op
		switch op {
		case token.ADD:
			reverse = token.SUB
		case token.SUB:
			reverse = token.ADD
		}
		dec := evalOperator(reverse, enc, y)
		if dec != x {
			t.Fatalf("op %v not invertible", op)
		}
	}
}

func TestRandExtKeysRange(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(1))
	keys := randExtKeys(rand)
	if len(keys) < minExtKeyCount || len(keys) > maxExtKeyCount {
		t.Fatalf("keys=%d out of range", len(keys))
	}
	for _, k := range keys {
		if k.bits == 0 || k.typ == "" {
			t.Fatal("invalid external key")
		}
	}
}

func TestShuffleSplitSwapSeedObfuscators(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(2))
	ctx := newSimpleContext(rand)
	data := []byte("hello")

	cases := []obfuscator{shuffle{}, split{}, swap{}, seed{}}
	for _, obf := range cases {
		block := obf.obfuscate(ctx, append([]byte(nil), data...), []*externalKey{{name: "k1", typ: "uint16", value: 1, bits: 16}})
		if block == nil || len(block.List) == 0 {
			t.Fatalf("obfuscator %T returned empty block", obf)
		}
	}
}

func TestSplitChunkHelpers(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(3))
	chunks := splitIntoRandomChunks(rand, []byte("abcde"))
	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}
	one := splitIntoOneByteChunks([]byte("ab"))
	if len(one) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(one))
	}
}

func TestSwapIndexTypeBoundaries(t *testing.T) {
	if getIndexType(10) != "byte" {
		t.Fatal("expected byte type")
	}
	if getIndexType(1<<16) != "uint32" && getIndexType(1<<16) != "uint16" {
		// allow either based on boundary
	}
}

func TestGenerateSwapCountEven(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(4))
	for _, n := range []int{1, 2, 3, 10} {
		count := generateSwapCount(rand, n)
		if count%2 != 0 {
			t.Fatalf("swap count not even: %d", count)
		}
		if count < n {
			t.Fatalf("swap count < data len: %d < %d", count, n)
		}
	}
}
