package ctrlflow

import (
	"go/ast"
	mathrand "math/rand"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestXorHardeningAddsOpaquePredicate(t *testing.T) {
	rnd := mathrand.New(mathrand.NewSource(1))
	ssaRemap := make(map[ssa.Value]ast.Expr)

	decl, stmt := (xorHardening{}).Apply(nil, ssaRemap, rnd)
	if decl == nil {
		t.Fatal("expected global key declaration")
	}
	if stmt == nil {
		t.Fatal("expected prologue statement")
	}

	block, ok := stmt.(*ast.BlockStmt)
	if !ok {
		t.Fatalf("expected block stmt, got %T", stmt)
	}
	if len(block.List) != 2 {
		t.Fatalf("expected 2 statements in block, got %d", len(block.List))
	}
	if _, ok := block.List[0].(*ast.AssignStmt); !ok {
		t.Fatalf("expected assignment as first statement, got %T", block.List[0])
	}
	if _, ok := block.List[1].(*ast.IfStmt); !ok {
		t.Fatalf("expected if statement as second statement, got %T", block.List[1])
	}
}
