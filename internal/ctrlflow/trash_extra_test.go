package ctrlflow

import (
	"go/ast"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"testing"

	"github.com/AeonDave/garble/internal/ssa2ast"
)

func TestIsValidIdentifier(t *testing.T) {
	cases := map[string]bool{
		"":        false,
		"1abc":    false,
		"a-b":     false,
		"int":     false,
		"_":       true,
		"_ok":     true,
		"hello1":  true,
		"go_lang": true,
	}
	for name, want := range cases {
		if got := isValidIdentifier(name); got != want {
			t.Fatalf("isValidIdentifier(%q)=%v, want %v", name, got, want)
		}
	}
}

func TestGenerateAssignEmpty(t *testing.T) {
	gen := &trashGenerator{
		rand:          mathrand.New(mathrand.NewSource(1)),
		typeConverter: &ssa2ast.TypeConverter{BasePos: token.NoPos},
	}
	stmt := gen.generateAssign(map[string]*definedVar{})
	if _, ok := stmt.(*ast.EmptyStmt); !ok {
		t.Fatalf("expected EmptyStmt, got %T", stmt)
	}
}

func TestGenerateRandomConstUnsupportedPanics(t *testing.T) {
	gen := &trashGenerator{
		rand:          mathrand.New(mathrand.NewSource(2)),
		typeConverter: &ssa2ast.TypeConverter{BasePos: token.NoPos},
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = gen.generateRandomConst(types.NewStruct(nil, nil), gen.rand)
}

func TestGenerateAssignUsesPredeclaredGuard(t *testing.T) {
	gen := &trashGenerator{
		rand:          mathrand.New(mathrand.NewSource(3)),
		typeConverter: &ssa2ast.TypeConverter{BasePos: token.NoPos},
	}
	stmts := gen.Generate(1, map[string]types.Type{
		"string": types.Typ[types.Int],
		"x":      types.Typ[types.Int],
	})
	var assign *ast.AssignStmt
	for _, stmt := range stmts {
		if a, ok := stmt.(*ast.AssignStmt); ok {
			assign = a
			break
		}
	}
	if assign == nil {
		t.Fatal("expected AssignStmt")
	}
	if assign.Tok != token.ASSIGN {
		t.Fatalf("expected ASSIGN due to predeclared name, got %v", assign.Tok)
	}
}

func TestIsInternal(t *testing.T) {
	cases := map[string]bool{
		"internal/foo":             true,
		"a/internal/b":             true,
		"a/b/internal":             true,
		"a/b/internal/c":           true,
		"a/b/notinternal/c":        false,
		"a/internalish/c":          false,
		"a/b/internalish/internal": true,
	}
	for path, want := range cases {
		if got := isInternal(path); got != want {
			t.Fatalf("isInternal(%q)=%v, want %v", path, got, want)
		}
	}
}

func TestCanConvertInterface(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	if !canConvert(types.Typ[types.Int], iface) {
		t.Fatal("expected int to convert to empty interface")
	}
}
