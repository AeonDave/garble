package literals

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	mathrand "math/rand"
	"testing"
)

func TestProxyDispatcherNoValuesNoDecls(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(1))
	pd := newProxyDispatcher(rand, func(r *mathrand.Rand, base string) string { return base })
	file := &ast.File{Name: ast.NewIdent("p")}
	pd.AddToFile(file)
	if len(file.Decls) != 0 {
		t.Fatalf("expected no decls, got %d", len(file.Decls))
	}
}

func TestProxyDispatcherHideValueAddsDecls(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(2))
	pd := newProxyDispatcher(rand, func(r *mathrand.Rand, base string) string { return base })
	_ = pd.HideValue(ast.NewIdent("x"), ast.NewIdent("int"))

	file := &ast.File{Name: ast.NewIdent("p"), Scope: ast.NewScope(nil)}
	pd.AddToFile(file)
	if len(file.Decls) == 0 {
		t.Fatal("expected decls after HideValue")
	}

	// ensure code can be printed without panic
	fset := token.NewFileSet()
	if err := formatCheck(fset, file); err != nil {
		t.Fatalf("format check failed: %v", err)
	}
}

func formatCheck(fset *token.FileSet, file *ast.File) error {
	var buf bytes.Buffer
	return printer.Fprint(&buf, fset, file)
}
