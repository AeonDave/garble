package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestFindDangerousDirective(t *testing.T) {
	src := `package p

//go:nosplit
func f() {}
`
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse file: %v", err)
	}

	directive, pos := findDangerousDirective([]*ast.File{file})
	if directive != "//go:nosplit" {
		t.Fatalf("expected //go:nosplit, got %q", directive)
	}
	if pos == (token.Position{}) {
		t.Fatalf("expected non-zero position for directive")
	}
}

func TestFindDangerousDirectiveNone(t *testing.T) {
	src := `package p

func f() {}
`
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse file: %v", err)
	}

	directive, pos := findDangerousDirective([]*ast.File{file})
	if directive != "" || pos != (token.Position{}) {
		t.Fatalf("expected no directive, got %q at %v", directive, pos)
	}
}
