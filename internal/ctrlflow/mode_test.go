package ctrlflow

import (
	"go/ast"
	"testing"
)

func makeFuncDecl(withBody bool) *ast.FuncDecl {
	decl := &ast.FuncDecl{
		Name: ast.NewIdent("test"),
	}
	if withBody {
		decl.Body = &ast.BlockStmt{List: []ast.Stmt{&ast.EmptyStmt{Implicit: true}}}
	}
	return decl
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"", ModeAuto, false},
		{"auto", ModeAuto, false},
		{"1", ModeAuto, false},
		{"true", ModeAuto, false},
		{"off", ModeOff, false},
		{"0", ModeOff, false},
		{"false", ModeOff, false},
		{"directives", ModeAnnotated, false},
		{"annotated", ModeAnnotated, false},
		{"all", ModeAll, false},
		{"something", ModeOff, true},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("ParseMode(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseMode(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestShouldObfuscate(t *testing.T) {
	fnWithBody := makeFuncDecl(true)
	fnNoBody := makeFuncDecl(false)

	if shouldObfuscate(ModeOff, fnWithBody, false) {
		t.Fatal("ModeOff should never obfuscate")
	}
	if !shouldObfuscate(ModeAnnotated, fnWithBody, true) {
		t.Fatal("ModeAnnotated should respect directives")
	}
	if shouldObfuscate(ModeAnnotated, fnWithBody, false) {
		t.Fatal("ModeAnnotated requires directive")
	}
	if !shouldObfuscate(ModeAuto, fnWithBody, false) {
		t.Fatal("ModeAuto should obfuscate functions with bodies")
	}
	if shouldObfuscate(ModeAuto, fnNoBody, false) {
		t.Fatal("ModeAuto should skip functions without bodies")
	}
	if !shouldObfuscate(ModeAll, fnWithBody, false) {
		t.Fatal("ModeAll should ignore directives")
	}
}
