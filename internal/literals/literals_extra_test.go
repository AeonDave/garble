package literals

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"strings"
	"testing"
)

func parseAndTypecheck(t *testing.T, src string) (*ast.File, *types.Info, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	var conf types.Config
	if _, err := conf.Check("p", fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("typecheck failed: %v", err)
	}
	return file, info, fset
}

func newTestBuilder(t *testing.T, file *ast.File) *Builder {
	t.Helper()
	rand := mathrand.New(mathrand.NewSource(1))
	return NewBuilder(rand, file, func(r *mathrand.Rand, base string) string { return base }, BuilderConfig{})
}

func TestObfuscateFileSkipsConstAndLinkStrings(t *testing.T) {
	src := `package p

const keep = "keep"
var obf = "hide"
var link = "link"
`
	file, info, fset := parseAndTypecheck(t, src)
	linkStrings := make(map[*types.Var]string)
	for ident, obj := range info.Defs {
		if obj == nil {
			continue
		}
		if ident.Name == "link" {
			linkStrings[obj.(*types.Var)] = "link"
		}
	}
	builder := newTestBuilder(t, file)
	obfuscated := builder.ObfuscateFile(file, info, linkStrings)
	builder.Finalize(obfuscated)

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, obfuscated); err != nil {
		t.Fatalf("print failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\"keep\"") {
		t.Fatal("expected const string to remain unobfuscated")
	}
	if !strings.Contains(out, "\"link\"") {
		t.Fatal("expected link string to remain unobfuscated")
	}
	if strings.Contains(out, "\"hide\"") {
		t.Fatal("expected obfuscated string to be removed")
	}
}

func TestHandleCompositeLiteralByteSlice(t *testing.T) {
	src := `package p
var b = []byte{1,2,3}
var p = &[]byte{4,5}
`
	file, info, _ := parseAndTypecheck(t, src)
	builder := newTestBuilder(t, file)

	var sliceLit, ptrLit *ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || cl.Type == nil {
			return true
		}
		if sliceLit == nil {
			sliceLit = cl
			return true
		}
		ptrLit = cl
		return true
	})
	if sliceLit == nil || ptrLit == nil {
		t.Fatal("expected composite literals")
	}

	if got := handleCompositeLiteral(builder.obfRand, false, sliceLit, info); got == nil {
		t.Fatal("expected obfuscated slice literal")
	}
	if got := handleCompositeLiteral(builder.obfRand, true, ptrLit, info); got == nil {
		t.Fatal("expected obfuscated pointer literal")
	}
}

func TestHandleCompositeLiteralRejectsNonByte(t *testing.T) {
	src := `package p
var b = []int{1,2,3}
`
	file, info, _ := parseAndTypecheck(t, src)
	builder := newTestBuilder(t, file)

	var lit *ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		if cl, ok := n.(*ast.CompositeLit); ok {
			lit = cl
			return false
		}
		return true
	})
	if lit == nil {
		t.Fatal("expected composite literal")
	}
	if got := handleCompositeLiteral(builder.obfRand, false, lit, info); got != nil {
		t.Fatal("expected non-byte literal to be skipped")
	}
}

func TestHandleCompositeLiteralRejectsNonConst(t *testing.T) {
	src := `package p
var x = 1
var b = []byte{byte(x)}
`
	file, info, _ := parseAndTypecheck(t, src)
	builder := newTestBuilder(t, file)

	var lit *ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		if cl, ok := n.(*ast.CompositeLit); ok {
			lit = cl
			return false
		}
		return true
	})
	if lit == nil {
		t.Fatal("expected composite literal")
	}
	if got := handleCompositeLiteral(builder.obfRand, false, lit, info); got != nil {
		t.Fatal("expected non-const literal to be skipped")
	}
}

func TestByteLitWithExtKey(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(2))
	keys := []*externalKey{{name: "k1", typ: "uint16", value: 0x4242, bits: 16}}
	literal := byteLitWithExtKey(rand, 0x11, keys, externalKeyProbability(0))
	if _, ok := literal.(*ast.BasicLit); !ok {
		t.Fatalf("expected BasicLit when ext key disabled, got %T", literal)
	}
	_ = byteLitWithExtKey(rand, 0x11, keys, externalKeyProbability(1.0))
	if keys[0].refs == 0 {
		t.Fatal("expected external key to be used")
	}
}

func TestGetNextObfuscatorUsesTestObfuscator(t *testing.T) {
	rand := mathrand.New(mathrand.NewSource(3))
	nameFunc := func(r *mathrand.Rand, base string) string { return base }
	obf := &obfRand{Rand: rand, testObfuscator: swap{}, proxyDispatcher: newProxyDispatcher(rand, nameFunc)}

	if got := getNextObfuscator(obf, maxSize); got == nil {
		t.Fatal("expected test obfuscator for maxSize")
	}
	if got := getNextObfuscator(obf, maxSize+1); got == nil {
		t.Fatal("expected test obfuscator for large size")
	}
}
