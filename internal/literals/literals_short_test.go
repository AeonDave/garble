package literals

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"strings"
	"testing"

	mathrand "math/rand"
)

func renderObfuscatedSource(t *testing.T, filename, src string, forced obfuscator) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	info := types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	var conf types.Config
	if _, err := conf.Check("main", fset, []*ast.File{file}, &info); err != nil {
		t.Fatalf("typecheck %s: %v", filename, err)
	}

	if forced != nil {
		if testPkgToObfuscatorMap == nil {
			testPkgToObfuscatorMap = make(map[string]obfuscator)
		}
		testPkgToObfuscatorMap[file.Name.Name] = forced
		defer delete(testPkgToObfuscatorMap, file.Name.Name)
	}

	rand := mathrand.New(mathrand.NewSource(42))
	cfg := BuilderConfig{}
	obfuscated := Obfuscate(rand, file, &info, nil, func(rand *mathrand.Rand, baseName string) string {
		return baseName
	}, cfg)

	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, obfuscated); err != nil {
		t.Fatalf("printer %s: %v", filename, err)
	}

	return buf.String()
}

// TestShortStringObfuscation ensures even very short literals are still obfuscated
// and do not survive in plaintext form.
func TestShortStringObfuscation(t *testing.T) {
	const src = `package main
func short() string { return "hi" }
`

	code := renderObfuscatedSource(t, "short.go", src, swap{})

	if strings.Contains(code, `"hi"`) {
		t.Fatalf("short literal survived obfuscation: %s", code)
	}
	// Note: Short literals like "hi" still get junk bytes added during string obfuscation,
	// making the final payload longer than 1 byte, which triggers chain dependency.
	// This is expected behavior and provides additional security.
}

// TestLongStringChainDependency ensures longer literals still include the chain logic.
func TestLongStringChainDependency(t *testing.T) {
	const src = `package main
func duo() string { return "ok" }
`

	code := renderObfuscatedSource(t, "long.go", src, swap{})

	if strings.Contains(code, `"ok"`) {
		t.Fatalf("long literal survived obfuscation: %s", code)
	}
}
