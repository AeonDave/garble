package ldflags

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/go-quicktest/qt"
)

func typecheckPkg(t *testing.T, pkgPath, src string) *types.Package {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.AllErrors)
	qt.Assert(t, qt.IsNil(err))

	info := &types.Info{
		Defs:   make(map[*ast.Ident]types.Object),
		Uses:   make(map[*ast.Ident]types.Object),
		Types:  make(map[ast.Expr]types.TypeAndValue),
		Scopes: make(map[ast.Node]*types.Scope),
	}

	pkg, err := new(types.Config).Check(pkgPath, fset, []*ast.File{file}, info)
	qt.Assert(t, qt.IsNil(err))
	return pkg
}

func TestResolveInjectedStringsFiltersPackageVars(t *testing.T) {
	src := `package sample

var Secret string
var Ignored int
`
	pkg := typecheckPkg(t, "example.com/app", src)

	captured := map[string]string{
		"example.com/app.Secret":  "secret-value",
		"example.com/app.Missing": "oops",
		"other/pkg.Secret":        "foreign",
	}

	resolved, err := ResolveInjectedStrings(pkg, captured)
	qt.Assert(t, qt.IsNil(err))

	secretVar := pkg.Scope().Lookup("Secret").(*types.Var)
	value, ok := resolved[secretVar]
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(value, "secret-value"))
	qt.Assert(t, qt.Equals(len(resolved), 1))
}
