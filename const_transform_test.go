package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	consts "github.com/AeonDave/garble/internal/consts"
	"github.com/go-quicktest/qt"
)

func parseConstFixture(t *testing.T, src string) (*ast.File, *types.Package, *types.Info) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	qt.Assert(t, qt.IsNil(err))

	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}

	pkg, err := new(types.Config).Check("test/consts", fset, []*ast.File{file}, info)
	qt.Assert(t, qt.IsNil(err))

	return file, pkg, info
}

func TestComputeConstTransformsFiltersEligibleConsts(t *testing.T) {
	t.Parallel()

	const src = `package sample

type alias string

const (
    runtimeConst = "hide-me"
    arrayLen = "length"
    aliasConst alias = "typed"
    ExportedConst = "public"
    onlyCase = "case-only"
)

var sink = runtimeConst + string(aliasConst)
var arr = [len(arrayLen)]byte{}

func needsConst(v string) bool {
    switch v {
    case onlyCase:
        return true
    }
    return false
}

var _ = needsConst(sink)
`

	file, pkg, info := parseConstFixture(t, src)
	transforms := consts.ComputeTransforms([]*ast.File{file}, info, pkg)

	qt.Assert(t, qt.HasLen(transforms, 1))

	runtimeObj, _ := pkg.Scope().Lookup("runtimeConst").(*types.Const)
	qt.Assert(t, qt.IsNotNil(runtimeObj))
	qt.Assert(t, qt.IsNotNil(transforms[runtimeObj]))

	_, hasArray := transforms[pkg.Scope().Lookup("arrayLen").(*types.Const)]
	qt.Assert(t, qt.IsFalse(hasArray))

	_, hasAlias := transforms[pkg.Scope().Lookup("aliasConst").(*types.Const)]
	qt.Assert(t, qt.IsFalse(hasAlias))

	_, hasExported := transforms[pkg.Scope().Lookup("ExportedConst").(*types.Const)]
	qt.Assert(t, qt.IsFalse(hasExported))

	_, hasCase := transforms[pkg.Scope().Lookup("onlyCase").(*types.Const)]
	qt.Assert(t, qt.IsFalse(hasCase))
}

func TestRewriteConstDeclsConvertsAndPreservesMetadata(t *testing.T) {
	const src = `package sample

const (
    // runtimeDoc
    runtimeSecret, caseLabel = "secret value", "case-only" // trailing runtime comment
    arrayLen = "sentinel"

    // pairDoc
    pairLeft, pairRight = "left", "right" // trailing pair comment
)

var sink = runtimeSecret + pairLeft + pairRight
var arr = [len(arrayLen)]byte{}

func wantsConst(s string) bool {
    switch s {
    case caseLabel:
        return true
    }
    return false
}

var _ = wantsConst(sink)
`

	file, pkg, info := parseConstFixture(t, src)
	transforms := consts.ComputeTransforms([]*ast.File{file}, info, pkg)

	runtimeObj := pkg.Scope().Lookup("runtimeSecret").(*types.Const)
	caseObj := pkg.Scope().Lookup("caseLabel").(*types.Const)
	arrayObj := pkg.Scope().Lookup("arrayLen").(*types.Const)
	leftObj := pkg.Scope().Lookup("pairLeft").(*types.Const)
	rightObj := pkg.Scope().Lookup("pairRight").(*types.Const)

	qt.Assert(t, qt.IsNotNil(transforms[runtimeObj]))
	qt.Assert(t, qt.IsNotNil(transforms[leftObj]))
	qt.Assert(t, qt.IsNotNil(transforms[rightObj]))
	qt.Assert(t, qt.IsNil(transforms[caseObj]))
	qt.Assert(t, qt.IsNil(transforms[arrayObj]))

	consts.RewriteDecls(file, info, transforms)

	constNames := make(map[string]bool)
	varDocs := make(map[string]*ast.CommentGroup)
	varComments := make(map[string]*ast.CommentGroup)

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		switch gen.Tok {
		case token.CONST:
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for _, name := range vs.Names {
					constNames[name.Name] = true
				}
			}
		case token.VAR:
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for _, name := range vs.Names {
					switch name.Name {
					case "runtimeSecret", "pairLeft", "pairRight":
						varDocs[name.Name] = vs.Doc
						varComments[name.Name] = vs.Comment
					}
				}
			}
		}
	}

	qt.Assert(t, qt.IsTrue(constNames["caseLabel"]))
	qt.Assert(t, qt.IsTrue(constNames["arrayLen"]))
	qt.Assert(t, qt.IsFalse(constNames["runtimeSecret"]))

	qt.Assert(t, qt.IsNotNil(varDocs["runtimeSecret"]))
	qt.Assert(t, qt.IsNotNil(varComments["runtimeSecret"]))
	qt.Assert(t, qt.IsNotNil(varDocs["pairLeft"]))
	qt.Assert(t, qt.IsNotNil(varComments["pairLeft"]))
	qt.Assert(t, qt.IsNil(varDocs["pairRight"]))
	qt.Assert(t, qt.IsNil(varComments["pairRight"]))

	runtimeIdent := findDefIdent(t, info, "runtimeSecret")
	obj, ok := info.Defs[runtimeIdent].(*types.Var)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(obj.Type().String(), "string"))

	var useObj types.Object
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || ident.Name != "runtimeSecret" {
			return true
		}
		if info.Defs[ident] != nil {
			return true
		}
		useObj = info.Uses[ident]
		return false
	})
	qt.Assert(t, qt.Equals(useObj, info.Defs[runtimeIdent]))

	transform := transforms[runtimeObj]
	qt.Assert(t, qt.IsNotNil(transform))
	qt.Assert(t, qt.IsNil(transform.Uses))
	qt.Assert(t, qt.Equals(types.Object(transform.VarObj), info.Defs[runtimeIdent]))
}

func findDefIdent(t *testing.T, info *types.Info, name string) *ast.Ident {
	t.Helper()
	for ident := range info.Defs {
		if ident.Name == name {
			return ident
		}
	}
	t.Fatalf("definition for %q not found", name)
	return nil
}
