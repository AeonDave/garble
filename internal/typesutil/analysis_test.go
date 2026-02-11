package typesutil_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/AeonDave/garble/internal/typesutil"
)

func typecheckFixture(t *testing.T, pkgPath string, src string) (*types.Package, *types.Info) {
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

	pkg, err := (&types.Config{Importer: importer.Default()}).Check(pkgPath, fset, []*ast.File{file}, info)
	qt.Assert(t, qt.IsNil(err))
	return pkg, info
}

func TestFieldToStructTracksOrigins(t *testing.T) {
	src := `package sample

type inner struct { Value int }

type container struct {
    inner
    Alias inner
    Field string
}
`
	pkg, info := typecheckFixture(t, "example.com/sample", src)
	fieldToStruct := typesutil.FieldToStruct(info)

	containerStruct := pkg.Scope().Lookup("container").Type().Underlying().(*types.Struct)
	for i := 0; i < containerStruct.NumFields(); i++ {
		field := containerStruct.Field(i)
		qt.Assert(t, qt.Equals(fieldToStruct[field], containerStruct))
	}

	innerStruct := pkg.Scope().Lookup("inner").Type().Underlying().(*types.Struct)
	qt.Assert(t, qt.Equals(fieldToStruct[innerStruct.Field(0)], innerStruct))
}

func TestIsSafeInstanceType(t *testing.T) {
	src := `package sample

type plain string

type plainStruct struct{ Value int }

type box[T any] struct{}

type iface interface{}

type ifaceWithMethod interface { Foo() }

type constraint interface { ~int }

func generic[T any]() {}
`
	pkg, _ := typecheckFixture(t, "example.com/sample", src)

	plain := pkg.Scope().Lookup("plain").Type()
	plainStruct := pkg.Scope().Lookup("plainStruct").Type()
	box := pkg.Scope().Lookup("box").Type()
	iface := pkg.Scope().Lookup("iface").Type()
	ifaceWithMethod := pkg.Scope().Lookup("ifaceWithMethod").Type()
	constraint := pkg.Scope().Lookup("constraint").Type()
	genericSig := pkg.Scope().Lookup("generic").(*types.Func).Type().(*types.Signature)

	cases := []struct {
		name     string
		typ      types.Type
		expected bool
	}{
		{"basic", plain, true},
		{"pointer", types.NewPointer(plainStruct), true},
		{"generic struct", box, false},
		{"empty interface", iface, true},
		{"method interface", ifaceWithMethod, true},
		{"type constraint", constraint, false},
		{"generic signature", genericSig, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qt.Assert(t, qt.Equals(typesutil.IsSafeInstanceType(tc.typ), tc.expected))
		})
	}
}

func TestNamedTypeResolves(t *testing.T) {
	src := `package sample

type named struct{}

type alias = named
`
	pkg, _ := typecheckFixture(t, "example.com/sample", src)

	namedObj := pkg.Scope().Lookup("named").(*types.TypeName)
	aliasObj := pkg.Scope().Lookup("alias").(*types.TypeName)

	namedType := namedObj.Type()
	ptrType := types.NewPointer(namedType)
	aliasPtr := types.NewPointer(aliasObj.Type())

	qt.Assert(t, qt.Equals(typesutil.NamedType(namedType), namedObj))
	qt.Assert(t, qt.Equals(typesutil.NamedType(ptrType), namedObj))
	qt.Assert(t, qt.Equals(typesutil.NamedType(aliasObj.Type()), aliasObj))
	qt.Assert(t, qt.Equals(typesutil.NamedType(aliasPtr), aliasObj))
	qt.Assert(t, qt.IsNil(typesutil.NamedType(types.Typ[types.Int])))
}

func TestIsTestSignature(t *testing.T) {
	src := `package sample

import "testing"

type AliasT = testing.T

func good(t *testing.T) {}

func aliasParam(t *AliasT) {}

func wrongParam(t string) {}

func twoParams(t *testing.T, extra int) {}

type receiver struct{}

func (receiver) method(t *testing.T) {}
`
	pkg, _ := typecheckFixture(t, "example.com/sample", src)

	good := pkg.Scope().Lookup("good").(*types.Func).Type().(*types.Signature)
	aliasParam := pkg.Scope().Lookup("aliasParam").(*types.Func).Type().(*types.Signature)
	wrongParam := pkg.Scope().Lookup("wrongParam").(*types.Func).Type().(*types.Signature)
	twoParams := pkg.Scope().Lookup("twoParams").(*types.Func).Type().(*types.Signature)
	recv := pkg.Scope().Lookup("receiver").Type().(*types.Named)
	methodSig := recv.Method(0).Type().(*types.Signature)

	qt.Assert(t, qt.IsTrue(typesutil.IsTestSignature(good)))
	qt.Assert(t, qt.IsFalse(typesutil.IsTestSignature(aliasParam)))
	qt.Assert(t, qt.IsFalse(typesutil.IsTestSignature(wrongParam)))
	qt.Assert(t, qt.IsFalse(typesutil.IsTestSignature(twoParams)))
	qt.Assert(t, qt.IsFalse(typesutil.IsTestSignature(methodSig)))
}

func TestFieldToStructWithTypeParams(t *testing.T) {
	src := `package sample

type generic[T any] struct {
	Value T
	Count int
}

type wrapper struct {
	*generic[int]
	Field string
}
`
	pkg, info := typecheckFixture(t, "example.com/sample", src)
	fieldToStruct := typesutil.FieldToStruct(info)

	genericStruct := pkg.Scope().Lookup("generic").Type().(*types.Named).Underlying().(*types.Struct)
	wrapperStruct := pkg.Scope().Lookup("wrapper").Type().Underlying().(*types.Struct)

	qt.Assert(t, qt.Equals(fieldToStruct[genericStruct.Field(0)], genericStruct))
	qt.Assert(t, qt.Equals(fieldToStruct[genericStruct.Field(1)], genericStruct))
	qt.Assert(t, qt.Equals(fieldToStruct[wrapperStruct.Field(0)], wrapperStruct))
	qt.Assert(t, qt.Equals(fieldToStruct[wrapperStruct.Field(1)], wrapperStruct))
}
