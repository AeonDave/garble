package ssa2ast

import (
	"go/ast"
	"go/token"
	"go/types"
	"testing"
)

func TestMakeMapIteratorPolyfillDistinctTypeNodes(t *testing.T) {
	pkg := types.NewPackage("example.com/p", "p")
	keyType := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Key", nil), types.Typ[types.Uint32], nil)
	valType := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Val", nil), types.Typ[types.Int], nil)
	mapType := types.NewMap(keyType, valType)

	tc := &TypeConverter{Resolver: func(*types.Package) *ast.Ident { return nil }}
	expr, _, err := makeMapIteratorPolyfill(tc, mapType)
	if err != nil {
		t.Fatalf("makeMapIteratorPolyfill error: %v", err)
	}

	funcLit, ok := expr.(*ast.FuncLit)
	if !ok {
		t.Fatalf("expected *ast.FuncLit, got %T", expr)
	}

	paramMap, ok := funcLit.Type.Params.List[0].Type.(*ast.MapType)
	if !ok {
		t.Fatalf("expected param map type, got %T", funcLit.Type.Params.List[0].Type)
	}
	paramKey := paramMap.Key
	paramVal := paramMap.Value

	resultFunc, ok := funcLit.Type.Results.List[0].Type.(*ast.FuncType)
	if !ok {
		t.Fatalf("expected result func type, got %T", funcLit.Type.Results.List[0].Type)
	}
	if len(resultFunc.Results.List) < 3 {
		t.Fatalf("expected 3 result types, got %d", len(resultFunc.Results.List))
	}
	resultKey := resultFunc.Results.List[1].Type
	resultVal := resultFunc.Results.List[2].Type

	if paramKey == resultKey {
		t.Fatalf("expected distinct key type nodes for param and result")
	}
	if paramVal == resultVal {
		t.Fatalf("expected distinct value type nodes for param and result")
	}

	var sliceKey ast.Expr
	for _, stmt := range funcLit.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) == 0 {
			continue
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		arr, ok := call.Args[0].(*ast.ArrayType)
		if ok {
			sliceKey = arr.Elt
			break
		}
	}
	if sliceKey == nil {
		t.Fatalf("expected slice key type node in polyfill")
	}
	if sliceKey == paramKey || sliceKey == resultKey {
		t.Fatalf("expected distinct key type nodes for slice element")
	}

	var innerFunc *ast.FuncLit
	for _, stmt := range funcLit.Body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		if lit, ok := ret.Results[0].(*ast.FuncLit); ok {
			innerFunc = lit
			break
		}
	}
	if innerFunc == nil {
		t.Fatalf("expected inner func literal in polyfill")
	}
	if len(innerFunc.Type.Results.List) < 3 {
		t.Fatalf("expected 3 inner result types, got %d", len(innerFunc.Type.Results.List))
	}
	innerKey := innerFunc.Type.Results.List[1].Type
	innerVal := innerFunc.Type.Results.List[2].Type
	if innerKey == paramKey || innerKey == resultKey || innerKey == sliceKey {
		t.Fatalf("expected distinct key type nodes for inner result")
	}
	if innerVal == paramVal || innerVal == resultVal {
		t.Fatalf("expected distinct value type nodes for inner result")
	}
}
