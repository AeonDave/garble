package ssa2ast

import (
	"go/ast"
	"go/token"
	"go/types"
)

func makeMapIteratorPolyfill(tc *TypeConverter, mapType *types.Map) (ast.Expr, types.Type, error) {
	nextType := types.NewSignatureType(nil, nil, nil, nil, types.NewTuple(
		types.NewVar(tc.BasePos, nil, "", types.Typ[types.Bool]),
		types.NewVar(tc.BasePos, nil, "", mapType.Key()),
		types.NewVar(tc.BasePos, nil, "", mapType.Elem()),
	), false)

	keyParamExpr, err := tc.Convert(mapType.Key())
	if err != nil {
		return nil, nil, err
	}
	valueParamExpr, err := tc.Convert(mapType.Elem())
	if err != nil {
		return nil, nil, err
	}
	resultKeyExpr, err := tc.Convert(mapType.Key())
	if err != nil {
		return nil, nil, err
	}
	resultValueExpr, err := tc.Convert(mapType.Elem())
	if err != nil {
		return nil, nil, err
	}
	sliceKeyExpr, err := tc.Convert(mapType.Key())
	if err != nil {
		return nil, nil, err
	}
	innerKeyExpr, err := tc.Convert(mapType.Key())
	if err != nil {
		return nil, nil, err
	}
	innerValueExpr, err := tc.Convert(mapType.Elem())
	if err != nil {
		return nil, nil, err
	}

	// Generated using https://github.com/lu4p/astextract from snippet:
	/*
		func(m map[<key type>]<value type>) func() (bool, <key type>, <value type>) {
			keys := make([]<key type>, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			i := 0
			return func() (ok bool, k <key type>, r <value type>) {
				if i < len(keys) {
					k = keys[i]
					ok, r = true, m[k]
					i++
				}
				return
			}
		}
	*/
	return &ast.FuncLit{
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{{
				Names: []*ast.Ident{{Name: "m"}},
				Type: &ast.MapType{
					Key:   keyParamExpr,
					Value: valueParamExpr,
				},
			}}},
			Results: &ast.FieldList{List: []*ast.Field{{
				Type: &ast.FuncType{
					Params: &ast.FieldList{},
					Results: &ast.FieldList{List: []*ast.Field{
						{Type: &ast.Ident{Name: "bool"}},
						{Type: resultKeyExpr},
						{Type: resultValueExpr},
					}},
				},
			}}},
		},
		Body: &ast.BlockStmt{
			List: []ast.Stmt{
				&ast.AssignStmt{
					Lhs: []ast.Expr{&ast.Ident{Name: "keys"}},
					Tok: token.DEFINE,
					Rhs: []ast.Expr{
						&ast.CallExpr{
							Fun: &ast.Ident{Name: "make"},
							Args: []ast.Expr{
								&ast.ArrayType{Elt: sliceKeyExpr},
								&ast.BasicLit{Kind: token.INT, Value: "0"},
								&ast.CallExpr{
									Fun:  &ast.Ident{Name: "len"},
									Args: []ast.Expr{&ast.Ident{Name: "m"}},
								},
							},
						},
					},
				},
				&ast.RangeStmt{
					Key: &ast.Ident{Name: "k"},
					Tok: token.DEFINE,
					X:   &ast.Ident{Name: "m"},
					Body: &ast.BlockStmt{
						List: []ast.Stmt{
							&ast.AssignStmt{
								Lhs: []ast.Expr{&ast.Ident{Name: "keys"}},
								Tok: token.ASSIGN,
								Rhs: []ast.Expr{
									&ast.CallExpr{
										Fun: &ast.Ident{Name: "append"},
										Args: []ast.Expr{
											&ast.Ident{Name: "keys"},
											&ast.Ident{Name: "k"},
										},
									},
								},
							},
						},
					},
				},
				&ast.AssignStmt{
					Lhs: []ast.Expr{&ast.Ident{Name: "i"}},
					Tok: token.DEFINE,
					Rhs: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "0"}},
				},
				&ast.ReturnStmt{Results: []ast.Expr{
					&ast.FuncLit{
						Type: &ast.FuncType{
							Params: &ast.FieldList{},
							Results: &ast.FieldList{List: []*ast.Field{
								{
									Names: []*ast.Ident{{Name: "ok"}},
									Type:  &ast.Ident{Name: "bool"},
								},
								{
									Names: []*ast.Ident{{Name: "k"}},
									Type:  innerKeyExpr,
								},
								{
									Names: []*ast.Ident{{Name: "r"}},
									Type:  innerValueExpr,
								},
							}},
						},
						Body: &ast.BlockStmt{
							List: []ast.Stmt{
								&ast.IfStmt{
									Cond: &ast.BinaryExpr{
										X:  &ast.Ident{Name: "i"},
										Op: token.LSS,
										Y: &ast.CallExpr{
											Fun:  &ast.Ident{Name: "len"},
											Args: []ast.Expr{&ast.Ident{Name: "keys"}},
										},
									},
									Body: &ast.BlockStmt{List: []ast.Stmt{
										&ast.AssignStmt{
											Lhs: []ast.Expr{&ast.Ident{Name: "k"}},
											Tok: token.ASSIGN,
											Rhs: []ast.Expr{&ast.IndexExpr{
												X:     &ast.Ident{Name: "keys"},
												Index: &ast.Ident{Name: "i"},
											}},
										},
										&ast.AssignStmt{
											Lhs: []ast.Expr{
												&ast.Ident{Name: "ok"},
												&ast.Ident{Name: "r"},
											},
											Tok: token.ASSIGN,
											Rhs: []ast.Expr{
												&ast.Ident{Name: "true"},
												&ast.IndexExpr{
													X:     &ast.Ident{Name: "m"},
													Index: &ast.Ident{Name: "k"},
												},
											},
										},
										&ast.IncDecStmt{
											X:   &ast.Ident{Name: "i"},
											Tok: token.INC,
										},
									}},
								},
								&ast.ReturnStmt{},
							},
						},
					},
				}},
			},
		},
	}, nextType, nil
}
