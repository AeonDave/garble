// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	ah "mvdan.cc/garble/internal/asthelper"
)

// updateMagicValue updates hardcoded value of hdr.magic
// when verifying header in symtab.go
func updateMagicValue(file *ast.File, magicValue uint32) {
	magicUpdated := false

	// Find `hdr.magic != 0xfffffff?` in symtab.go and update to random magicValue
	updateMagic := func(node ast.Node) bool {
		binExpr, ok := node.(*ast.BinaryExpr)
		if !ok || binExpr.Op != token.NEQ {
			return true
		}

		selectorExpr, ok := binExpr.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if ident, ok := selectorExpr.X.(*ast.Ident); !ok || ident.Name != "hdr" {
			return true
		}
		if selectorExpr.Sel.Name != "magic" {
			return true
		}

		if _, ok := binExpr.Y.(*ast.BasicLit); !ok {
			return true
		}
		binExpr.Y = &ast.BasicLit{
			Kind:  token.INT,
			Value: strconv.FormatUint(uint64(magicValue), 10),
		}
		magicUpdated = true
		return false
	}

	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if ok && funcDecl.Name.Name == "moduledataverify1" {
			ast.Inspect(funcDecl, updateMagic)
			break
		}
	}

	if !magicUpdated {
		panic("magic value not updated")
	}
}

// updateEntryOffsetFeistel injects Feistel decryption into runtime.funcInfo.entry()
// Uses 4-round Feistel network with helper functions marked //go:nosplit to avoid
// adding stack frames that would break runtime.Caller() depth tracking.
// The encryption provides stronger cryptographic properties than simple XOR while
// maintaining compatibility with runtime introspection.
func updateEntryOffsetFeistel(file *ast.File, seed [32]byte) {
	const nameOffField = "nameOff"
	entryOffUpdated := false

	keys := feistelKeysFromSeed(seed)

	// Add helper functions with special compiler directives
	addFeistelHelperFunctions(file, keys)

	var entryFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		decl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if decl.Name.Name == "entry" {
			entryFunc = decl
			break
		}
	}
	if entryFunc == nil {
		panic("entry function not found")
	}

	// Find and replace the return statement containing f.entryOff
	// The original code is: return f.datap.textAddr(f.entryOff)
	// We want: return f.datap.textAddr(linkFeistelDecrypt(f.entryOff, uint32(f.nameOff)))

	for _, stmt := range entryFunc.Body.List {
		retStmt, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(retStmt.Results) != 1 {
			continue
		}

		// Check if this is a call expression (textAddr call)
		callExpr, ok := retStmt.Results[0].(*ast.CallExpr)
		if !ok {
			continue
		}

		// Verify it's textAddr method
		selExpr, ok := callExpr.Fun.(*ast.SelectorExpr)
		if !ok || selExpr.Sel.Name != "textAddr" {
			continue
		}

		// Check if the argument contains entryOff
		if len(callExpr.Args) != 1 {
			continue
		}

		entryOffSel, ok := callExpr.Args[0].(*ast.SelectorExpr)
		if !ok || entryOffSel.Sel.Name != "entryOff" {
			continue
		}

		// Replace f.entryOff with linkFeistelDecrypt(f.entryOff, uint32(f.nameOff))
		callExpr.Args[0] = ah.CallExpr(
			ast.NewIdent("linkFeistelDecrypt"),
			entryOffSel,
			ah.CallExpr(ast.NewIdent("uint32"), &ast.SelectorExpr{
				X:   entryOffSel.X,
				Sel: ast.NewIdent(nameOffField),
			}),
		)

		entryOffUpdated = true
		break
	}

	if !entryOffUpdated {
		panic("failed to replace entryOff with Feistel decryption in entry() function")
	}
}

// addFeistelHelperFunctions adds Feistel cipher helper functions with special directives
// These are marked with //go:nosplit to minimize impact on runtime.Caller stack unwinding
func addFeistelHelperFunctions(file *ast.File, keys [feistelRounds]uint32) {
	// Check if already added
	for _, decl := range file.Decls {
		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			if funcDecl.Name.Name == "linkFeistelDecrypt" {
				return // Already added
			}
		}
	}

	// Add keys as var declaration
	file.Decls = append(file.Decls, makeFeistelKeysDecl(keys))

	// Add round function with //go:nosplit
	file.Decls = append(file.Decls, makeFeistelRoundFuncWithDirectives())

	// Add decrypt function with //go:nosplit
	file.Decls = append(file.Decls, makeFeistelDecryptFuncWithDirectives())
}

func makeFeistelKeysDecl(keys [feistelRounds]uint32) ast.Decl {
	elts := make([]ast.Expr, len(keys))
	for i, key := range keys {
		elts[i] = &ast.BasicLit{
			Kind:  token.INT,
			Value: strconv.FormatUint(uint64(key), 10),
		}
	}

	return &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names: []*ast.Ident{ast.NewIdent("linkFeistelKeys")},
				Values: []ast.Expr{
					&ast.CompositeLit{
						Type: &ast.ArrayType{
							Len: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(len(keys))},
							Elt: ast.NewIdent("uint32"),
						},
						Elts: elts,
					},
				},
			},
		},
	}
}

func makeFeistelRoundFuncWithDirectives() ast.Decl {
	// Create the function with //go:nosplit directive
	funcDecl := &ast.FuncDecl{
		Name: ast.NewIdent("linkFeistelRound"),
		Type: &ast.FuncType{
			Params: &ast.FieldList{
				List: []*ast.Field{
					{Names: []*ast.Ident{ast.NewIdent("right")}, Type: ast.NewIdent("uint16")},
					{Names: []*ast.Ident{ast.NewIdent("tweak")}, Type: ast.NewIdent("uint32")},
					{Names: []*ast.Ident{ast.NewIdent("key")}, Type: ast.NewIdent("uint32")},
				},
			},
			Results: &ast.FieldList{
				List: []*ast.Field{{Type: ast.NewIdent("uint16")}},
			},
		},
		Body: ah.BlockStmt(
			// x := uint32(right)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("right"))},
			},
			// x ^= tweak
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X:  ast.NewIdent("x"),
					Op: token.XOR,
					Y:  ast.NewIdent("tweak"),
				}},
			},
			// x += key*0x9e3779b1 + 0x7f4a7c15 (pre-computed per key to avoid overflow)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X:  ast.NewIdent("x"),
					Op: token.ADD,
					Y: &ast.BinaryExpr{
						X: &ast.BinaryExpr{
							X:  ast.NewIdent("key"),
							Op: token.MUL,
							Y:  ah.IntLit(0x9e3779b1),
						},
						Op: token.ADD,
						Y:  ah.IntLit(0x7f4a7c15),
					},
				}},
			},
			// n := key & 31 (rotation amount)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("n")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X:  ast.NewIdent("key"),
					Op: token.AND,
					Y:  ah.IntLit(31),
				}},
			},
			// tmp := x ^ key
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("tmp")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X:  ast.NewIdent("x"),
					Op: token.XOR,
					Y:  ast.NewIdent("key"),
				}},
			},
			// if n != 0 { x = (tmp << n) | (tmp >> (32-n)) } else { x = tmp }
			&ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X:  ast.NewIdent("n"),
					Op: token.NEQ,
					Y:  ah.IntLit(0),
				},
				Body: ah.BlockStmt(
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("x")},
						Tok: token.ASSIGN,
						Rhs: []ast.Expr{&ast.BinaryExpr{
							X: &ast.BinaryExpr{
								X:  ast.NewIdent("tmp"),
								Op: token.SHL,
								Y:  ast.NewIdent("n"),
							},
							Op: token.OR,
							Y: &ast.BinaryExpr{
								X:  ast.NewIdent("tmp"),
								Op: token.SHR,
								Y: &ast.BinaryExpr{
									X:  ah.IntLit(32),
									Op: token.SUB,
									Y:  ast.NewIdent("n"),
								},
							},
						}},
					},
				),
				Else: ah.BlockStmt(
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("x")},
						Tok: token.ASSIGN,
						Rhs: []ast.Expr{ast.NewIdent("tmp")},
					},
				),
			},
			// x ^= x >> 16 (mixing step)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X:  ast.NewIdent("x"),
					Op: token.XOR,
					Y: &ast.BinaryExpr{
						X:  ast.NewIdent("x"),
						Op: token.SHR,
						Y:  ah.IntLit(16),
					},
				}},
			},
			// return uint16(x)
			ah.ReturnStmt(ah.CallExpr(ast.NewIdent("uint16"), ast.NewIdent("x"))),
		),
	}

	// Add //go:nosplit directive
	if funcDecl.Doc == nil {
		funcDecl.Doc = &ast.CommentGroup{}
	}
	funcDecl.Doc.List = append(funcDecl.Doc.List, &ast.Comment{
		Text: "//go:nosplit",
	})

	return funcDecl
}

func makeFeistelDecryptFuncWithDirectives() ast.Decl {
	funcDecl := &ast.FuncDecl{
		Name: ast.NewIdent("linkFeistelDecrypt"),
		Type: &ast.FuncType{
			Params: &ast.FieldList{
				List: []*ast.Field{
					{Names: []*ast.Ident{ast.NewIdent("value")}, Type: ast.NewIdent("uint32")},
					{Names: []*ast.Ident{ast.NewIdent("tweak")}, Type: ast.NewIdent("uint32")},
				},
			},
			Results: &ast.FieldList{
				List: []*ast.Field{{Type: ast.NewIdent("uint32")}},
			},
		},
		Body: ah.BlockStmt(
			// left := uint16(value >> 16)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("left")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), &ast.BinaryExpr{
					X:  ast.NewIdent("value"),
					Op: token.SHR,
					Y:  ah.IntLit(16),
				})},
			},
			// right := uint16(value)
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("right")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), ast.NewIdent("value"))},
			},
			// for round := 3; round >= 0; round-- { ... }
			&ast.ForStmt{
				Init: &ast.AssignStmt{
					Lhs: []ast.Expr{ast.NewIdent("round")},
					Tok: token.DEFINE,
					Rhs: []ast.Expr{&ast.BinaryExpr{
						X:  ah.CallExpr(ast.NewIdent("len"), ast.NewIdent("linkFeistelKeys")),
						Op: token.SUB,
						Y:  ah.IntLit(1),
					}},
				},
				Cond: &ast.BinaryExpr{
					X:  ast.NewIdent("round"),
					Op: token.GEQ,
					Y:  ah.IntLit(0),
				},
				Post: &ast.AssignStmt{
					Lhs: []ast.Expr{ast.NewIdent("round")},
					Tok: token.ASSIGN,
					Rhs: []ast.Expr{&ast.BinaryExpr{
						X:  ast.NewIdent("round"),
						Op: token.SUB,
						Y:  ah.IntLit(1),
					}},
				},
				Body: ah.BlockStmt(
					// key := linkFeistelKeys[round]
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("key")},
						Tok: token.DEFINE,
						Rhs: []ast.Expr{ah.IndexExpr("linkFeistelKeys", ast.NewIdent("round"))},
					},
					// f := linkFeistelRound(left, tweak, key)
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("f")},
						Tok: token.DEFINE,
						Rhs: []ast.Expr{ah.CallExpr(
							ast.NewIdent("linkFeistelRound"),
							ast.NewIdent("left"),
							ast.NewIdent("tweak"),
							ast.NewIdent("key"),
						)},
					},
					// left, right = right^f, left
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("left"), ast.NewIdent("right")},
						Tok: token.ASSIGN,
						Rhs: []ast.Expr{
							&ast.BinaryExpr{
								X:  ast.NewIdent("right"),
								Op: token.XOR,
								Y:  ast.NewIdent("f"),
							},
							ast.NewIdent("left"),
						},
					},
				),
			},
			// return (uint32(left) << 16) | uint32(right)
			ah.ReturnStmt(&ast.BinaryExpr{
				X: &ast.BinaryExpr{
					X:  ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("left")),
					Op: token.SHL,
					Y:  ah.IntLit(16),
				},
				Op: token.OR,
				Y:  ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("right")),
			}),
		),
	}

	// Add //go:nosplit directive
	if funcDecl.Doc == nil {
		funcDecl.Doc = &ast.CommentGroup{}
	}
	funcDecl.Doc.List = append(funcDecl.Doc.List, &ast.Comment{
		Text: "//go:nosplit",
	})

	return funcDecl
}

// stripRuntime removes unnecessary code from the runtime,

// makeUnrolledFeistelDecrypt creates an expression with all 4 Feistel rounds unrolled
func makeUnrolledFeistelDecrypt(valueExpr ast.Expr, tweakExpr ast.Expr, keys [feistelRounds]uint32) ast.Expr {
	// This is complex, so we'll use a CallExpr wrapper that calls an immediately invoked function expression
	// Actually, Go AST doesn't support IIFEs easily, so we'll create the full inline computation

	// Strategy: Build the expression as a function literal that gets immediately called
	// func() uint32 { ...full feistel logic... }()

	// Create the function body with all rounds unrolled
	var stmts []ast.Stmt

	// value := f.entryOff
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_value")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{valueExpr},
	})

	// tweak := uint32(f.nameOff)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_tweak")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{tweakExpr},
	})

	// left := uint16(_value >> 16)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_left")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), &ast.BinaryExpr{
			X:  ast.NewIdent("_value"),
			Op: token.SHR,
			Y:  ah.IntLit(16),
		})},
	})

	// right := uint16(_value)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_right")},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), ast.NewIdent("_value"))},
	})

	// Unroll all 4 rounds (decrypt goes backwards: round 3, 2, 1, 0)
	for roundIdx, round := 0, feistelRounds-1; round >= 0; roundIdx, round = roundIdx+1, round-1 {
		stmts = append(stmts, makeInlinedFeistelRound("_left", "_right", "_tweak", keys[round], false, roundIdx)...)
	}

	// return (uint32(_left) << 16) | uint32(_right)
	stmts = append(stmts, ah.ReturnStmt(&ast.BinaryExpr{
		X: &ast.BinaryExpr{
			X:  ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("_left")),
			Op: token.SHL,
			Y:  ah.IntLit(16),
		},
		Op: token.OR,
		Y:  ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("_right")),
	}))

	// Create function literal: func() uint32 { ...stmts... }
	funcLit := &ast.FuncLit{
		Type: &ast.FuncType{
			Results: &ast.FieldList{
				List: []*ast.Field{{Type: ast.NewIdent("uint32")}},
			},
		},
		Body: &ast.BlockStmt{List: stmts},
	}

	// Return immediately invoked: (func() uint32 { ... })()
	return &ast.CallExpr{
		Fun:  &ast.ParenExpr{X: funcLit},
		Args: []ast.Expr{},
	}
}

// makeInlinedFeistelRound creates statements for one Feistel round
// It computes: f := feistelRound(inputVar, tweak, key); left, right = right, left^f
// roundIdx indicates which round this is (0-3) - used to determine if we need to DEFINE or ASSIGN variables
func makeInlinedFeistelRound(leftVar, rightVar, tweakVar string, key uint32, isEncrypt bool, roundIdx int) []ast.Stmt {
	var stmts []ast.Stmt

	// Determine which variable to use for the round function (decrypt uses left, encrypt uses right)
	inputVar := leftVar
	if isEncrypt {
		inputVar = rightVar
	}

	// x := uint32(inputVar) for first round, x = uint32(inputVar) for subsequent rounds
	xTok := token.ASSIGN
	nTok := token.ASSIGN
	tmpTok := token.ASSIGN
	fTok := token.ASSIGN
	if roundIdx == 0 {
		xTok = token.DEFINE
		nTok = token.DEFINE
		tmpTok = token.DEFINE
		fTok = token.DEFINE
	}

	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_x")},
		Tok: xTok,
		Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent(inputVar))},
	})

	// x ^= tweak
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_x")},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.BinaryExpr{
			X:  ast.NewIdent("_x"),
			Op: token.XOR,
			Y:  ast.NewIdent(tweakVar),
		}},
	})

	// x += key*0x9e3779b1 + 0x7f4a7c15
	// Pre-compute to avoid overflow: (key * 0x9e3779b1 + 0x7f4a7c15) wraps in uint32
	addValue := uint32(key)*0x9e3779b1 + 0x7f4a7c15
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_x")},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.BinaryExpr{
			X:  ast.NewIdent("_x"),
			Op: token.ADD,
			Y:  &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(uint64(addValue), 10)},
		}},
	})

	// Manual rotate left: rotateLeft32(x^key, key&31)
	// n := key & 31 (first round) or n = key & 31 (subsequent rounds)
	nValue := key & 31
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_n")},
		Tok: nTok,
		Rhs: []ast.Expr{ah.IntLit(int(nValue))},
	})

	// tmp := x ^ key (first round) or tmp = x ^ key (subsequent rounds)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_tmp")},
		Tok: tmpTok,
		Rhs: []ast.Expr{&ast.BinaryExpr{
			X:  ast.NewIdent("_x"),
			Op: token.XOR,
			Y:  ah.IntLit(int(key)),
		}},
	})

	// Conditional rotate: if n != 0 { x = (tmp << n) | (tmp >> (32 - n)) } else { x = tmp }
	stmts = append(stmts, &ast.IfStmt{
		Cond: &ast.BinaryExpr{X: ast.NewIdent("_n"), Op: token.NEQ, Y: ah.IntLit(0)},
		Body: ah.BlockStmt(
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("_x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X: &ast.BinaryExpr{
						X:  ast.NewIdent("_tmp"),
						Op: token.SHL,
						Y:  ast.NewIdent("_n"),
					},
					Op: token.OR,
					Y: &ast.BinaryExpr{
						X:  ast.NewIdent("_tmp"),
						Op: token.SHR,
						Y:  &ast.BinaryExpr{X: ah.IntLit(32), Op: token.SUB, Y: ast.NewIdent("_n")},
					},
				}},
			},
		),
		Else: ah.BlockStmt(
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("_x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{ast.NewIdent("_tmp")},
			},
		),
	})

	// x ^= x >> 16 (mixing step)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_x")},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.BinaryExpr{
			X:  ast.NewIdent("_x"),
			Op: token.XOR,
			Y: &ast.BinaryExpr{
				X:  ast.NewIdent("_x"),
				Op: token.SHR,
				Y:  ah.IntLit(16),
			},
		}},
	})

	// f := uint16(_x) (first round) or f = uint16(_x) (subsequent rounds)
	stmts = append(stmts, &ast.AssignStmt{
		Lhs: []ast.Expr{ast.NewIdent("_f")},
		Tok: fTok,
		Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), ast.NewIdent("_x"))},
	})

	// Swap: left, right = right^f, left (for decrypt)
	// or: left, right = right, left^f (for encrypt)
	if isEncrypt {
		stmts = append(stmts, &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(leftVar), ast.NewIdent(rightVar)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{
				ast.NewIdent(rightVar),
				&ast.BinaryExpr{X: ast.NewIdent(leftVar), Op: token.XOR, Y: ast.NewIdent("_f")},
			},
		})
	} else {
		stmts = append(stmts, &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(leftVar), ast.NewIdent(rightVar)},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{
				&ast.BinaryExpr{X: ast.NewIdent(rightVar), Op: token.XOR, Y: ast.NewIdent("_f")},
				ast.NewIdent(leftVar),
			},
		})
	}

	return stmts
}

// stripRuntime removes unnecessary code from the runtime,
// such as panic and fatal error printing, and code that
// prints trace/debug info of the runtime.
func stripRuntime(basename string, file *ast.File) {
	stripPrints := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}

		switch id.Name {
		case "print", "println":
			id.Name = "hidePrint"
			return false
		default:
			return true
		}
	}

	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		switch basename {
		case "error.go":
			// only used in panics
			switch funcDecl.Name.Name {
			case "printany", "printanycustomtype":
				funcDecl.Body.List = nil
			}
		case "mgcscavenge.go":
			// used in tracing the scavenger
			if funcDecl.Name.Name == "printScavTrace" {
				funcDecl.Body.List = nil
			}
		case "mprof.go":
			// remove all functions that print debug/tracing info
			// of the runtime
			if strings.HasPrefix(funcDecl.Name.Name, "trace") {
				funcDecl.Body.List = nil
			}
		case "panic.go":
			// used for printing panics
			switch funcDecl.Name.Name {
			case "preprintpanics", "printpanics":
				funcDecl.Body.List = nil
			}
		case "print.go":
			// only used in tracebacks
			if funcDecl.Name.Name == "hexdumpWords" {
				funcDecl.Body.List = nil
			}
		case "proc.go":
			// used in tracing the scheduler
			if funcDecl.Name.Name == "schedtrace" {
				funcDecl.Body.List = nil
			}
		case "runtime1.go":
			usesEnv := func(node ast.Node) bool {
				for node := range ast.Preorder(node) {
					ident, ok := node.(*ast.Ident)
					if ok && ident.Name == "gogetenv" {
						return true
					}
				}
				return false
			}
		filenames:
			switch funcDecl.Name.Name {
			case "parsedebugvars":
				// keep defaults for GODEBUG cgocheck and invalidptr,
				// remove code that reads GODEBUG via gogetenv
				for i, stmt := range funcDecl.Body.List {
					if usesEnv(stmt) {
						funcDecl.Body.List = funcDecl.Body.List[:i]
						break filenames
					}
				}
				panic("did not see any gogetenv call in parsedebugvars")
			case "setTraceback":
				// tracebacks are completely hidden, no
				// sense keeping this function
				funcDecl.Body.List = nil
			}
		case "traceback.go":
			// only used for printing tracebacks
			switch funcDecl.Name.Name {
			case "tracebackdefers", "printcreatedby", "printcreatedby1", "traceback", "tracebacktrap", "traceback1", "printAncestorTraceback",
				"printAncestorTracebackFuncInfo", "goroutineheader", "tracebackothers", "tracebackHexdump", "printCgoTraceback":
				funcDecl.Body.List = nil
			case "printOneCgoTraceback":
				funcDecl.Body = ah.BlockStmt(ah.ReturnStmt(ast.NewIdent("false")))
			default:
				if strings.HasPrefix(funcDecl.Name.Name, "print") {
					funcDecl.Body.List = nil
				}
			}
		}

	}

	if basename == "print.go" {
		file.Decls = append(file.Decls, hidePrintDecl)
		return
	}

	// replace all 'print' and 'println' statements in
	// the runtime with an empty func, which will be
	// optimized out by the compiler
	ast.Inspect(file, stripPrints)
}

var hidePrintDecl = &ast.FuncDecl{
	Name: ast.NewIdent("hidePrint"),
	Type: &ast.FuncType{Params: &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{Name: "args"}},
			Type: &ast.Ellipsis{Elt: &ast.InterfaceType{
				Methods: &ast.FieldList{},
			}},
		}},
	}},
	Body: &ast.BlockStmt{},
}
