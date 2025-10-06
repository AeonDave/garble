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
// This is used in Phase 2 reversible mode for stronger encryption than XOR
func updateEntryOffsetFeistel(file *ast.File, seed [32]byte) {
	const nameOffField = "nameOff"
	entryOffUpdated := false

	keys := feistelKeysFromSeed(seed)
	addFeistelSupportDecls(file, keys)

	updateEntryOff := func(node ast.Node) bool {
		callExpr, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		textSelExpr, ok := callExpr.Fun.(*ast.SelectorExpr)
		if !ok || textSelExpr.Sel.Name != "textAddr" {
			return true
		}

		selExpr, ok := callExpr.Args[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}

		callExpr.Args[0] = ah.CallExpr(ast.NewIdent("linkFeistelDecrypt"),
			selExpr,
			ah.CallExpr(ast.NewIdent("uint32"), &ast.SelectorExpr{X: selExpr.X, Sel: ast.NewIdent(nameOffField)}),
		)

		entryOffUpdated = true
		return false
	}

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

	ast.Inspect(entryFunc, updateEntryOff)
	if !entryOffUpdated {
		panic("entryOff not found")
	}
}

func addFeistelSupportDecls(file *ast.File, keys [feistelRounds]uint32) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range valueSpec.Names {
				if name.Name == "linkFeistelKeys" {
					return
				}
			}
		}
	}

	file.Decls = append(file.Decls, makeFeistelKeysDecl(keys), makeFeistelRoundDecl(), makeFeistelDecryptDecl())
}

func makeFeistelKeysDecl(keys [feistelRounds]uint32) ast.Decl {
	elts := make([]ast.Expr, len(keys))
	for i, key := range keys {
		elts[i] = &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(uint64(key), 10)}
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

func makeFeistelRoundDecl() ast.Decl {
	return &ast.FuncDecl{
		Name: ast.NewIdent("linkFeistelRound"),
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{
				{Names: []*ast.Ident{ast.NewIdent("right")}, Type: ast.NewIdent("uint16")},
				{Names: []*ast.Ident{ast.NewIdent("tweak")}, Type: ast.NewIdent("uint32")},
				{Names: []*ast.Ident{ast.NewIdent("key")}, Type: ast.NewIdent("uint32")},
			}},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("uint16")}}},
		},
		Body: ah.BlockStmt(
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("right"))},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.XOR, Y: ast.NewIdent("tweak")}},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.XOR, Y: ast.NewIdent("key")}},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{
					X: &ast.BinaryExpr{
						X:  ast.NewIdent("x"),
						Op: token.MUL,
						Y:  &ast.BasicLit{Kind: token.INT, Value: "2654435761"},
					},
					Op: token.ADD,
					Y:  &ast.BasicLit{Kind: token.INT, Value: "2139062149"},
				}},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("shift")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{
					ah.CallExpr(
						ast.NewIdent("uint"),
						&ast.BinaryExpr{
							X:  &ast.BinaryExpr{X: ast.NewIdent("key"), Op: token.SHR, Y: ah.IntLit(27)},
							Op: token.OR,
							Y:  ah.IntLit(1),
						},
					),
				},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("shift")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{
					&ast.BinaryExpr{X: ast.NewIdent("shift"), Op: token.AND, Y: ah.IntLit(31)},
				},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{
					&ast.BinaryExpr{
						X:  &ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.SHL, Y: ast.NewIdent("shift")},
						Op: token.OR,
						Y: &ast.BinaryExpr{
							X:  ast.NewIdent("x"),
							Op: token.SHR,
							Y:  &ast.BinaryExpr{X: ah.IntLit(32), Op: token.SUB, Y: ast.NewIdent("shift")},
						},
					},
				},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("x")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.XOR, Y: &ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.SHR, Y: ah.IntLit(16)}}},
			},
			ah.ReturnStmt(ah.CallExpr(ast.NewIdent("uint16"), &ast.BinaryExpr{X: ast.NewIdent("x"), Op: token.XOR, Y: &ast.BinaryExpr{X: ast.NewIdent("key"), Op: token.SHR, Y: ah.IntLit(16)}})),
		),
	}
}

func makeFeistelDecryptDecl() ast.Decl {
	return &ast.FuncDecl{
		Name: ast.NewIdent("linkFeistelDecrypt"),
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{
				{Names: []*ast.Ident{ast.NewIdent("value")}, Type: ast.NewIdent("uint32")},
				{Names: []*ast.Ident{ast.NewIdent("tweak")}, Type: ast.NewIdent("uint32")},
			}},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("uint32")}}},
		},
		Body: ah.BlockStmt(
			&ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X:  ast.NewIdent("value"),
					Op: token.EQL,
					Y: &ast.UnaryExpr{
						Op: token.XOR,
						X:  ah.CallExpr(ast.NewIdent("uint32"), ah.IntLit(0)),
					},
				},
				Body: ah.BlockStmt(
					ah.ReturnStmt(ast.NewIdent("value")),
				),
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("left")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), &ast.BinaryExpr{X: ast.NewIdent("value"), Op: token.SHR, Y: ah.IntLit(16)})},
			},
			&ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent("right")},
				Tok: token.DEFINE,
				Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("uint16"), &ast.BinaryExpr{X: ast.NewIdent("value"), Op: token.AND, Y: &ast.BasicLit{Kind: token.INT, Value: "65535"}})},
			},
			&ast.ForStmt{
				Init: &ast.AssignStmt{
					Lhs: []ast.Expr{ast.NewIdent("round")},
					Tok: token.DEFINE,
					Rhs: []ast.Expr{&ast.BinaryExpr{X: ah.CallExpr(ast.NewIdent("len"), ast.NewIdent("linkFeistelKeys")), Op: token.SUB, Y: ah.IntLit(1)}},
				},
				Cond: &ast.BinaryExpr{X: ast.NewIdent("round"), Op: token.GEQ, Y: ah.IntLit(0)},
				Post: &ast.AssignStmt{Lhs: []ast.Expr{ast.NewIdent("round")}, Tok: token.ASSIGN, Rhs: []ast.Expr{&ast.BinaryExpr{X: ast.NewIdent("round"), Op: token.SUB, Y: ah.IntLit(1)}}},
				Body: ah.BlockStmt(
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("key")},
						Tok: token.DEFINE,
						Rhs: []ast.Expr{ah.IndexExpr("linkFeistelKeys", ast.NewIdent("round"))},
					},
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("f")},
						Tok: token.DEFINE,
						Rhs: []ast.Expr{ah.CallExpr(ast.NewIdent("linkFeistelRound"), ast.NewIdent("left"), ast.NewIdent("tweak"), ast.NewIdent("key"))},
					},
					&ast.AssignStmt{
						Lhs: []ast.Expr{ast.NewIdent("left"), ast.NewIdent("right")},
						Tok: token.ASSIGN,
						Rhs: []ast.Expr{
							&ast.BinaryExpr{X: ast.NewIdent("right"), Op: token.XOR, Y: ast.NewIdent("f")},
							ast.NewIdent("left"),
						},
					},
				),
			},
			ah.ReturnStmt(&ast.BinaryExpr{
				X:  &ast.BinaryExpr{X: ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("left")), Op: token.SHL, Y: ah.IntLit(16)},
				Op: token.OR,
				Y:  ah.CallExpr(ast.NewIdent("uint32"), ast.NewIdent("right")),
			}),
		),
	}
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
