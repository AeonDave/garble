package literals

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	mathrand "math/rand"

	ah "github.com/AeonDave/garble/internal/asthelper"
	"golang.org/x/tools/go/ast/astutil"
)

// maxSize is the upper limit of the size of string-like literals
// which we will obfuscate with any of the available obfuscators.
// Beyond that we apply only a subset of obfuscators which are guaranteed to run efficiently.
const maxSize = 2 << 10 // KiB

const (
	// minStringJunkBytes defines the minimum number of junk bytes to prepend or append during string obfuscation.
	minStringJunkBytes = 2
	// maxStringJunkBytes defines the maximum number of junk bytes to prepend or append during string obfuscation.
	maxStringJunkBytes = 8
)

// NameProviderFunc defines a function type that generates a string based on a random source and a base name.
type NameProviderFunc func(rand *mathrand.Rand, baseName string) string

type BuilderConfig struct {
	KeyProvider KeyProvider
	// DisableAsconInterleave skips extra interleaving of ASCON key/nonce/ciphertext
	// to keep literal obfuscation leaner (useful for -tiny builds).
	DisableAsconInterleave bool
}

type Builder struct {
	obfRand *obfRand
}

func NewBuilder(rand *mathrand.Rand, file *ast.File, nameFunc NameProviderFunc, cfg BuilderConfig) *Builder {
	if cfg.KeyProvider == nil {
		panic("literals: Builder requires a key provider")
	}
	return &Builder{obfRand: newObfRand(rand, file, nameFunc, cfg.KeyProvider, cfg.DisableAsconInterleave)}
}

func (b *Builder) ObfuscateFile(file *ast.File, info *types.Info, linkStrings map[*types.Var]string) *ast.File {
	pre := func(cursor *astutil.Cursor) bool {
		switch node := cursor.Node().(type) {
		case *ast.GenDecl:
			if node.Tok == token.CONST {
				return false
			}
		case *ast.ValueSpec:
			for _, name := range node.Names {
				obj := info.Defs[name].(*types.Var)
				if _, e := linkStrings[obj]; e {
					return false
				}
			}
		}
		return true
	}

	post := func(cursor *astutil.Cursor) bool {
		node, ok := cursor.Node().(ast.Expr)
		if !ok {
			return true
		}

		typeAndValue := info.Types[node]
		if !typeAndValue.IsValue() {
			return true
		}

		if typeAndValue.Type == types.Typ[types.String] && typeAndValue.Value != nil {
			value := constant.StringVal(typeAndValue.Value)
			if len(value) == 0 {
				return true
			}

			cursor.Replace(withPos(obfuscateString(b.obfRand, value), node.Pos()))

			return true
		}

		switch node := node.(type) {
		case *ast.UnaryExpr:
			if node.Op != token.AND {
				return true
			}

			if child, ok := node.X.(*ast.CompositeLit); ok {
				newnode := handleCompositeLiteral(b.obfRand, true, child, info)
				if newnode != nil {
					cursor.Replace(newnode)
				}
			}

		case *ast.CompositeLit:
			parent, ok := cursor.Parent().(*ast.UnaryExpr)
			if ok && parent.Op == token.AND {
				return true
			}

			newnode := handleCompositeLiteral(b.obfRand, false, node, info)
			if newnode != nil {
				cursor.Replace(newnode)
			}
		}

		return true
	}

	return astutil.Apply(file, pre, post).(*ast.File)
}

func (b *Builder) ObfuscateStringLiteral(value string, pos token.Pos) ast.Expr {
	return withPos(obfuscateString(b.obfRand, value), pos).(ast.Expr)
}

func (b *Builder) Finalize(file *ast.File) {
	b.obfRand.proxyDispatcher.AddToFile(file)
	if b.obfRand.asconHelper.used {
		insertAsconInlineCode(file, b.obfRand.asconHelper)
	}
	if b.obfRand.irreversibleHelper.used {
		insertIrreversibleInlineCode(file, b.obfRand.irreversibleHelper)
	}
}

// Obfuscate replaces literals with obfuscated anonymous functions.
func Obfuscate(rand *mathrand.Rand, file *ast.File, info *types.Info, linkStrings map[*types.Var]string, nameFunc NameProviderFunc, cfg BuilderConfig) *ast.File {
	b := NewBuilder(rand, file, nameFunc, cfg)
	newFile := b.ObfuscateFile(file, info, linkStrings)
	b.Finalize(newFile)
	return newFile
}

// handleCompositeLiteral checks if the input node is []byte or [...]byte and
// calls the appropriate obfuscation method, returning a new node that should
// be used to replace it.
//
// If the input node cannot be obfuscated nil is returned.
func handleCompositeLiteral(obfRand *obfRand, isPointer bool, node *ast.CompositeLit, info *types.Info) ast.Node {
	if len(node.Elts) == 0 {
		return nil
	}

	byteType := types.Universe.Lookup("byte").Type()

	var arrayLen int64
	switch y := info.TypeOf(node.Type).(type) {
	case *types.Array:
		if y.Elem() != byteType {
			return nil
		}

		arrayLen = y.Len()

	case *types.Slice:
		if y.Elem() != byteType {
			return nil
		}

	default:
		return nil
	}

	data := make([]byte, 0, len(node.Elts))

	for _, el := range node.Elts {
		elType := info.Types[el]

		if elType.Value == nil || elType.Value.Kind() != constant.Int {
			return nil
		}

		value, ok := constant.Uint64Val(elType.Value)
		if !ok {
			panic(fmt.Sprintf("cannot parse byte value: %v", elType.Value))
		}

		data = append(data, byte(value))
	}

	if arrayLen > 0 {
		return withPos(obfuscateByteArray(obfRand, isPointer, data, arrayLen), node.Pos())
	}

	return withPos(obfuscateByteSlice(obfRand, isPointer, data), node.Pos())
}

// withPos sets any token.Pos fields under node which affect printing to pos.
// Note that we can't set all token.Pos fields, since some affect the semantics.
//
// This function is useful so that go/printer doesn't try to estimate position
// offsets, which can end up in printing comment directives too early.
//
// We don't set any "end" or middle positions, because they seem irrelevant.
func withPos(node ast.Node, pos token.Pos) ast.Node {
	for node := range ast.Preorder(node) {
		switch node := node.(type) {
		case *ast.BasicLit:
			node.ValuePos = pos
		case *ast.Ident:
			node.NamePos = pos
		case *ast.CompositeLit:
			node.Lbrace = pos
			node.Rbrace = pos
		case *ast.ArrayType:
			node.Lbrack = pos
		case *ast.FuncType:
			node.Func = pos
		case *ast.BinaryExpr:
			node.OpPos = pos
		case *ast.StarExpr:
			node.Star = pos
		case *ast.CallExpr:
			node.Lparen = pos
			node.Rparen = pos

		case *ast.GenDecl:
			node.TokPos = pos
		case *ast.ReturnStmt:
			node.Return = pos
		case *ast.ForStmt:
			node.For = pos
		case *ast.RangeStmt:
			node.For = pos
		case *ast.BranchStmt:
			node.TokPos = pos
		}
	}
	return node
}

func obfuscateString(obfRand *obfRand, data string) *ast.CallExpr {
	obf := getNextObfuscator(obfRand, len(data))

	// Generate junk bytes to to prepend and append to the data.
	// This is to prevent the obfuscated string from being easily fingerprintable.
	junkBytes := make([]byte, obfRand.Intn(maxStringJunkBytes-minStringJunkBytes)+minStringJunkBytes)
	obfRand.Read(junkBytes)
	splitIdx := obfRand.Intn(len(junkBytes))

	extKeys := randExtKeys(obfRand.Rand)

	plainData := []byte(data)
	plainDataWithJunkBytes := append(append(junkBytes[:splitIdx], plainData...), junkBytes[splitIdx:]...)

	block := obf.obfuscate(obfRand, plainDataWithJunkBytes, extKeys)
	params, args := extKeysToParams(obfRand, extKeys)

	// Generate unique cast bytes to string function and hide it using proxyDispatcher:
	//
	// func(x []byte) string {
	//		return string(x[<splitIdx>:<splitIdx+len(plainData)>])
	//	}
	funcTyp := &ast.FuncType{
		Params: &ast.FieldList{List: []*ast.Field{{
			Type: ah.ByteSliceType(),
		}}},
		Results: &ast.FieldList{List: []*ast.Field{{
			Type: ast.NewIdent("string"),
		}}},
	}
	funcVal := &ast.FuncLit{
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{{
				Names: []*ast.Ident{ast.NewIdent("x")},
				Type:  ah.ByteSliceType(),
			}}},
			Results: &ast.FieldList{List: []*ast.Field{{
				Type: ast.NewIdent("string"),
			}}},
		},
		Body: ah.BlockStmt(
			ah.ReturnStmt(
				ah.CallExprByName("string",
					&ast.SliceExpr{
						X:    ast.NewIdent("x"),
						Low:  ah.IntLit(splitIdx),
						High: ah.IntLit(splitIdx + len(plainData)),
					},
				),
			),
		),
	}
	block.List = append(block.List, ah.ReturnStmt(ah.CallExpr(obfRand.proxyDispatcher.HideValue(funcVal, funcTyp), ast.NewIdent("data"))))
	return ah.LambdaCall(params, ast.NewIdent("string"), block, args)
}

func obfuscateByteSlice(obfRand *obfRand, isPointer bool, data []byte) *ast.CallExpr {
	obf := getNextObfuscator(obfRand, len(data))

	extKeys := randExtKeys(obfRand.Rand)
	block := obf.obfuscate(obfRand, data, extKeys)
	params, args := extKeysToParams(obfRand, extKeys)

	if isPointer {
		block.List = append(block.List, ah.ReturnStmt(
			ah.UnaryExpr(token.AND, ast.NewIdent("data")),
		))
		return ah.LambdaCall(params, ah.StarExpr(ah.ByteSliceType()), block, args)
	}

	block.List = append(block.List, ah.ReturnStmt(ast.NewIdent("data")))
	return ah.LambdaCall(params, ah.ByteSliceType(), block, args)
}

func obfuscateByteArray(obfRand *obfRand, isPointer bool, data []byte, length int64) *ast.CallExpr {
	obf := getNextObfuscator(obfRand, len(data))

	extKeys := randExtKeys(obfRand.Rand)
	block := obf.obfuscate(obfRand, data, extKeys)
	params, args := extKeysToParams(obfRand, extKeys)

	arrayType := ah.ByteArrayType(length)

	sliceToArray := []ast.Stmt{
		&ast.DeclStmt{
			Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{
					Names: []*ast.Ident{ast.NewIdent("newdata")},
					Type:  arrayType,
				}},
			},
		},
		&ast.RangeStmt{
			Key: ast.NewIdent("i"),
			Tok: token.DEFINE,
			X:   ast.NewIdent("data"),
			Body: ah.BlockStmt(
				ah.AssignStmt(
					ah.IndexExprByExpr(ast.NewIdent("newdata"), ast.NewIdent("i")),
					ah.IndexExprByExpr(ast.NewIdent("data"), ast.NewIdent("i")),
				),
			),
		},
	}

	var retexpr ast.Expr = ast.NewIdent("newdata")
	if isPointer {
		retexpr = ah.UnaryExpr(token.AND, retexpr)
	}

	sliceToArray = append(sliceToArray, ah.ReturnStmt(retexpr))
	block.List = append(block.List, sliceToArray...)

	if isPointer {
		return ah.LambdaCall(params, ah.StarExpr(arrayType), block, args)
	}

	return ah.LambdaCall(params, arrayType, block, args)
}

func getNextObfuscator(obfRand *obfRand, size int) obfuscator {
	if size <= maxSize {
		return obfRand.nextObfuscator()
	} else {
		return obfRand.nextLinearTimeObfuscatorForSize(size)
	}
}
