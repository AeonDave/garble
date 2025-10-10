package consts

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Transform tracks const identifiers that are rewritten into vars.
type Transform struct {
	Uses   []*ast.Ident
	VarObj *types.Var
}

func ComputeTransforms(files []*ast.File, info *types.Info, pkg *types.Package) map[*types.Const]*Transform {
	parentMaps := make(map[*ast.File]map[ast.Node]ast.Node, len(files))
	constUses := make(map[*types.Const][]*ast.Ident)
	identFile := make(map[*ast.Ident]*ast.File)

	for _, file := range files {
		parentMaps[file] = buildParentMap(file)
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if info.Defs[ident] != nil {
				return true
			}
			obj, ok := info.Uses[ident].(*types.Const)
			if !ok || obj.Pkg() != pkg {
				return true
			}
			constUses[obj] = append(constUses[obj], ident)
			identFile[ident] = file
			return true
		})
	}

	requiresConst := make(map[*types.Const]bool, len(constUses))
	for obj, idents := range constUses {
		for _, ident := range idents {
			if isConstContext(ident, parentMaps[identFile[ident]]) {
				requiresConst[obj] = true
				break
			}
		}
	}

	transforms := make(map[*types.Const]*Transform)
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if len(vs.Names) == 0 || len(vs.Values) != len(vs.Names) {
					continue
				}
				for idx, name := range vs.Names {
					obj, ok := info.Defs[name].(*types.Const)
					if !ok || obj.Pkg() != pkg {
						continue
					}
					if obj.Exported() {
						continue
					}
					if requiresConst[obj] {
						continue
					}
					uses := constUses[obj]
					if len(uses) == 0 {
						continue
					}
					if !isBasicStringConst(obj) {
						continue
					}
					if lit, ok := vs.Values[idx].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
						continue
					}
					if _, seen := transforms[obj]; !seen {
						transforms[obj] = &Transform{Uses: uses}
					}
				}
			}
		}
	}

	return transforms
}

func RewriteDecls(file *ast.File, info *types.Info, transforms map[*types.Const]*Transform) {
	if len(transforms) == 0 {
		return
	}
	var newDecls []ast.Decl
	changed := false

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			newDecls = append(newDecls, decl)
			continue
		}

		var keptSpecs []ast.Spec
		var inserted []ast.Decl

		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 {
				keptSpecs = append(keptSpecs, spec)
				continue
			}
			if len(vs.Values) != len(vs.Names) {
				keptSpecs = append(keptSpecs, spec)
				continue
			}

			var keptNames []*ast.Ident
			var keptValues []ast.Expr

			for idx, name := range vs.Names {
				obj, ok := info.Defs[name].(*types.Const)
				if !ok {
					keptNames = append(keptNames, name)
					keptValues = append(keptValues, vs.Values[idx])
					continue
				}
				transform, ok := transforms[obj]
				if !ok {
					keptNames = append(keptNames, name)
					keptValues = append(keptValues, vs.Values[idx])
					continue
				}
				lit, ok := vs.Values[idx].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					keptNames = append(keptNames, name)
					keptValues = append(keptValues, vs.Values[idx])
					continue
				}

				changed = true

				varDoc := vs.Doc
				if len(keptNames) > 0 {
					varDoc = nil
				} else {
					vs.Doc = nil
				}
				varComment := vs.Comment
				if varComment != nil {
					vs.Comment = nil
				}

				varSpec := &ast.ValueSpec{
					Doc:     varDoc,
					Comment: varComment,
					Names:   []*ast.Ident{name},
					Values:  []ast.Expr{vs.Values[idx]},
				}
				varDecl := &ast.GenDecl{
					Tok:   token.VAR,
					Specs: []ast.Spec{varSpec},
				}
				if name.Pos().IsValid() {
					varDecl.TokPos = name.Pos()
				} else {
					varDecl.TokPos = gen.TokPos
				}
				inserted = append(inserted, varDecl)

				newType := obj.Type()
				if basic, ok := newType.(*types.Basic); ok && basic.Kind() == types.UntypedString {
					newType = types.Typ[types.String]
				}
				newVar := types.NewVar(obj.Pos(), obj.Pkg(), obj.Name(), newType)
				info.Defs[name] = newVar
				transform.VarObj = newVar
				for _, use := range transform.Uses {
					info.Uses[use] = newVar
				}
				transform.Uses = nil
			}

			if len(keptNames) > 0 {
				vs.Names = keptNames
				if len(keptValues) > 0 {
					vs.Values = keptValues
				} else {
					vs.Values = nil
				}
				keptSpecs = append(keptSpecs, vs)
			}
		}

		if len(keptSpecs) > 0 {
			gen.Specs = keptSpecs
			newDecls = append(newDecls, gen)
		}
		if len(inserted) > 0 {
			newDecls = append(newDecls, inserted...)
		}
	}

	if changed {
		file.Decls = newDecls
	}
}

func buildParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

func isConstContext(node ast.Node, parents map[ast.Node]ast.Node) bool {
	if parents == nil {
		return false
	}
	child := node
	for parent := parents[child]; parent != nil; child, parent = parent, parents[parent] {
		switch p := parent.(type) {
		case *ast.GenDecl:
			if p.Tok == token.CONST {
				return true
			}
		case *ast.CaseClause:
			for _, expr := range p.List {
				if expr == child {
					return true
				}
			}
		case *ast.ArrayType:
			if p.Len == child {
				return true
			}
		}
	}
	return false
}

func isBasicStringConst(obj *types.Const) bool {
	typ := obj.Type()
	if _, isNamed := typ.(*types.Named); isNamed {
		return false
	}
	if basic, ok := typ.(*types.Basic); ok {
		switch basic.Kind() {
		case types.String, types.UntypedString:
			return true
		}
	}
	return false
}
