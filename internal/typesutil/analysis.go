package typesutil

import "go/types"

// FieldToStruct builds a map that links struct field objects back to their
// declaring struct type. This is used when obfuscating field names and relies on
// the provided type information.
func FieldToStruct(info *types.Info) map[*types.Var]*types.Struct {
	done := make(map[*types.Named]bool)
	fieldToStruct := make(map[*types.Var]*types.Struct)

	for _, obj := range info.Uses {
		if obj != nil {
			recordType(obj.Type(), nil, done, fieldToStruct)
		}
	}
	for _, obj := range info.Defs {
		if obj != nil {
			recordType(obj.Type(), nil, done, fieldToStruct)
		}
	}
	for _, tv := range info.Types {
		recordType(tv.Type, nil, done, fieldToStruct)
	}
	return fieldToStruct
}

// IsSafeInstanceType reports whether the provided type can be safely used as a
// variable type when rewriting consts into vars. Generic types and interface
// types without method sets are excluded.
func IsSafeInstanceType(t types.Type) bool {
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() != types.Invalid
	case *types.Named:
		if t.TypeParams().Len() > 0 {
			return false
		}
		return IsSafeInstanceType(t.Underlying())
	case *types.Signature:
		return t.TypeParams().Len() == 0
	case *types.Interface:
		return t.IsMethodSet()
	}
	return true
}

// NamedType unwraps the provided type until it finds the referenced named type
// (if any). Type aliases are resolved to their alias object.
func NamedType(t types.Type) *types.TypeName {
	switch t := t.(type) {
	case *types.Alias:
		return t.Obj()
	case *types.Named:
		return t.Obj()
	case *types.Pointer:
		return NamedType(t.Elem())
	default:
		return nil
	}
}

// IsTestSignature reports whether a function signature matches the Go test
// helper pattern "func _(*testing.T)".
func IsTestSignature(sign *types.Signature) bool {
	if sign.Recv() != nil {
		return false
	}
	params := sign.Params()
	if params.Len() != 1 {
		return false
	}
	tname := NamedType(params.At(0).Type())
	if tname == nil {
		return false
	}
	return tname.Pkg().Path() == "testing" && tname.Name() == "T"
}

func recordType(used, origin types.Type, done map[*types.Named]bool, fieldToStruct map[*types.Var]*types.Struct) {
	used = types.Unalias(used)
	if origin == nil {
		origin = used
	} else {
		origin = types.Unalias(origin)
		if _, ok := origin.(*types.TypeParam); ok {
			return
		}
	}
	type container interface{ Elem() types.Type }
	switch used := used.(type) {
	case container:
		recordType(used.Elem(), origin.(container).Elem(), done, fieldToStruct)
	case *types.Named:
		if done[used] {
			return
		}
		done[used] = true
		recordType(used.Underlying(), used.Origin().Underlying(), done, fieldToStruct)
	case *types.Struct:
		originStruct := origin.(*types.Struct)
		for i := range used.NumFields() {
			field := used.Field(i)
			fieldToStruct[field] = originStruct

			if field.Embedded() {
				recordType(field.Type(), originStruct.Field(i).Type(), done, fieldToStruct)
			}
		}
	}
}
