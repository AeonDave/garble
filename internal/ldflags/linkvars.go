package ldflags

import (
	"go/types"
	"strings"
)

// ResolveInjectedStrings maps fully-qualified -ldflags=-X injections to the
// corresponding package variable objects for the provided package. Entries that
// do not belong to the package are ignored.
func ResolveInjectedStrings(pkg *types.Package, injected map[string]string) (map[*types.Var]string, error) {
	linkerVariableStrings := make(map[*types.Var]string)
	if len(injected) == 0 {
		return linkerVariableStrings, nil
	}

	for fullName, stringValue := range injected {
		idx := strings.LastIndex(fullName, ".")
		if idx <= 0 {
			continue
		}
		path, name := fullName[:idx], fullName[idx+1:]

		if path != pkg.Path() && (path != "main" || pkg.Name() != "main") {
			continue
		}

		obj, _ := pkg.Scope().Lookup(name).(*types.Var)
		if obj == nil {
			continue
		}
		linkerVariableStrings[obj] = stringValue
	}

	return linkerVariableStrings, nil
}
