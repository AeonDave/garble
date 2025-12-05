package ctrlflow

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"math"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	ah "github.com/AeonDave/garble/internal/asthelper"
	"github.com/AeonDave/garble/internal/ssa2ast"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/ssa"
)

const (
	mergedFileName    = "GARBLE_controlflow.go"
	directiveName     = "//garble:controlflow"
	skipDirectiveName = "//garble:nocontrolflow"
	importPrefix      = "___garble_import"

	defaultBlockSplits   = 0
	defaultJunkJumps     = 0
	defaultFlattenPasses = 1
	defaultTrashBlocks   = 0

	maxBlockSplits   = math.MaxInt32
	maxJunkJumps     = 256
	maxFlattenPasses = 4
	maxTrashBlocks   = 1024

	minTrashBlockStmts = 1
	maxTrashBlockStmts = 32

	skippedPackagesFile = "ctrlflow-skipped-packages.txt"
)

var (
	skippedPackagesMu sync.Mutex
	ctrlflowDebug     = os.Getenv("GARBLE_CONTROLFLOW_DEBUG") == "1"
)

func debugf(format string, args ...any) {
	if !ctrlflowDebug {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "[ctrlflow] "+format+"\n", args...)
}

// loadSkippedPackages loads the list of packages that were skipped during control-flow obfuscation
func loadSkippedPackages(sharedTempDir string) (map[string]bool, error) {
	if sharedTempDir == "" {
		return make(map[string]bool), nil
	}
	skippedPackagesMu.Lock()
	defer skippedPackagesMu.Unlock()

	path := filepath.Join(sharedTempDir, skippedPackagesFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	skipped := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			skipped[line] = true
		}
	}
	return skipped, scanner.Err()
}

// saveSkippedPackage appends a package to the list of skipped packages
func saveSkippedPackage(sharedTempDir, pkgPath string) error {
	if sharedTempDir == "" {
		return nil
	}
	skippedPackagesMu.Lock()
	defer skippedPackagesMu.Unlock()

	path := filepath.Join(sharedTempDir, skippedPackagesFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	_, err = fmt.Fprintln(f, pkgPath)
	return err
}

type directiveParamMap map[string]string

func (m directiveParamMap) GetInt(name string, def, max int) int {
	rawVal, ok := m[name]
	if !ok {
		return def
	}

	if rawVal == "max" {
		return max
	}

	val, err := strconv.Atoi(rawVal)
	if err != nil {
		panic(fmt.Errorf("invalid flag %q format: %v", name, err))
	}
	if val > max {
		panic(fmt.Errorf("too big flag %q value: %d (max: %d)", name, val, max))
	}
	return val
}

func (m directiveParamMap) StringSlice(name string) []string {
	rawVal, ok := m[name]
	if !ok {
		return nil
	}

	slice := strings.Split(rawVal, ",")
	if len(slice) == 0 {
		return nil
	}
	return slice
}

// parseDirective parses a directive string and returns a map of directive parameters.
// Each parameter should be in the form "key=value" or "key"
func parseDirective(directive string) (directiveParamMap, bool) {
	fieldsStr, ok := strings.CutPrefix(directive, directiveName)
	if !ok {
		return nil, false
	}

	fields := strings.Fields(fieldsStr)
	if len(fields) == 0 {
		return nil, true
	}
	m := make(map[string]string)
	for _, v := range fields {
		key, value, ok := strings.Cut(v, "=")
		if ok {
			m[key] = value
		} else {
			m[key] = ""
		}
	}
	return m, true
}

func extractControlFlowIntent(doc *ast.CommentGroup) (directiveParamMap, bool, bool) {
	if doc == nil {
		return nil, false, false
	}

	var (
		params       directiveParamMap
		hasDirective bool
	)

	for _, comment := range doc.List {
		if strings.HasPrefix(comment.Text, skipDirectiveName) {
			return nil, false, true
		}
		if !hasDirective {
			if parsed, ok := parseDirective(comment.Text); ok {
				params = parsed
				hasDirective = true
			}
		}
	}

	return params, hasDirective, false
}

func eligibleForAuto(funcDecl *ast.FuncDecl) bool {
	if funcDecl.Body == nil {
		return false
	}
	if len(funcDecl.Body.List) == 0 {
		return false
	}
	return true
}

func shouldObfuscate(mode Mode, funcDecl *ast.FuncDecl, hasDirective bool) bool {
	switch mode {
	case ModeOff:
		return false
	case ModeAnnotated:
		return hasDirective
	case ModeAuto:
		return hasDirective || eligibleForAuto(funcDecl)
	case ModeAll:
		return true
	default:
		return false
	}
}

// isFragilePackage determines if a package should be skipped for control-flow obfuscation.
// Conservative strategy: obfuscate ONLY user code (project packages), exclude ALL external libraries.
// This avoids maintaining an infinite blacklist of problematic third-party packages.
// Returns true if the package should be skipped.
func isFragilePackage(ssaPkg *ssa.Package, files []*ast.File) bool {
	pkgPath := ssaPkg.Pkg.Path()

	// 1. Always skip critical stdlib packages (runtime, syscall, unsafe-heavy).
	if strings.HasPrefix(pkgPath, "golang.org") ||
		strings.HasPrefix(pkgPath, "runtime") ||
		pkgPath == "syscall" ||
		pkgPath == "unsafe" {
		debugf("%s: fragile skip due to stdlib prefix", pkgPath)
		return true
	}

	// 2. Skip packages that import "C" (cgo) - fragile type interactions.
	for _, f := range files {
		for _, imp := range f.Imports {
			if imp.Path != nil && strings.Trim(imp.Path.Value, `"`) == "C" {
				debugf("%s: fragile skip due to cgo import", pkgPath)
				return true
			}
		}
	}

	// 4. Skip packages with dangerous compiler directives that indicate low-level code.
	//    These may not tolerate control-flow transformations.
	//    Safe directives like //go:build are allowed.
	dangerousDirectives := []string{
		"//go:noinline",
		"//go:noescape",
		"//go:uintptrescapes",
		"//go:nosplit",
		"//go:norace",
		"//go:cgo_",
	}
	for _, f := range files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				for _, dangerous := range dangerousDirectives {
					if strings.HasPrefix(c.Text, dangerous) {
						debugf("%s: fragile skip due to directive %s", pkgPath, dangerous)
						return true
					}
				}
			}
		}
	}

	// If we reach here, it's user code (project package) - safe to obfuscate.
	return false
}

// hasBoundMethodClosure checks if a function (or any of its anonymous functions recursively)
// contains a MakeClosure instruction referencing a non-anonymous function (e.g., bound method).
// Bound methods like "Method$bound" are not safely lowered by the SSA→AST converter.
func hasBoundMethodClosure(fn *ssa.Function) bool {
	// Check the function itself
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if mc, ok := instr.(*ssa.MakeClosure); ok {
				if closureFn, ok := mc.Fn.(*ssa.Function); ok {
					// Check if it's a bound method (contains "$bound" suffix)
					if strings.Contains(closureFn.Name(), "$bound") {
						return true
					}
					// Check if it's a non-anonymous function
					isAnon := false
					if parent := closureFn.Parent(); parent != nil {
						for _, af := range parent.AnonFuncs {
							if af == closureFn {
								isAnon = true
								break
							}
						}
					}
					if !isAnon {
						return true
					}
				}
			}
		}
	}

	// Check all anonymous functions recursively
	for _, anonFn := range fn.AnonFuncs {
		if hasBoundMethodClosure(anonFn) {
			return true
		}
	}

	return false
}

// hasPredeclaredNames checks if a function has parameters or results that shadow
// predeclared identifiers like "error", "string", "int", etc.
func hasPredeclaredNames(fn *ssa.Function) bool {
	sig := fn.Signature

	if params := sig.Params(); params != nil {
		for i := 0; i < params.Len(); i++ {
			param := params.At(i)
			if param.Name() != "" && param.Name() != "_" && types.Universe.Lookup(param.Name()) != nil {
				return true
			}
		}
	}

	if results := sig.Results(); results != nil {
		for i := 0; i < results.Len(); i++ {
			result := results.At(i)
			if result.Name() != "" && result.Name() != "_" && types.Universe.Lookup(result.Name()) != nil {
				return true
			}
		}
	}

	// Check receiver (for methods)
	if recv := sig.Recv(); recv != nil {
		if recv.Name() != "" && recv.Name() != "_" && types.Universe.Lookup(recv.Name()) != nil {
			return true
		}
	}

	return false
}

// Obfuscate obfuscates control flow of all functions with directive using control flattening.
// All obfuscated functions are removed from the original file and moved to the new one.
// Obfuscation can be customized by passing parameters from the directive, example:
//
// //garble:controlflow flatten_passes=1 junk_jumps=0 block_splits=0
// func someMethod() {}
//
// flatten_passes - controls number of passes of control flow flattening. Have exponential complexity and more than 3 passes are not recommended in most cases.
// junk_jumps - controls how many junk jumps are added. It does not affect final binary by itself, but together with flattening linearly increases complexity.
// block_splits - controls number of times largest block must be splitted. Together with flattening improves obfuscation of long blocks without branches.
//
//goland:noinspection GoUnhandledErrorResult
func Obfuscate(fset *token.FileSet, ssaPkg *ssa.Package, files []*ast.File, obfRand *mathrand.Rand, mode Mode, sharedTempDir string) (newFileName string, newFile *ast.File, affectedFiles []*ast.File, err error) {
	if !mode.Enabled() {
		debugf("%s: control-flow disabled (mode=%v)", ssaPkg.Pkg.Path(), mode)
		return
	}

	currentPkgPath := ssaPkg.Pkg.Path()

	// Heuristic check: skip control-flow obfuscation for fragile packages.
	// Instead of maintaining an infinite blacklist of external packages,
	// we detect problematic patterns automatically.
	if isFragilePackage(ssaPkg, files) {
		debugf("%s: skip entire package due to fragile heuristics", currentPkgPath)
		return
	}

	// Load the list of packages that were skipped in previous compilations
	skippedPackages, err := loadSkippedPackages(sharedTempDir)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to load skipped packages: %v", err)
	}

	// Collect candidate functions and their AST declarations
	type functionCandidate struct {
		ssaFunc  *ssa.Function
		params   directiveParamMap
		funcDecl *ast.FuncDecl
	}
	var candidates []functionCandidate

	for _, file := range files {
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if funcDecl.Body == nil {
				continue
			}

			params, hasDirective, skip := extractControlFlowIntent(funcDecl.Doc)
			if skip || !shouldObfuscate(mode, funcDecl, hasDirective) {
				if ctrlflowDebug {
					reason := "mode"
					if skip {
						reason = "directive"
					} else if funcDecl.Body == nil || len(funcDecl.Body.List) == 0 {
						reason = "empty"
					}
					debugf("%s: skip candidate %s (%s)", currentPkgPath, funcDecl.Name.Name, reason)
				}
				continue
			}

			path, _ := astutil.PathEnclosingInterval(file, funcDecl.Pos(), funcDecl.Pos())
			ssaFunc := ssa.EnclosingFunction(ssaPkg, path)
			if ssaFunc == nil {
				debugf("%s: unable to find SSA function for %s", currentPkgPath, funcDecl.Name.Name)
				continue
			}
			// Skip functions which create closures over non-anonymous functions (e.g., bound methods),
			// as the current SSA→AST converter does not lower them safely in all cases.
			// Check both the function itself and all its anonymous functions recursively.
			if hasBoundMethodClosure(ssaFunc) {
				debugf("%s: skip %s due to bound method closure", currentPkgPath, funcDecl.Name.Name)
				continue
			}
			// Note: We check for predeclared names at the package level after collecting all candidates

			if params == nil {
				params = make(directiveParamMap)
			}
			candidates = append(candidates, functionCandidate{
				ssaFunc:  ssaFunc,
				params:   params,
				funcDecl: funcDecl,
			})
		}
	}

	if len(candidates) == 0 {
		debugf("%s: no candidate functions found", currentPkgPath)
		return
	}

	// Check if any candidate would be skipped due to predeclared names.
	// If so, skip control-flow for the entire package to avoid broken references
	// and mark this package as skipped for dependent packages.
	for _, candidate := range candidates {
		if hasPredeclaredNames(candidate.ssaFunc) {
			debugf("%s: skip package due to predeclared names in %s", currentPkgPath, candidate.ssaFunc.Name())
			if err := saveSkippedPackage(sharedTempDir, currentPkgPath); err != nil {
				return "", nil, nil, fmt.Errorf("failed to save skipped package: %v", err)
			}
			return
		}
	}

	// Now check if this package imports any package that was skipped due to predeclared names
	// to avoid broken cross-package references
	for _, imp := range ssaPkg.Pkg.Imports() {
		impPath := imp.Path()
		if skippedPackages[impPath] {
			debugf("%s: dependency %s previously marked as skipped", currentPkgPath, impPath)
			if err := saveSkippedPackage(sharedTempDir, currentPkgPath); err != nil {
				return "", nil, nil, fmt.Errorf("failed to save skipped package: %v", err)
			}
			return
		}
	}

	// Early validation: test SSA→AST conversion before modifying files.
	// This prevents leaving empty stubs for functions that fail conversion.
	funcConfig := ssa2ast.DefaultConfig()
	var ssaFuncs []*ssa.Function
	var ssaParams []directiveParamMap
	var funcDecls []*ast.FuncDecl

	for _, candidate := range candidates {
		// Quick dry-run: attempt conversion without full obfuscation
		_, err := ssa2ast.Convert(candidate.ssaFunc, funcConfig)
		if err != nil {
			debugf("%s: dry-run convert failed for %s: %v", currentPkgPath, candidate.ssaFunc.Name(), err)
			continue
		}
		ssaFuncs = append(ssaFuncs, candidate.ssaFunc)
		ssaParams = append(ssaParams, candidate.params)
		funcDecls = append(funcDecls, candidate.funcDecl)
	}

	if len(ssaFuncs) == 0 {
		debugf("%s: dry-run produced no convertible functions", currentPkgPath)
		return
	}

	newFile = &ast.File{
		Package: token.Pos(fset.Base()),
		Name:    ast.NewIdent(files[0].Name.Name),
	}
	// Use a large size (1MB) for the synthetic file to give the printer enough
	// position space. A size of 1 causes go/printer to insert /*line :1*/ comments
	// everywhere, which breaks type conversions like "error(nil)" into "error /*line :1*/ (nil)".
	fset.AddFile(mergedFileName, int(newFile.Package), 1<<20)

	// Reuse funcConfig from validation phase and set up ImportNameResolver
	imports := make(map[string]string)
	funcConfig.ImportNameResolver = func(pkg *types.Package) *ast.Ident {
		if pkg == nil || pkg.Path() == ssaPkg.Pkg.Path() {
			return nil
		}

		name, ok := imports[pkg.Path()]
		if !ok {
			name = importPrefix + strconv.Itoa(len(imports))
			imports[pkg.Path()] = name
			astutil.AddNamedImport(fset, newFile, name, pkg.Path())
		}
		return ast.NewIdent(name)
	}

	var trashGen *trashGenerator

	for i, ssaFunc := range ssaFuncs {
		params := ssaParams[i]
		funcDecl := funcDecls[i]

		split := params.GetInt("block_splits", defaultBlockSplits, maxBlockSplits)
		junkCount := params.GetInt("junk_jumps", defaultJunkJumps, maxJunkJumps)
		passes := params.GetInt("flatten_passes", defaultFlattenPasses, maxFlattenPasses)
		if passes == 0 {
			fmt.Fprintf(os.Stderr, "%q function has no effect on the resulting binary, to fix this flatten_passes must be greater than zero\n", ssaFunc)
		}
		flattenHardening := params.StringSlice("flatten_hardening")

		trashBlockCount := params.GetInt("trash_blocks", defaultTrashBlocks, maxTrashBlocks)
		// TEMPORARY: disable trash blocks due to SSA→AST converter limitations causing "undefined" errors
		trashBlockCount = 0
		if trashBlockCount > 0 && trashGen == nil {
			trashGen = newTrashGenerator(ssaPkg.Prog, ssaPkg.Pkg.Path(), funcConfig.ImportNameResolver, obfRand)
		}

		applyObfuscation := func(ssaFunc *ssa.Function) []dispatcherInfo {
			if trashBlockCount > 0 {
				addTrashBlockMarkers(ssaFunc, trashBlockCount, obfRand)
			}
			for range split {
				if !applySplitting(ssaFunc, obfRand) {
					break // no more candidates for splitting
				}
			}
			if junkCount > 0 {
				addJunkBlocks(ssaFunc, junkCount, obfRand)
			}
			var dispatchers []dispatcherInfo
			for range passes {
				if info := applyFlattening(ssaFunc, obfRand); info != nil {
					dispatchers = append(dispatchers, info)
				}
			}
			fixBlockIndexes(ssaFunc)
			return dispatchers
		}

		dispatchers := applyObfuscation(ssaFunc)
		for _, anonFunc := range ssaFunc.AnonFuncs {
			dispatchers = append(dispatchers, applyObfuscation(anonFunc)...)
		}

		// Because of ssa package api limitations, implementation of hardening for control flow flattening dispatcher
		// is implemented during converting by replacing key values with obfuscated ast expressions
		var prologues []ast.Stmt
		if len(flattenHardening) > 0 && len(dispatchers) > 0 {
			hardening := newDispatcherHardening(flattenHardening)

			ssaRemap := make(map[ssa.Value]ast.Expr)
			for _, dispatcher := range dispatchers {
				decl, stmt := hardening.Apply(dispatcher, ssaRemap, obfRand)
				if decl != nil {
					newFile.Decls = append(newFile.Decls, decl)
				}
				if stmt != nil {
					prologues = append(prologues, stmt)
				}
			}
			funcConfig.SsaValueRemap = ssaRemap
		} else {
			funcConfig.SsaValueRemap = nil
		}

		funcConfig.MarkerInstrCallback = nil
		if trashBlockCount > 0 {
			funcConfig.MarkerInstrCallback = func(m map[string]types.Type) []ast.Stmt {
				return trashGen.Generate(minTrashBlockStmts+obfRand.Intn(maxTrashBlockStmts-minTrashBlockStmts), m)
			}
		}

		astFunc, err := ssa2ast.Convert(ssaFunc, funcConfig)
		if err != nil {
			debugf("%s: conversion failed for %s after obfuscation: %v", currentPkgPath, ssaFunc.Name(), err)
			// SSA→AST conversion failed for this function. Log a warning and skip it.
			// The function has already been removed from the original file, which will
			// cause a typecheck error, but we don't propagate the error to allow other
			// packages/functions to proceed.
			continue
		}
		if len(prologues) > 0 {
			astFunc.Body.List = append(prologues, astFunc.Body.List...)
		}
		newFile.Decls = append(newFile.Decls, astFunc)

		// Only now that conversion succeeded, remove the function from its original file
		funcDecl.Name = ast.NewIdent("_")
		funcDecl.Body = ah.BlockStmt()
		funcDecl.Recv = nil
		funcDecl.Type = &ast.FuncType{Params: &ast.FieldList{}}
		funcDecl.Doc = nil // Remove doc comments to avoid "misplaced compiler directive" errors

		// Track which file was modified
		for _, file := range files {
			for _, decl := range file.Decls {
				if decl == funcDecl {
					// Only add to affectedFiles if not already there
					found := false
					for _, af := range affectedFiles {
						if af == file {
							found = true
							break
						}
					}
					if !found {
						affectedFiles = append(affectedFiles, file)
					}
					break
				}
			}
		}
	}

	if len(newFile.Decls) == 0 {
		debugf("%s: control-flow produced no declarations", currentPkgPath)
		return "", nil, nil, nil
	}

	newFileName = mergedFileName
	return
}
