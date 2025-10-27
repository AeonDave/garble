package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/types"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rogpeppe/go-internal/cache"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/ssa"

	cacheenc "github.com/AeonDave/garble/internal/cache"
)

type (
	funcFullName = string // as per go/types.Func.FullName
	objectString = string // as per recordedObjectString
)

var (
	pkgCacheMu  sync.Mutex
	pkgCacheMem = make(map[[sha256.Size]byte]pkgCache)
)

var (
	cacheEncryptWarnOnce   sync.Once
	cacheEncryptWarnWriter io.Writer = os.Stderr
)

// pkgCache contains information about a package that will be stored in fsCache.
// Note that pkgCache is "deep", containing information about all packages
// which are transitive dependencies as well.
type pkgCache struct {
	// ReflectAPIs is a static record of what std APIs use reflection on their
	// parameters, so we can avoid obfuscating types used with them.
	//
	// TODO: we're not including fmt.Printf, as it would have many false positives,
	// unless we were smart enough to detect which arguments get used as %#v or %T.
	ReflectAPIs map[funcFullName]map[int]bool

	// ReflectObjectNames maps obfuscated names which are reflected to their original
	// non-obfuscated names.
	ReflectObjectNames map[objectString]string
}

func (c *pkgCache) CopyFrom(c2 pkgCache) {
	maps.Copy(c.ReflectAPIs, c2.ReflectAPIs)
	maps.Copy(c.ReflectObjectNames, c2.ReflectObjectNames)
}

func cacheEncryptionSeed() ([]byte, bool) {
	if !flagCacheEncrypt {
		return nil, false
	}
	if sharedCache != nil && len(sharedCache.OriginalSeed) > 0 {
		return sharedCache.OriginalSeed, false
	}
	if flagSeed.present() {
		return flagSeed.bytes, false
	}
	hasBuildNonce := sharedCache != nil && len(sharedCache.BuildNonce) > 0
	if seed := seedHashInput(); len(seed) > 0 && hasBuildNonce {
		if flagDebug {
			fmt.Fprintln(cacheEncryptWarnWriter, "garble: cache encryption using per-build nonce; supply -seed for reusable encrypted cache entries or disable with -no-cache-encrypt")
		}
		return seed, true
	}
	cacheEncryptWarnOnce.Do(func() {
		fmt.Fprintln(cacheEncryptWarnWriter, "garble: cache encryption disabled because no seed or build nonce is available; pass -seed or disable with -no-cache-encrypt")
	})
	return nil, false
}

func decodePkgCacheBytes(data []byte) (pkgCache, error) {
	var loaded pkgCache
	var decryptErr error

	if seed, _ := cacheEncryptionSeed(); len(seed) > 0 {
		if err := cacheenc.Decrypt(data, seed, &loaded); err == nil {
			return loaded, nil
		} else {
			decryptErr = err
		}
	}

	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&loaded); err == nil {
		return loaded, nil
	}

	if decryptErr != nil {
		return pkgCache{}, decryptErr
	}
	return pkgCache{}, fmt.Errorf("gob decode: unable to decode cache entry")
}

func ssaBuildPkg(pkg *types.Package, files []*ast.File, info *types.Info) *ssa.Package {
	// Create SSA packages for all imports. Order is not significant.
	ssaProg := ssa.NewProgram(fset, 0)
	created := make(map[*types.Package]bool)
	var createAll func(pkgs []*types.Package)
	createAll = func(pkgs []*types.Package) {
		for _, p := range pkgs {
			if !created[p] {
				created[p] = true
				ssaProg.CreatePackage(p, nil, nil, true)
				createAll(p.Imports())
			}
		}
	}
	createAll(pkg.Imports())

	ssaPkg := ssaProg.CreatePackage(pkg, files, info, false)
	ssaPkg.Build()
	return ssaPkg
}

func openCache() (*cache.Cache, error) {
	// Use a subdirectory for the hashed build cache, to clarify what it is,
	// and to allow us to have other directories or files later on without mixing.
	dir := filepath.Join(sharedCache.CacheDir, "build")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	return cache.Open(dir)
}

// parseFiles parses a list of Go files.
// It supports relative file paths, such as those found in listedPackage.CompiledGoFiles,
// as long as dir is set to listedPackage.Dir.
func parseFiles(lpkg *listedPackage, dir string, paths []string) (files []*ast.File, err error) {
	mainPackage := lpkg.Name == "main" && lpkg.ForTest == ""
	hasReflectTemplate := false
	for _, candidate := range paths {
		if filepath.Base(candidate) == "reflect_abi_code.go" {
			hasReflectTemplate = true
			break
		}
	}

	for _, path := range paths {
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}

		var src any

		base := filepath.Base(path)
		if lpkg.ImportPath == "internal/abi" && base == "type.go" {
			src, err = abiNamePatch(path)
			if err != nil {
				return nil, err
			}
		} else if mainPackage && hasReflectTemplate && base == "reflect_abi_code.go" && reflectPatchFile == "" {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			src = strings.ReplaceAll(string(content), "//disabledgo:", "//go:")
			reflectPatchFile = path
		} else if mainPackage && !hasReflectTemplate && reflectPatchFile == "" && !strings.HasPrefix(base, "_cgo_") {
			// Note that we cannot add our code to e.g. _cgo_gotypes.go.
			src, err = reflectMainPrePatch(path)
			if err != nil {
				return nil, err
			}

			reflectPatchFile = path
		}

		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			return nil, err
		}

		if mainPackage && src != "" {
			astutil.AddNamedImport(fset, file, "_", "unsafe")
		}

		files = append(files, file)
	}
	if mainPackage && !hasReflectTemplate && reflectPatchFile == "" {
		return nil, fmt.Errorf("main packages must get reflect code patched in")
	}
	return files, nil
}

func loadPkgCache(lpkg *listedPackage, pkg *types.Package, files []*ast.File, info *types.Info, ssaPkg *ssa.Package) (pkgCache, error) {
	key := lpkg.GarbleActionID
	pkgCacheMu.Lock()
	if cached, ok := pkgCacheMem[key]; ok {
		pkgCacheMu.Unlock()
		return cached, nil
	}
	pkgCacheMu.Unlock()

	fsCache, err := openCache()
	if err != nil {
		return pkgCache{}, err
	}
	filename, _, err := fsCache.GetFile(lpkg.GarbleActionID)
	// Already in the cache; load it directly.
	if err == nil {
		if data, readErr := os.ReadFile(filename); readErr == nil {
			if decoded, decodeErr := decodePkgCacheBytes(data); decodeErr == nil {
				pkgCacheMu.Lock()
				pkgCacheMem[key] = decoded
				pkgCacheMu.Unlock()
				return decoded, nil
			}
		}
		// Cache load failed - treat as cache miss and recompute
		// (This handles corrupted cache, incompatible format, etc.)
	}
	computed, err := computePkgCache(fsCache, lpkg, pkg, files, info, ssaPkg)
	if err != nil {
		return pkgCache{}, err
	}
	pkgCacheMu.Lock()
	pkgCacheMem[key] = computed
	pkgCacheMu.Unlock()
	return computed, nil
}

func computePkgCache(fsCache *cache.Cache, lpkg *listedPackage, pkg *types.Package, files []*ast.File, info *types.Info, ssaPkg *ssa.Package) (pkgCache, error) {
	// Not yet in the cache. Load the cache entries for all direct dependencies,
	// build our cache entry, and write it to disk.
	// Note that practically all errors from Cache.GetFile are a cache miss;
	// for example, a file might exist but be empty if another process
	// is filling the same cache entry concurrently.
	computed := pkgCache{
		ReflectAPIs: map[funcFullName]map[int]bool{
			"reflect.TypeOf":  {0: true},
			"reflect.ValueOf": {0: true},
		},
		ReflectObjectNames: map[objectString]string{},
	}
	for _, imp := range lpkg.Imports {
		if imp == "C" {
			// `go list -json` shows "C" in Imports but not Deps.
			// See https://go.dev/issue/60453.
			continue
		}
		// Shadowing lpkg ensures we don't use the wrong listedPackage below.
		lpkg, err := listPackage(lpkg, imp)
		if err != nil {
			return computed, err
		}
		if lpkg.BuildID == "" {
			continue // nothing to load
		}
		if err := func() error { // function literal for the deferred close
			if filename, _, err := fsCache.GetFile(lpkg.GarbleActionID); err == nil {
				// Cache hit; attempt to append new entries to computed.
				if data, readErr := os.ReadFile(filename); readErr == nil {
					if depCache, decodeErr := decodePkgCacheBytes(data); decodeErr == nil {
						computed.CopyFrom(depCache)
						return nil
					}
				}
			}
			// Missing or incompatible entry in the cache for a dependency.
			// Could happen if GARBLE_CACHE was emptied but GOCACHE was not, or if
			// encrypted entries remain but this build lacks the seed. Compute it
			// fresh, which can recurse if many entries are missing.
			files, err := parseFiles(lpkg, lpkg.Dir, lpkg.CompiledGoFiles)
			if err != nil {
				return err
			}
			origImporter := importerForPkg(lpkg)
			pkg, info, err := typecheck(lpkg.ImportPath, files, origImporter)
			if err != nil {
				return err
			}
			computedImp, err := computePkgCache(fsCache, lpkg, pkg, files, info, nil)
			if err != nil {
				return err
			}
			computed.CopyFrom(computedImp)
			return nil
		}(); err != nil {
			return pkgCache{}, fmt.Errorf("pkgCache load for %s: %w", imp, err)
		}
	}

	// Fill the reflect info from SSA, which builds on top of the syntax tree and type info.
	inspector := reflectInspector{
		lpkg:            lpkg,
		pkg:             pkg,
		checkedAPIs:     make(map[string]bool),
		propagatedInstr: map[ssa.Instruction]bool{},
		result:          computed, // append the results
	}
	if ssaPkg == nil {
		ssaPkg = ssaBuildPkg(pkg, files, info)
	}
	inspector.recordReflection(ssaPkg)

	// Encrypt cache if flag enabled and seed present
	// Use sharedCache.OriginalSeed (shared across toolexec processes)
	if seed, _ := cacheEncryptionSeed(); len(seed) > 0 {
		encrypted, err := cacheenc.Encrypt(computed, seed)
		if err != nil {
			return pkgCache{}, fmt.Errorf("cache encryption failed: %v", err)
		}

		if err := fsCache.PutBytes(lpkg.GarbleActionID, encrypted); err != nil {
			return pkgCache{}, err
		}
	} else {
		// Fallback: unencrypted gob encoding
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(computed); err != nil {
			return pkgCache{}, err
		}
		if err := fsCache.PutBytes(lpkg.GarbleActionID, buf.Bytes()); err != nil {
			return pkgCache{}, err
		}
	}

	return computed, nil
}

type importerWithMap struct {
	importMap  map[string]string
	importFrom func(path, dir string, mode types.ImportMode) (*types.Package, error)
}

func (im importerWithMap) Import(_ string) (*types.Package, error) {
	panic("should never be called")
}

func (im importerWithMap) ImportFrom(path, dir string, mode types.ImportMode) (*types.Package, error) {
	if path2 := im.importMap[path]; path2 != "" {
		path = path2
	}
	return im.importFrom(path, dir, mode)
}

func importerForPkg(lpkg *listedPackage) importerWithMap {
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		pkg, err := listPackage(lpkg, path)
		if err != nil {
			return nil, err
		}
		return os.Open(pkg.Export)
	}).(types.ImporterFrom)

	return importerWithMap{
		importFrom: imp.ImportFrom, // method value; receiver already bound
		importMap:  lpkg.ImportMap,
	}
}
