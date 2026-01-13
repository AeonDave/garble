# Garble Architecture — Technical Documentation

---

## Contents

1. [Overview](#1-overview)
2. [High-level Architecture](#2-high-level-architecture)
3. [Core Components](#3-core-components)
4. [Execution Flow](#4-execution-flow)
5. [Obfuscation Mechanisms](#5-obfuscation-mechanisms)
6. [Strengths](#6-strengths)
7. [Implementation Details](#7-implementation-details)

---

## 1. Overview

### 1.1 What Garble is

Garble is a Go code obfuscator that sits between the standard Go toolchain and the build process. It transforms source code to:
- Remove identifying information (names, paths, metadata)
- Protect literals (strings, constants)
- Obfuscate control flow
- Encrypt runtime metadata
- Make reverse engineering significantly harder

This repository is a hardened fork (AeonDave/garble) of burrowers/garble with additional security-focused features.

### 1.2 Differences from upstream

This fork (AeonDave/garble) introduces several improvements compared to `burrowers/garble`:

| Feature            | Upstream | Hardened Fork                         |
|--------------------|----------|---------------------------------------|
| Cache encryption   | ❌       | ✅ ASCON-128                          |
| Feistel cipher     | ❌       | ✅ 4-round metadata protection        |
| Build nonce        | Partial  | ✅ Complete + reproducibility         |
| Directive parsing  | Basic    | ✅ Fuzzing + robust checks            |
| Test coverage      | ~70%     | ~85%                                  |
| Security docs      | Minimal  | ✅ Comprehensive SECURITY.md          |

### 1.3 Requirements

- Go: 1.25 or newer
- OS: Linux, macOS, Windows
- Targets: any platform supported by the Go toolchain

---

## 2. High-level Architecture

### 2.1 Architecture diagram

```
┌────────────────────────────────────────────────────────────┐
│                          GARBLE ARCHITECTURE               │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  User Command: garble build [flags] ./cmd/app              │
│                         │                                  │
│                         ▼                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    main.go (Entry Point)             │  │
│  │  • Flag parsing & validation                         │  │
│  │  • Seed & nonce generation/combination               │  │
│  │  • Environment setup (GARBLE_SHARED, etc.)           │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│                     ▼                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Cache Layer (cache_*.go)                │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Shared Cache (in-memory + encrypted disk)      │  │  │
│  │  │  • ListedPackages (go list -json output)       │  │  │
│  │  │  • Build flags & go env                        │  │  │
│  │  │  • ASCON-128 encryption at rest                │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Package Cache (per-package metadata)           │  │  │
│  │  │  • lpkg (listed package info)                  │  │  │
│  │  │  • ActionID (build cache key)                  │  │  │
│  │  │  • PrivateNameMap (obfuscated name mapping)    │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│                     ▼                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Go Toolchain Wrapper (toolexec)            │  │
│  │  Intercepts: compile, link, asm, etc.                │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│       ┌─────────────┴─────────────────────┐                │
│       ▼                                   ▼                │
│  ┌─────────────┐                    ┌─────────────┐        │
│  │   COMPILE   │                    │    LINK     │        │
│  │ transformer │                    │   linker    │        │
│  └──────┬──────┘                    └──────┬──────┘        │
│         │                                  │               │
│         ▼                                  ▼               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │             Obfuscation Modules                     │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Name Hashing   │  │ Literal Obfusc. │            │   │
│  │  │  (hash.go)     │  │  (literals/)    │            │   │
│  │  │                │  │  • ASCON-128    │            │   │
│  │  │ SHA-256 +      │  │  • Simple       │            │   │
│  │  │ per-package    │  │  • Split/Swap   │            │   │
│  │  │ seed mixing    │  └─────────────────┘            │   │
│  │  └────────────────┘                                 │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Control Flow   │  │ Feistel Cipher  │            │   │
│  │  │  (ctrlflow/)   │  │  (feistel.go)   │            │   │
│  │  │  • Flattening  │  │                 │            │   │
│  │  │  • Block split │  │  4-round per    │            │   │
│  │  │  • Junk jumps  │  │  func metadata  │            │   │
│  │  │  • Trash       │  │  encrypt/decrypt│            │   │
│  │  └────────────────┘  └─────────────────┘            │   │
│  │  ┌────────────────┐                                   │   │
│  │  │ Runtime Patch  │                                   │   │
│  │  │ (runtime_patch)│                                   │   │
│  │  │                │                                   │   │
│  │  │ Inject helpers │                                   │   │
│  │  │ for Feistel    │                                   │   │
│  │  └────────────────┘                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                     │                                      │
│                     ▼                                      │
│            Obfuscated Binary                               │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 2.2 Separation of responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                       LAYER ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CLI & Orchestration Layer (main.go)                      │  │
│  │  • Argument parsing & validation                          │  │
│  │  • Command dispatch (build/test/run)                      │  │
│  │  • Environment & flag management                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Cryptographic Primitive Layer                            │  │
│  │  • Seed & nonce management (hash.go)                      │  │
│  │  • Feistel cipher (feistel.go)                            │  │
│  │  • ASCON-128 encryption (cache_ascon.go, literals/)       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Caching & State Management Layer                         │  │
│  │  • Shared cache (cache_shared.go)                         │  │
│  │  • Package cache (cache_pkg.go)                           │  │
│  │  • Encrypted persistence (cache_ascon.go)                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Transformation Layer (transformer.go)                    │  │
│  │  • AST parsing & type checking                            │  │
│  │  • Name obfuscation                                       │  │
│  │  • Import rewriting                                       │  │
│  │  • Reflection handling                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Obfuscation Modules (internal/)                          │  │
│  │  • Literal obfuscation (literals/)                        │  │
│  │  • Control flow (ctrlflow/)                               │  │
│  │  • Linker patches (linker/)                               │  │
│  │  • SSA to AST conversion (ssa2ast/)                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Go Toolchain Integration                                 │  │
│  │  • Compile wrapper                                        │  │
│  │  • Link wrapper                                           │  │
│  │  • Assembly wrapper                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Components

### 3.1 main.go — Entry point and orchestration

Responsibilities:
- Parse CLI flags
- Generate and combine seed and nonce
- Setup environment (GARBLE_SHARED, temp directories)
- Dispatch commands (build/test/run)

Main flags:

```go
-seed=<base64|random>   // Seed for reproducible builds; random per build by default
-literals               // Enable literal obfuscation
-tiny                   // Remove extra info (panic messages, etc.)
-controlflow            // Enable control flow obfuscation
-debugdir               // Directory for debug output
-no-cache-encrypt       // Disable cache encryption (default: ON)
```

Environment variables:

```bash
GARBLE_BUILD_NONCE=<base64>  # Build nonce for uniqueness/reproducibility
GARBLE_SHARED=/tmp/garble123 # Shared temporary directory
```

### 3.2 hash.go — Cryptographic core

Algorithms:
1. SHA-256: name hashing and key derivation
2. Base64: encoding hashes into valid Go identifiers
3. Seed combination: SHA-256(seed || nonce) for combined entropy

Key functions:

```go
func hashWith(inputHash, name string) string
    // Hash a name using SHA-256, salted with inputHash

func hashWithCustomSalt(salt, name string) string
    // Hash with a custom salt for different namespaces

func combineSeedAndNonce(seed, nonce []byte) [32]byte
    // Combine seed and nonce via SHA-256
```

### 3.3 transformer.go — AST transformation engine

Transformation pipeline:

```
Source Code (.go files)
    │
    ▼
┌─────────────────────┐
│ Parse (go/parser)   │  → AST (Abstract Syntax Tree)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Type Check          │  → types.Package, types.Info
│ (go/types)          │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Compute Metadata    │  → fieldToStruct map, linkerVariableStrings
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Apply Transformations│
│  • Name hashing     │
│  • Import rewriting │
│  • Literal obfusc.  │
│  • Control flow     │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Generate Output     │  → Obfuscated .go files
└─────────────────────┘
```

Primary transformations:
1. Name obfuscation: apply `hashWith()` to identifiers
2. Import path rewriting: rewrite import paths as needed
3. Position removal: zero out token.Pos to strip original positions
4. Reflection handling: never embed original names (reflection map stays empty)

### 3.4 Cache layer (cache_*.go)

Cache architecture:

```
┌──────────────────────────────────────────────────┐
│              GARBLE CACHE SYSTEM                 │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Shared Cache (Global, Process-wide)       │  │
│  │  ────────────────────────────────────────  │  │
│  │  Location: GARBLE_SHARED env variable      │  │
│  │                                            │  │
│  │  Contents:                                 │  │
│  │  • ListedPackages (from go list -json)     │  │
│  │  • ForwardBuildFlags                       │  │
│  │  • GoEnv (GOARCH, GOOS, etc.)              │  │
│  │  • ExecPath (path to toolexec wrapper)     │  │
│  │  • GOGARBLE pattern                        │  │
│  │                                            │  │
│  │  Persistence:                              │  │
│  │  → Encrypted with ASCON-128 (default ON)   │  │
│  │  → Serialized with gob encoding            │  │
│  │  → Format: [nonce][ciphertext][tag]        │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Package Cache (Per-Package Metadata)      │  │
│  │  ────────────────────────────────────────  │  │
│  │  Keyed by: Package import path             │  │
│  │                                            │  │
│  │  Contents:                                 │  │
│  │  • lpkg (listedPackage from go list)       │  │
│  │  • ActionID (build cache identifier)       │  │
│  │  • PrivateNameMap (obfuscated names)       │  │
│  │  • OrigImporter (type importer)            │  │
│  │                                            │  │
│  │  NOT persisted (in-memory only per build)  │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
└──────────────────────────────────────────────────┘
```

cache_ascon.go — ASCON-128 encryption:
- Algorithm: ASCON-128 (a NIST lightweight cipher standard winner)
- Key derivation: SHA-256(seed || "garble-cache-encryption-v1")
- Format: [16-byte nonce][ciphertext][16-byte auth tag]
- Provides confidentiality and authentication

### 3.5 Obfuscation modules (internal/)

#### 3.5.1 literals/ — Literal obfuscation

Available obfuscators:

```go
type obfuscator interface {
    obfuscate(rand *mathrand.Rand, data []byte) *ast.BlockStmt
}
```

Pre-pass performed in transformer.go:
1. Analyze package constants (computeConstTransforms)
2. Skip constants required in constant contexts (array lengths, iota, switch cases)
3. Convert eligible constants to package-level vars during preparation (rewriteConstDecls)

Obfuscator types:

1. ASCON obfuscator (cryptographically strong)
   - Encrypts literals with ASCON-128
   - Injects inline decryption code

2. Simple obfuscator (lighter, irreversible)
   - S-box + Feistel + external key mixing
   - No de-obfuscation metadata emitted

3. Split obfuscator
   - Splits a string into chunks and reconstructs it at runtime

4. Swap obfuscator
   - Swaps character positions

Obfuscator selection:

```
Literal size < 2KB?
    ├─ Yes → ASCON, Simple, Split, Swap (random choice)
    └─ No  → ASCON or linear-time obfuscators (random choice)
```

Constant pre-processing (in transformer.go):
- `computeConstTransforms` builds a map `*types.Const → constTransform` by tracking all `Ident` usages and excluding exported constants, type aliases, or constants constrained by constant contexts.
- `rewriteConstDecls` rewrites eligible `GenDecl` `const` declarations to `var`, updating `types.Info.Defs` and `types.Info.Uses` so obfuscators operate on runtime variables.
- Converted constants keep original doc and trailing comments to preserve documentation for `-debugdir`.

Sanitizing `-ldflags -X` (main.go → transformer.go):
- `sanitizeLinkerFlags()` intercepts `-ldflags` before they reach the Go toolchain
- It extracts all `-X package.var=value` assignments into a `LinkerInjectedStrings` map
- It rewrites the flags with empty values: `-X package.var=` so the linker never sees plaintext values
- When compiling the final package, `injectLinkerVariableInit()` generates an `init()` function that sets the variable:

```go
func init() {
    varName = <obfuscated_literal("original_value")>
}
```

- The injected value is obfuscated (ASCON-128 or Simple) like any other literal
- Result: API keys, secrets, and linker-injected strings are protected in the final binary

#### 3.5.2 ctrlflow/ — Control flow obfuscation

Available modes:

```go
const (
    ModeOff        Mode = iota  // Disabled
    ModeXor                      // XOR-based dispatcher
    ModeComplex                  // SSA + flattening + junk
)
```

Techniques:

1. Flattening: converts if/switch constructs into a centralized dispatcher
2. Block splitting: splits basic blocks into sub-blocks with intermediate jumps
3. Junk jumps: inserts non-functional jumps to confuse the CFG
4. Trash blocks: injects dead code to increase complexity

Directives:

```go
//garble:controlflow flatten=max splits=10 junk=5
func myFunc() { ... }

//garble:nocontrolflow
func skipThis() { ... }
```

#### 3.5.3 linker/ — Runtime patching

Runtime patches for Go:
- Inject helper functions for Feistel decryption
- Patch runtime.funcname() to decrypt names on the fly
- Keep reflection name mapping empty to avoid leaking identifiers

---

## 4. Execution Flow

### 4.1 Full build flow

```
┌──────────────────────────────────────────────────────────────┐
│  PHASE 1: Initialization & Setup                             │
├──────────────────────────────────────────────────────────────┤
│  1. Parse CLI flags (main.go)                                │
│  2. Generate/load seed and nonce                             │
│  3. Combine seed/nonce → combined hash                       │
│  4. Setup GARBLE_SHARED temp directory                       │
│  5. Run "go list -json -export -toolexec" to populate cache  │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 2: Cache Population                                   │
├──────────────────────────────────────────────────────────────┤
│  6. Parse go list JSON output → ListedPackages               │
│  7. Determine which packages to obfuscate (GOGARBLE)         │
│  8. Encrypt & persist shared cache to disk (ASCON-128)       │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 3: Per-Package Compilation (toolexec loop)            │
├──────────────────────────────────────────────────────────────┤
│  For each package in dependency order:                       │
│                                                              │
│  9. Toolexec intercepts "compile" command                  │
│  10. Load package metadata from cache                        │
│  11. Parse .go files → AST                                   │
│  12. Type-check → types.Package, types.Info                  │
│  13. Apply transformations:                                  │
│      ├─ Hash identifiers (hashWith)                          │
│      ├─ Obfuscate literals (if -literals)                    │
│      ├─ Obfuscate control flow (if -controlflow)             │
│      ├─ Remove positions & build info                        │
│      └─ Rewrite imports                                      │
│  14. Write obfuscated .go files to temp directory            │
│  15. Call original Go compiler on obfuscated files           │
│  16. Cache obfuscated names for dependent packages           │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 4: Linking                                            │
├──────────────────────────────────────────────────────────────┤
│  17. Toolexec intercepts "link" command                     │
│  18. Apply linker patches (runtime helpers, etc.)            │
│  19. Strip debug info (-w -s)                                │
│  20. Remove build/module info                                │
│  21. Call original Go linker                                 │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 5: Cleanup                                            │
├──────────────────────────────────────────────────────────────┤
│  22. Remove GARBLE_SHARED temp directory                     │
│  23. Return obfuscated binary                                │
└──────────────────────────────────────────────────────────────┘
```

## 5. Obfuscation mechanisms

### 5.1 Name obfuscation

Algorithm:

```
Original Name: "MyFunction"
Package Path: "github.com/user/pkg"
Seed: <32-byte combined seed>

Step 1: Compute package-specific salt
    salt = SHA-256(seed || packagePath)[:8]

Step 2: Hash the name
    hash = SHA-256(salt || "MyFunction")

Step 3: Encode to a valid Go identifier
    encoded = base64url(hash[:8])
    obfuscatedName = sanitize(encoded)  // e.g., "A7bK2xQz"
```

Namespace isolation:
- Each package has a different salt
- Identical names in different packages produce different hashes
- Collision probability: negligible (64-bit space in this scheme)

### 5.2 Literal obfuscation (ASCON-128)

Flow for a string literal:

```go
Original Code:
    msg := "Hello, World!"

Step 1: Derive per-literal key
    literalKey = deriveLiteralKey(combinedSeed, literalIndex)

Step 2: Encrypt with ASCON-128
    ciphertext = ASCON_Encrypt(literalKey, nonce, "Hello, World!")

Step 3: Inject inline decryption
    Obfuscated Code:
    func() string {
        key := interleave(evenKey, oddKey)    // embedded, split
        nonce := interleave(evenNonce, oddNonce)
        ct := interleave(evenCt, oddCt)       // ciphertext
        pt := asconDecrypt(key, nonce, ct)    // zeroizes key/nonce/ct internally
        return string(pt)
    }()
```

Characteristics:
- Each literal has a unique key and nonce
- Runtime decryption overhead: ~1–2 µs per literal
- No plaintext leakage (AEAD provides authentication)
- Key/nonce/ciphertext are interleaved at build time and zeroized after decrypt

### 5.3 Feistel cipher for metadata

Applied to the runtime funcInfo table:

```
Go runtime maintains a table of functions like:
    type funcInfo struct {
        nameOff int32   // Offset in the namedata section
        ...
    }

Obfuscation:
    1. Derive 4 round keys from the seed
    2. For each funcInfo entry:
        encryptedNameOff = Feistel_Encrypt(nameOff, funcID, keys)
    3. Patch runtime.funcname() to decrypt on the fly:
        func funcname(f funcInfo) string {
            realOff := Feistel_Decrypt(f.nameOff, f.funcID, keys)
            return namedata[realOff:]
        }
```

Properties:
- Format-preserving: the encrypted value has the same size as the original
- Deterministic runtime decryption with the same keys
- Overhead: ~10 ns per decryption (4 rounds)

### 5.4 Control flow obfuscation (Complex mode)

Example flattening:

```go
// Original Function
func calculate(x int) int {
    if x > 10 {
        x = x * 2
    } else {
        x = x + 5
    }
    return x
}

// Flattened Version
func calculate(x int) int {
    state := 0
    var result int
    for {
        switch state {
        case 0:
            if x > 10 {
                state = 1
            } else {
                state = 2
            }
        case 1:
            x = x * 2
            state = 3
        case 2:
            x = x + 5
            state = 3
        case 3:
            result = x
            return result
        }
    }
}
```

Adding trash blocks:

```go
case 4:  // Dead code, never reached
    x = x ^ 0xDEADBEEF
    if false {
        panic("never happens")
    }
    state = 0
```

---

## 6. Strengths

### 6.1 Security

1. Standard crypto primitives:
   - ASCON-128 (NIST Lightweight Crypto competition winner)
   - SHA-256 for hashing and key derivation
   - No home-grown crypto

2. Defense in depth:
   - Multiple obfuscation layers
   - At-rest cache encryption
   - Runtime metadata protection
   - Literal protection

3. Reproducible and auditable builds:
   - Deterministic seeds for CI/CD
   - Build nonce for uniqueness and reproducibility

### 6.2 Performance

1. Compile-time overhead:
   - ~10–30% slower than standard `go build` (depends on options)
   - Parallelizable (go build -p)
   - Efficient caching reduces repeated work

2. Runtime overhead:
   - Name obfuscation: zero runtime overhead (static)
   - Literal decryption: ~1–2 µs per literal (lazy)
   - Feistel decryption: ~10 ns per function (amortized)
   - Control flow: ~5–15% overhead (optional and configurable)

3. Binary size:
   - Base obfuscation: +5–10% (inline decryption code)
   - `-tiny` mode: -10–20% (removes panic messages, etc.)
   - `-literals`: +10–30% (depends on number/size of literals)

### 6.3 Compatibility

1. Go version support:
   - Go 1.25+ fully supported
   - Backwards compatibility considered where practical

2. Platform support:
   - GOARCH: amd64, arm64, 386, arm, etc. (all architectures Go supports)
   - GOOS: linux, darwin, windows, etc.
   - cgo: supported with limitations on obfuscation

3. Modules & dependencies:
   - Go modules: supported
   - Vendor: supported
   - `replace` directives: supported

### 6.4 Maintainability

1. Structured codebase:
   - Clear layer separation (CLI, crypto, cache, transform, obfuscation)
   - Well-defined interfaces (obfuscator interface, etc.)
   - Inline documentation

2. Testing:
   - Unit tests: ~85% coverage
   - Integration tests: cache encryption, control flow, literals
   - Fuzz tests: directive parsing, literal obfuscation

3. Debugging:
   - `-debugdir` flag to inspect obfuscated source
   - Detailed logging via `log.SetPrefix("[garble]")`

### 6.5 Extensibility

1. Obfuscator plugin system:
   - Add new obfuscators by implementing the `obfuscator` interface
   - Literal obfuscators are composable

2. Control flow modes:
   - Off / XOR / Complex
   - Configurable via per-function directives

3. Custom patches:
   - Linker patches are extensible (see `internal/linker/patches/`)

---

## 7. Implementation details

### 7.1 Error handling

Strategies:
1. Early validation: strict flag parsing at startup
2. Graceful degradation: if cache crypto fails, fall back to plaintext with a warning
3. Contextual errors: wrap errors using `fmt.Errorf` for context

Example:

```go
func encryptCache(data any, seed []byte) ([]byte, error) {
    if len(seed) == 0 {
        return nil, fmt.Errorf("cache encryption: seed cannot be empty")
    }
    return cache.Encrypt(data, seed)
}
```

### 7.2 Concurrency & thread safety

Shared cache:
- Read-only after initialization — no locks required for reads
- Per-package cache is isolated and avoids contention

Crypto operations:
- Stateless: each operation is independent
- RNG seeding done once at startup and deterministic when requested

### 7.3 Memory management

Optimizations:
1. Lazy loading: packages are loaded only when required
2. Streaming parsing: ASTs are not retained longer than necessary
3. Temp files: obfuscated source files are written to disk instead of kept in memory

Profiling example:

```bash
GARBLE_WRITE_MEMPROFILES=/tmp garble build ./...
# Produces .pprof files for analysis
```

### 7.4 File system layout

```
$GARBLE_SHARED/
├── main-cache.gob.enc         # Encrypted shared cache
├── pkg-cache/
│   ├── github.com_user_pkg1.gob.enc
│   └── github.com_user_pkg2.gob.enc
└── obfuscated-src/
    ├── pkg1/
    │   ├── file1.go
    │   └── file2.go
    └── pkg2/
        └── file.go
```

### 7.5 Integration with the Go toolchain

Toolexec mechanism:

```bash
# Internally Go calls:
/path/to/garble toolexec compile -o output.a input.go

# Garble:
# 1. Intercepts the command
# 2. Applies obfuscation
# 3. Calls the real compiler:
$GOTOOLDIR/compile -o output.a obfuscated.go
```

Action graph:
- Garble generates an action graph JSON to determine build order
- It respects package dependencies

---

## 8. ASCII diagrams summary

### 8.1 Data flow: Seed → Obfuscated binary

```
User Seed (-seed=...)
    │
    ├─► SHA-256 ──► 32 bytes seed
    │
    └─► Combined with Build Nonce
            │
            ▼
     Combined Hash (32 bytes)
            │
     ┌──────┴─────────────────────────┐
     │                                │
     ▼                                ▼
Package Salt Derivation      Crypto Key Derivation
     │                                │
     ├─► Name Hashing                 ├─► ASCON Literal Keys
     │   (per identifier)             │   (per literal)
     │                                │
     └─► Import Path Hashing          └─► Feistel Round Keys
                                          (4x32-bit)
                                      │
                                      └─► Cache Encryption Key
```

### 8.2 Build pipeline: Source → Binary

```
main.go, util.go, ...
    │
    ├─► Parse ─────────────► AST
    │
    ├─► Type Check ────────► types.Info
    │
    ├─► Transform ─────────► Obfuscated AST
    │   ├─ Hash Names
    │   ├─ Obfuscate Literals
    │   ├─ Obfuscate Control Flow
    │   └─ Remove Positions
    │
    ├─► Generate ──────────► Obfuscated .go files
    │
    ├─► Compile ───────────► .a archive
    │
    └─► Link ──────────────► Obfuscated Binary
        └─ Inject Runtime Patches
        └─ Strip Debug Info
```

### 8.3 Security layers

```
┌────────────────────────────────────────────────────┐
│              GARBLE SECURITY LAYERS                │
├────────────────────────────────────────────────────┤
│                                                    │
│  Layer 1: Name Obfuscation (SHA-256)               │
│  ┌──────────────────────────────────────────────┐  │
│  │ All identifiers hashed                       │  │
│  │ Package paths hashed                         │  │
│  │ No original names in binary                  │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 2: Literal Protection (ASCON-128)           │  │
│  ┌──────────────────────────────────────────────┐  │
│  │ Strings encrypted inline                     │  │
│  │ Constants obfuscated                         │  │
│  │ Runtime decryption only                      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 3: Metadata Hardening (Feistel)             │  │
│  ┌──────────────────────────────────────────────┐  │
│  │ funcInfo table encrypted                     │  │
│  │ Runtime helpers injected                     │  │
│  │ Format-preserving encryption                 │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 4: Control Flow Obfuscation (Optional)      │  │
│  ┌──────────────────────────────────────────────┐  │
│  │ Flattening + junk jumps                      │  │
│  │ Dead code injection                          │  │
│  │ CFG complexity increase                      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 5: Cache Encryption (ASCON-128)             │  │
│  ┌──────────────────────────────────────────────┐  │
│  │ Build artifacts encrypted at rest            │  │
│  │ Authenticated encryption (AEAD)              │  │
│  │ Tampering detected                           │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## Conclusion

Garble is a mature, security-focused Go obfuscator with a modular architecture that balances:
- Security: standard cryptography and multiple protection layers
- Performance: acceptable compile- and runtime overheads
- Usability: simple CLI and transparent Go toolchain integration
- Maintainability: well-structured, tested, documented codebase

The AeonDave/garble fork adds cache encryption, metadata hardening, and enterprise-grade robustness compared to upstream.

For security details see SECURITY.md.
For advanced configuration see FEATURE_TOGGLES.md.
For control flow specifics see CONTROLFLOW.md.

---

**Maintainer:** AeonDave
**Last updated:** 8 October 2025
**Garble version:** 0.14.x (hardened fork)

