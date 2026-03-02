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
- Protect literals (strings, constants) using per-build random ciphers
- Obfuscate control flow
- Make reverse engineering significantly harder

This repository is a hardened fork (AeonDave/garble) of burrowers/garble with additional security-focused features.

### 1.2 Differences from upstream

This fork (AeonDave/garble) introduces several improvements compared to `burrowers/garble`:

| Feature               | Upstream | Hardened Fork                              |
|-----------------------|----------|--------------------------------------------|
| Cache encryption      | ❌       | ✅ ASCON-128                               |
| Stealth literals      | ❌       | ✅ Per-build random SPN cipher             |
| Build nonce           | Partial  | ✅ Complete + reproducibility              |
| Directive parsing     | Basic    | ✅ Fuzzing + robust checks                 |
| `-force-rename` flag  | ❌       | ✅ Renames exported methods                |
| Test coverage         | ~70%     | ~85%                                       |
| Security docs         | Minimal  | ✅ Comprehensive SECURITY.md               |

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
│  │  │                │  │  • Custom Cipher│            │   │
│  │  │ SHA-256 +      │  │  • Swap/Split  │            │   │
│  │  │ per-package    │  │  • Shuffle/Seed│            │   │
│  │  │ seed mixing    │  └─────────────────┘            │   │
│  │  └────────────────┘                                 │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Control Flow   │  │ Runtime Patch   │            │   │
│  │  │  (ctrlflow/)   │  │ (runtime_patch) │            │   │
│  │  │  • Flattening  │  │                 │            │   │
│  │  │  • Block split │  │ Strip runtime   │            │   │
│  │  │  • Junk jumps  │  │ print/trace     │            │   │
│  │  │  • Trash       │  │ (-tiny mode)    │            │   │
│  │  └────────────────┘  └─────────────────┘            │   │
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
│  │  • ASCON-128 for cache encryption (internal/cache/)       │  │
│  │  • Per-build random cipher (internal/literals/)           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Caching & State Management Layer                         │  │
│  │  • Shared cache (cache_shared.go)                         │  │
│  │  • Package cache (cache_pkg.go)                           │  │
│  │  • Encrypted persistence (internal/cache/encryption.go)   │  │
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
-force-rename           // Rename exported methods (may break interfaces)
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

internal/cache/encryption.go — ASCON-128 encryption:
- Algorithm: ASCON-128 (a NIST lightweight cipher standard winner)
- Key derivation: SHA-256(seed || "garble-cache-encryption-v1")
- Format: [16-byte nonce][ciphertext][16-byte auth tag]
- Provides confidentiality and authentication
- Used only for build cache (never appears in output binaries)

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

1. **Custom cipher** (primary, ~60% weight)
   - Per-build random 256-byte S-box via Fisher-Yates shuffle
   - Multi-round SPN with CBC-like diffusion (4-6 rounds)
   - No fixed cryptographic constants — stealth by design
   - Inline decryption code generated as AST

2. **Split** obfuscator
   - Splits a string into chunks and reconstructs at runtime

3. **Swap** obfuscator
   - Swaps character positions

4. **Shuffle** obfuscator
   - Applies a random permutation to byte positions

5. **Seed** obfuscator
   - Uses a seed-based PRNG to generate XOR masks

Obfuscator selection (weighted):

```
Literal size < 2KB?
    ├─ Yes → Custom cipher, Split, Swap, Shuffle, Seed (weighted random)
    └─ No  → Linear-time obfuscators only (Split, Swap, Shuffle, Seed)
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

- The injected value is obfuscated like any other literal
- Result: API keys, secrets, and linker-injected strings are protected in the final binary

#### 3.5.2 ctrlflow/ — Control flow obfuscation

Available modes:

```go
const (
    ModeOff        Mode = iota  // Disabled (default)
    ModeDirectives              // Only //garble:controlflow functions
    ModeAuto                    // All eligible except //garble:nocontrolflow
    ModeAll                     // Every function
)
```

Techniques:

1. Flattening: converts if/switch constructs into a centralised dispatcher
2. Block splitting: splits basic blocks into sub-blocks with intermediate jumps
3. Junk jumps: inserts non-functional jumps to confuse the CFG
4. Trash blocks: injects dead code to increase complexity
5. Hardening prologues: dispatcher keys are obfuscated with opaque predicates

Directives:

```go
//garble:controlflow
func myFunc() { ... }

//garble:nocontrolflow
func skipThis() { ... }
```

#### 3.5.3 linker/ — Linker patching

Applied at link time:
- Patch the Go linker to strip additional metadata
- Communicate `-tiny` mode via `_XLINK_TINY` environment variable
- Apply linker patches from `internal/linker/patches/`

#### 3.5.4 runtime_patch.go — Runtime patching

Applied when building the `runtime` package:
- `stripRuntime()`: Removes runtime print and traceback function bodies (when `-tiny`)
- `nopPrintDecl()`: Replaces function bodies with empty returns

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
│  9.  Toolexec intercepts "compile" command                   │
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
│  17. Toolexec intercepts "link" command                      │
│  18. Apply linker patches                                    │
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

---

## 5. Obfuscation Mechanisms

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
- Collision probability: negligible (64-bit space)

### 5.2 Literal obfuscation (per-build random cipher)

Flow for a string literal:

```go
Original Code:
    msg := "Hello, World!"

Step 1: Select obfuscation strategy (weighted random)
    // ~60%: Custom cipher, ~10% each: swap, split, shuffle, seed

Step 2 (Custom cipher path):
    // Generate per-build random S-box via Fisher-Yates
    sbox := fisherYatesSbox(rand)
    invSbox := invertSbox(sbox)
    rounds := 4 + rand.Intn(3)
    keyBytes := randomBytes(rounds)

    // Encrypt with SPN (substitution-permutation network)
    ciphertext := customCipherEncrypt(sbox, keyBytes, plaintext)

Step 3: Emit inline decryption code (AST)
    Obfuscated Code:
    func() string {
        data := []byte{...ciphertext...}
        invSbox := [256]byte{...}   // per-build random
        keyBytes := []byte{...}     // per-build random
        for r := len(keyBytes)-1; r >= 0; r-- {
            // Inverse substitution
            // Inverse CBC diffusion
            // XOR with round key
        }
        return string(data)
    }()
```

Stealth characteristics:
- No fixed cryptographic constants (AES S-boxes, ASCON IVs) in output
- Each build produces a unique S-box permutation
- Runtime decryption overhead: ~1–2 µs per literal
- Key material is zeroized after decryption

### 5.3 Control flow obfuscation

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

1. **Stealth-first literal encryption**:
   - Per-build random SPN cipher — no detectable crypto signatures
   - Fisher-Yates S-box generation defeats findcrypt and YARA rules
   - Multiple obfuscation strategies for diversity

2. **Defense in depth**:
   - Multiple obfuscation layers (names, literals, control flow, metadata)
   - At-rest cache encryption (ASCON-128)
   - Literal protection with weighted strategy selection

3. **Reproducible and auditable builds**:
   - Deterministic seeds for CI/CD
   - Build nonce for uniqueness and reproducibility

### 6.2 Performance

1. Compile-time overhead:
   - ~10–30% slower than standard `go build` (depends on options)
   - Parallelisable (go build -p)
   - Efficient caching reduces repeated work

2. Runtime overhead:
   - Name obfuscation: zero runtime overhead (static)
   - Literal decryption: ~1–2 µs per literal
   - Control flow: ~5–15% overhead (optional and configurable)

3. Binary size:
   - Base obfuscation: +5–10% (inline decryption code)
   - `-tiny` mode: -10–20% (removes panic messages, etc.)
   - `-literals`: +10–30% (depends on number/size of literals)

### 6.3 Compatibility

1. Go version support: Go 1.25+ fully supported
2. Platform support: all GOARCH/GOOS combinations Go supports
3. Modules, vendor, and `replace` directives: supported
4. cgo: supported with limitations on obfuscation

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
   - Weighted strategy registry for selection control
   - Literal obfuscators are composable

2. Control flow modes:
   - Off / Directives / Auto / All
   - Configurable via per-function directives

3. Custom patches:
   - Linker patches are extensible (see `internal/linker/patches/`)

---

## 7. Implementation Details

### 7.1 Error handling

Strategies:
1. Early validation: strict flag parsing at startup
2. Graceful degradation: if cache crypto fails, fall back to plaintext with a warning
3. Contextual errors: wrap errors using `fmt.Errorf` for context

### 7.2 Concurrency & thread safety

Shared cache:
- Read-only after initialisation — no locks required for reads
- Per-package cache is isolated and avoids contention

Crypto operations:
- Stateless: each operation is independent
- RNG seeding done once at startup and deterministic when requested

### 7.3 Memory management

Optimisations:
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
│   ├── <action-id-1>.gob.enc
│   └── <action-id-2>.gob.enc
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
     ├─► Name Hashing                 ├─► Per-build SPN cipher keys
     │   (per identifier)             │   (random S-box + round keys)
     │                                │
     └─► Import Path Hashing          └─► Cache Encryption Key
                                          (ASCON-128)
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
│  Layer 2: Literal Protection (Random SPN Cipher)   │
│  ┌──────────────────────────────────────────────┐  │
│  │ Strings encrypted with per-build cipher      │  │
│  │ Constants obfuscated                         │  │
│  │ No detectable crypto signatures              │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 3: Control Flow Obfuscation (Optional)      │
│  ┌──────────────────────────────────────────────┐  │
│  │ Flattening + junk jumps                      │  │
│  │ Dead code injection                          │  │
│  │ CFG complexity increase                      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 4: Cache Encryption (ASCON-128)             │
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
- **Security**: stealth-first literal encryption with no detectable crypto signatures, plus standard cryptography for cache protection
- **Performance**: acceptable compile- and runtime overheads
- **Usability**: simple CLI and transparent Go toolchain integration
- **Maintainability**: well-structured, tested, documented codebase

The AeonDave/garble fork adds cache encryption, stealth literal protection, and enterprise-grade robustness compared to upstream.

For security details see SECURITY.md.
For advanced configuration see FEATURES.md.
For control flow specifics see CONTROLFLOW.md.
For literal encryption design see LITERAL_ENCRYPTION.md.

---

**Maintainer:** AeonDave
**Last updated:** January 2025
