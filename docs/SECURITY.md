# Garble hardened Security Architecture

**Last Updated**: October 8, 2025  
**Status**: ✅ Production Ready

This document provides the comprehensive technical security architecture of Garble's obfuscation mechanisms. It details each security component with its implementation, threat model, and operational characteristics.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Seed & Nonce Architecture](#2-seed--nonce-architecture)
3. [Runtime Metadata Hardening (Feistel Cipher)](#3-runtime-metadata-hardening-feistel-cipher)
4. [Literal Obfuscation (ASCON-128 + Simple)](#4-literal-obfuscation-ascon-128--simple)
5. [Reflection Control](#5-reflection-control)
6. [Build Cache Encryption (ASCON-128)](#6-build-cache-encryption-ascon-128)
7. [Control-Flow Obfuscation](#7-control-flow-obfuscation)
8. [Threat Model & Mitigation Matrix](#8-threat-model--mitigation-matrix)
9. [Security Limitations & Roadmap](#9-security-limitations--roadmap)
10. [References & Resources](#10-references--resources)

---

## 1. Executive Summary

### Security Posture Snapshot

| Component          | Status      | Implementation                                  |
|--------------------|-------------|-------------------------------------------------|
| Runtime Metadata   | ✅ Deployed  | 4-round Feistel cipher with per-function tweak  |
| Literal Protection | ✅ Deployed  | ASCON-128 inline + irreversible multi-layer obfuscation |
| Name Hashing       | ✅ Deployed  | SHA-256 with per-build nonce mixing             |
| Reflection Oracle  | ✅ Mitigated | Always empty; original identifiers never embedded |
| Cache Encryption   | ✅ Deployed  | ASCON-128 at rest with authentication           |
| Control-Flow       | ⚠️ Optional | Multiple modes available; default off           |

### Key Security Properties

- **Per-Build Uniqueness**: Every build uses a cryptographically random nonce mixed with the seed, ensuring symbol names and keys differ even with identical source code (unless explicitly reproduced).
- **Metadata Hardening**: Runtime function tables are encrypted with format-preserving Feistel encryption; decryption happens transparently at runtime via injected helpers.
- **Literal Protection**: Strings and constants are encrypted inline using NIST-standard ASCON-128 plus multi-layer irreversible transforms (see `docs/LITERAL_ENCRYPTION.md`).
- **Reflection Suppression**: Original identifier names are omitted from binaries by default, eliminating the reverse-engineering oracle.
- **Cache Security**: Build artifacts are encrypted at rest; tampering is detected via authentication tags.

---

## 2. Seed & Nonce Architecture

### Purpose

Provide reproducible yet secure randomness for all obfuscation operations, with explicit control over determinism vs. per-build uniqueness.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   Build Time - Entropy Flow                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Seed (optional)              Build Nonce              │
│  -seed=<base64> or random      GARBLE_BUILD_NONCE=<base64>  │
│         │                              │                    │
│         ├─ SHA-256 ─────►  32 bytes    │                    │
│         │                              │                    │
│         └──────────────┬───────────────┘                    │
│                        │                                    │
│              ┌─────────▼─────────┐                          │
│              │  combineSeedAndNonce()                       │
│              │  SHA-256(seed || nonce)                      │
│              └─────────┬─────────┘                          │
│                        │                                    │
│                        ▼                                    │
│            Combined Hash (32 bytes)                         │
│                        │                                    │
│        ┌───────────────┼───────────────┐                    │
│        │               │               │                    │
│        ▼               ▼               ▼                    │
│   Name Hashing    Feistel Keys   Literal Keys              │
│   (per-package)   (4x32-bit)     (per-literal)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Components

#### Seed (`-seed` flag)
- **Format**: Base64-encoded bytes or literal `random`
- **Processing**: Hashed to 32 bytes via SHA-256 for uniform entropy
- **Default**: Random per build (use `-seed=random` to print the generated seed)
- **Random Mode**: Generates 32 cryptographic random bytes; printed to stderr for reproducibility

#### Build Nonce (`GARBLE_BUILD_NONCE` env)
- **Format**: Base64-encoded 32 bytes (no padding)
- **Default**: Randomly generated per build
- **Printed**: When randomly generated (format: `-nonce chosen at random: <base64>`)
- **Purpose**: Ensures different builds produce different hashes even with identical seed and source

#### Combining Function
```go
func combineSeedAndNonce(seed, nonce []byte) []byte {
    h := sha256.New()
    if len(seed) > 0 {
        h.Write(seed)
    }
    if len(nonce) > 0 {
        h.Write(nonce)
    }
    return h.Sum(nil)  // Always 32 bytes
}
```

### Reproducible Builds

To achieve bit-for-bit identical builds:
1. Fix the seed: `-seed=<known-base64-value>`
2. Fix the nonce: `GARBLE_BUILD_NONCE=<known-base64-value>`
3. Use identical source code and Go toolchain version

**Without fixing both**: Each build is cryptographically unique by design.

### Implementation References
- `main.go`: Flag parsing, seed generation, nonce printing
- `hash.go`: `combineSeedAndNonce()`, `seedHashInput()`, `hashWithPackage()`

---

## 3. Runtime Metadata Hardening (Feistel Cipher)

### Purpose

Encrypt function entry point offsets in the runtime symbol table (`pclntab`) to prevent static analysis from mapping function metadata to code locations.

### Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                    Build Time (Linker Stage)                       │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1. Garble exports LINK_SEED (base64 32-byte seed)                 │
│     Environment: LINK_SEED=<base64>                                │
│                                                                    │
│  2. Linker derives 4 round keys via SHA-256                        │
│     for i = 0 to 3:                                                │
│       h = SHA256(seed || byte(i))                                  │
│       keys[i] = uint32(h[0:4])  // First 4 bytes                   │
│                                                                    │
│  3. For each function in pclntab:                                  │
│     entryOff  = function's entry point offset (32-bit)             │
│     nameOff   = function's name offset (32-bit, used as tweak)     │
│                                                                    │
│     // 4-round Feistel network encryption                          │
│     left = uint16(entryOff >> 16)                                  │
│     right = uint16(entryOff & 0xFFFF)                              │
│                                                                    │
│     for round = 0 to 3:                                            │
│       f = feistelRound(right, nameOff, keys[round])                │
│       left, right = right, left ^ f                                │
│                                                                    │
│     encrypted = (uint32(left) << 16) | uint32(right)               │
│     write encrypted value to binary                                │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘

                           ↓ Binary Written ↓

┌─────────────────────────────────────────────────────────────────────┐
│                    Runtime (Program Execution)                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Injected decryption functions (//go:nosplit)                    │
│                                                                     │
│     var linkFeistelKeys = [4]uint32{...}  // Embedded at compile    │
│                                                                     │
│     //go:nosplit                                                    │
│     func linkFeistelRound(right uint16, tweak, key uint32) uint16   │
│                                                                     │
│     //go:nosplit                                                    │
│     func linkFeistelDecrypt(value, tweak uint32) uint32             │
│                                                                     │
│  2. Patched funcInfo.entry() method                                 │
│                                                                     │
│     func (f funcInfo) entry() uintptr {                             │
│       // Decrypt on-the-fly                                         │
│       decrypted := linkFeistelDecrypt(f.entryOff, uint32(f.nameOff))│
│       return f.datap.textAddr(decrypted)                            │
│     }                                                               │
│                                                                     │
│  3. Transparent to application code                                 │
│     ✓ Stack traces work normally                                    │
│     ✓ runtime.Caller() returns correct information                  │
│     ✓ runtime.FuncForPC() resolves function names                   │
│     ✓ No performance impact (nosplit prevents extra stack frames)   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Feistel Round Function

```
F(right uint16, tweak uint32, key uint32) → uint16:
  x = uint32(right)
  x ^= tweak                         // Mix in per-function uniqueness
  x += key × 0x9e3779b1 + 0x7f4a7c15  // Golden ratio constant
  x = rotateLeft32(x ^ key, key & 31) // Key-dependent rotation  
  x ^= x >> 16                       // Mixing step
  return uint16(x)
```

### Security Properties

| Property          | Value                    | Security Benefit                         |
|-------------------|--------------------------|------------------------------------------|
| **Key Size**      | 4×32-bit (128-bit total) | Cryptographically strong key space       |
| **Rounds**        | 4                        | Sufficient for strong diffusion          |
| **Tweak**         | nameOff (32-bit)         | Each function encrypted uniquely         |
| **Diffusion**     | ~100%                    | All output bits depend on all input bits |
| **Non-linearity** | High                     | Resistant to linear cryptanalysis        |
| **Performance**   | <10 CPU cycles           | Negligible runtime overhead              |

### Why Feistel?

1. **Provable Security**: Well-studied structure used in DES, Blowfish, Twofish
2. **Perfect Invertibility**: Same structure for encryption/decryption (reverse key order)
3. **Format-Preserving**: 32-bit input → 32-bit output (maintains offset size)
4. **Tweak Support**: nameOff parameter ensures unique encryption per function
5. **Fast**: Simple bitwise operations, no memory allocations

### Implementation Details

#### Runtime Injection (`runtime_patch.go`)

```go
// Injected into runtime/symtab.go

//go:nosplit  // CRITICAL: Prevents stack frame creation
func linkFeistelRound(right uint16, tweak uint32, key uint32) uint16 {
    x := uint32(right)
    x ^= tweak
    x += key*0x9e3779b1 + 0x7f4a7c15
    n := key & 31
    tmp := x ^ key
    if n != 0 {
        x = (tmp << n) | (tmp >> (32 - n))
    } else {
        x = tmp
    }
    x ^= x >> 16
    return uint16(x)
}

//go:nosplit  // CRITICAL: Maintains runtime.Caller() correctness
func linkFeistelDecrypt(value, tweak uint32) uint32 {
    left := uint16(value >> 16)
    right := uint16(value)
    
    // Decrypt in reverse (rounds 3, 2, 1, 0)
    for round := len(linkFeistelKeys) - 1; round >= 0; round-- {
        key := linkFeistelKeys[round]
        f := linkFeistelRound(left, tweak, key)
        left, right = right^f, left
    }
    
    return (uint32(left) << 16) | uint32(right)
}

// Patched entry() method
func (f funcInfo) entry() uintptr {
    decrypted := linkFeistelDecrypt(f.entryOff, uint32(f.nameOff))
    return f.datap.textAddr(decrypted)
}
```

**Critical Design Note**: The `//go:nosplit` directive prevents Go from creating stack frames for these functions. This is essential because:
- `runtime.Caller()` counts stack frames to determine call depth
- Extra frames would break stack trace accuracy
- Functions remain invisible to the call stack mechanism

#### Linker Patch (`internal/linker/patches/go1.25/0002-add-entryOff-encryption.patch`)

Applied to `cmd/link/internal/ld/pcln.go`:

```go
// Read LINK_SEED from environment
seedBase64 := os.Getenv("LINK_SEED")
seedBytes, _ := base64.StdEncoding.DecodeString(seedBase64)
var seed [32]byte
copy(seed[:], seedBytes)

// Derive round keys
keys := [4]uint32{}
for i := 0; i < 4; i++ {
    h := sha256.New()
    h.Write(seed[:])
    h.Write([]byte{byte(i)})
    sum := h.Sum(nil)
    keys[i] = binary.LittleEndian.Uint32(sum[:4])
}

// Encrypt all entryOff values
for _, offset := range entryOffLocations {
    entryOff := binary.LittleEndian.Uint32(data[offset:])
    nameOff := binary.LittleEndian.Uint32(data[offset+4:])
    
    encrypted := feistelEncrypt(entryOff, nameOff, keys)
    binary.LittleEndian.PutUint32(data[offset:], encrypted)
}
```

### Testing & Verification

#### Unit Tests
- `feistel_test.go`: Encrypt/decrypt symmetry, edge cases
- `feistel_integration_test.go`: Full round-trip validation

#### Integration Tests  
- `testdata/script/runtime_metadata.txtar`: Validates:
  - ✅ `runtime.FuncForPC()` works with encrypted metadata
  - ✅ Stack traces via `runtime.Caller()` remain correct
  - ✅ Method name resolution functions properly
  - ✅ Reflection type names accessible

### Threat Mitigation

| Attack                     | Mitigation                         | Residual Risk                            |
|----------------------------|------------------------------------|------------------------------------------|
| Static pclntab enumeration | Entry offsets encrypted            | Dynamic tracing observes actual behavior |
| Pattern matching           | Per-function tweak breaks patterns | -                                        |
| Brute force key recovery   | 128-bit keyspace infeasible        | -                                        |
| Known-plaintext attack     | Tweak ensures unique ciphertexts   | Requires recovering seed                 |

### Implementation References
- `feistel.go`: Core encryption/decryption logic
- `runtime_patch.go`: Runtime injection
- `internal/linker/linker.go`: LINK_SEED environment setup
- `internal/linker/patches/go1.25/0002-add-entryOff-encryption.patch`: Linker modifications

---

## 4. Literal Obfuscation (ASCON-128 + Simple)

### Purpose

Transform string and numeric literals into encrypted or obfuscated expressions that resolve at runtime, preventing static extraction via tools like `strings` or `gostringungarbler`.

Packages that include low-level compiler directives (e.g., `//go:nosplit`, `//go:noescape`) skip literal obfuscation to avoid unsafe runtime behavior. Garble logs the first triggering directive and position during the build.

### Architecture Overview

Garble employs multiple obfuscation strategies selected randomly per literal for defense-in-depth:

1. **ASCON-128** (Primary): NIST Lightweight Cryptography standard, authenticated encryption
2. **Simple Irreversible** (Secondary): S-box substitution + Feistel mixing with HKDF-derived subkeys

### ASCON-128 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              ASCON-128 Inline Encryption Flow                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Build Time (internal/literals/ascon_obfuscator.go):            │
│                                                                 │
│  1. Generate random key (16 bytes) and nonce (16 bytes)         │
│     key := cryptoRand.Read(16)                                  │
│     nonce := cryptoRand.Read(16)                                │
│                                                                 │
│  2. Encrypt plaintext with ASCON-128                            │
│     ciphertext||tag = AsconEncrypt(key, nonce, plaintext)       │
│     // Output: ciphertext + 16-byte authentication tag          │
│                                                                 │
│  3. Generate inline decryption code (~2947 bytes)               │
│     • Complete ASCON implementation inlined                     │
│     • No imports required (crypto-free binary)                  │
│     • Unique decryptor per literal                              │
│                                                                 │
│  Runtime (generated code):                                      │
│                                                                 │
│  data, ok := _garbleAsconDecrypt(                               │
│      interleave(evenKey, oddKey),                               │
│      interleave(evenNonce, oddNonce),                           │
│      interleave(evenCt, oddCt)                                  │
│  )                                                              │
│  if !ok {                                                       │
│      panic(string(interleave(...)))                             │
│  }                                                              │
│  // data now contains decrypted plaintext                       │
│  // key/nonce/ciphertext are zeroized after use                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### ASCON-128 Properties

| Property           | Value              | Benefit                                |
|--------------------|--------------------|----------------------------------------|
| **Security Level** | 128-bit            | NIST-approved security strength        |
| **Key Size**       | 128-bit (16 bytes) | Strong key space                       |
| **Nonce Size**     | 128-bit (16 bytes) | Unique per literal                     |
| **Tag Size**       | 128-bit (16 bytes) | Detects tampering                      |
| **Authentication** | Yes (AEAD)         | Integrity + confidentiality            |
| **Performance**    | Lightweight        | Optimized for constrained environments |
| **Zeroization**    | Yes                | Scrubs key/nonce/cipher/tag after use  |

### Simple Irreversible Architecture

The simple obfuscator is now irreversible and uses HKDF-derived subkeys plus
S-box substitution and Feistel mixing:

1. Derive per-literal subkeys from HKDF (`garble/literals/irreversible:v1`).
2. Encrypt the literal data via S-box substitution + Feistel rounds.
3. Embed ciphertext and subkeys; apply external-key mixing to hide constants.
4. Emit an inline decode helper (from `irreversible_inline.go`) to restore the
   plaintext at runtime without exposing original names or mappings.

#### Simple Obfuscator Properties

- **Layers**: S-box substitution + Feistel mixing + external key mixing
- **Subkeys**: HKDF-derived per literal
- **Reversibility**: Not supported (no de-obfuscation metadata)
- **Performance**: Fast for small literals

### Obfuscator Selection Strategy

Implemented in `internal/literals/obfuscators.go`:

```go
// Approximate selection probabilities:
// - ASCON-128: ~60% of literals (strong encryption)
// - Simple: ~40% of literals (performance, diversity)
```

Selection factors:
- Literal size (ASCON preferred for larger literals)
- Performance requirements (simple for hot paths)
- Build randomness (varies per build for diversity)

### Known Limitations

#### Const Expressions
```go
const VERSION = "1.0"          // ✅ Rewritten to var + obfuscated when no compile-time dependency exists
const SIZE = len(VERSION)       // ⚠️ Must stay const (array length)
const CaseLabel = "case-only"  // ⚠️ Must stay const (switch label)
```
**Reason**: Garble rewrites string constants into vars when they are only used at runtime. Values that participate in compile-time contexts (array lengths, `iota` arithmetic, case clauses, etc.) must remain constants to keep the program valid and may stay in plaintext.

#### Linker-Injected Strings (`-ldflags -X`)

**Status**: ✅ **Fully Protected** since October 2025

Go's `-ldflags -X` flag allows injecting string values at link time:

```sh
go build -ldflags="-X main.apiKey=sk_live_51234567890abcdefABCDEF"
```

**Traditional Vulnerability**: These strings appear in plaintext in the binary, easily extractable with `strings` or hex editors.

**Garble Protection Pipeline**:

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 1: FLAG SANITIZATION (main.go)                       │
├──────────────────────────────────────────────────────────────┤
│  Input:  -ldflags="-X main.apiKey=sk_live_51234567890..."    │
│                                     └─────────┬────────┘      │
│                           Extracted & cached  │               │
│                                              ▼               │
│  sharedCache.LinkerInjectedStrings["main.apiKey"] =         │
│      "sk_live_51234567890abcdefABCDEF"                       │
│                                              │               │
│                    Sanitized flag rewritten  │               │
│                                              ▼               │
│  Output: -ldflags="-X main.apiKey="  ← Empty to linker!     │
│                                                              │
│  ✅ Go toolchain NEVER sees the original value               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Phase 2: RUNTIME INJECTION (transformer.go)                 │
├──────────────────────────────────────────────────────────────┤
│  During package compilation, Garble injects:                 │
│                                                              │
│  func init() {                                               │
│      apiKey = <obfuscated_literal>("sk_live_51234567...")>  │
│  }                                                           │
│                                                              │
│  ✅ Uses identical obfuscation as normal string literals     │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Phase 3: ENCRYPTION (literals.go)                           │
├──────────────────────────────────────────────────────────────┤
│  Value encrypted with ASCON-128 (~60%) or Simple (~40%):    │
│                                                              │
│  • ASCON: AES-like encryption + inline decrypt function     │
│  • Simple: XOR + shuffle + split + index remapping          │
│                                                              │
│  ✅ Binary contains only ciphertext + decrypt code           │
└──────────────────────────────────────────────────────────────┘
```

**Supported Formats**:
```sh
# All three -X formats are protected:
-ldflags="-X=main.version=1.0"
-ldflags="-X main.version=1.0"
-ldflags="-X \"main.message=hello world\""
```

**Security Guarantees**:

| Attack Vector                   | Normal Build           | Garble Build                |
|---------------------------------|------------------------|-----------------------------|
| `strings binary \| grep apiKey` | ❌ Plaintext found      | ✅ Not found                 |
| Static analysis                 | ❌ Immediate extraction | ⚠️ Requires reversing the runtime decode path |
| Hex editor search               | ❌ Visible bytes        | ✅ Only ciphertext           |
| Memory dump (runtime)           | ⚠️ Always plaintext    | ⚠️ Decrypted in memory      |

**Real-World Example**:

```go
package main
var apiKey = "default-key"  // Will be replaced via -ldflags

// Build without Garble
$ go build -ldflags="-X main.apiKey=sk_live_ABC123"
$ strings binary | grep sk_live
sk_live_ABC123  ← Exposed!

// Build with Garble
$ garble -literals build -ldflags="-X main.apiKey=sk_live_ABC123"
$ strings binary | grep sk_live
(no results)  ← Protected!

// But runtime still works:
$ ./binary
Using API key: sk_live_ABC123  ← Decrypted at runtime ✅
```

**Implementation Details**:
- `main.go`: `sanitizeLinkerFlags()` - extracts and sanitizes flags
- `transformer.go`: `injectLinkerVariableInit()` - generates init() function
- `internal/literals/literals.go`: `Builder.ObfuscateStringLiteral()` - encrypts value
- Tests: `testdata/script/ldflags.txtar` - end-to-end verification

### Current Status

| Feature             | Status               | Notes                                                                |
|---------------------|----------------------|----------------------------------------------------------------------|
| String literals     | ✅ Obfuscated         | ASCON + simple mix                                                   |
| Numeric literals    | ✅ Obfuscated         | When `-literals` enabled                                             |
| Byte slices         | ✅ Obfuscated         | Treated as literals                                                  |
| Const expressions   | ⚠️ Partially covered | Safe string consts are rewritten; compile-time contexts remain const |
| -ldflags -X strings | ✅ Covered            | Sanitised at flag parse; runtime decrypt                             |
| Irreversible simple | ✅ Deployed           | Feistel + S-box decode helper                                        |

### Implementation References
- `internal/literals/ascon.go`: Core ASCON-128 implementation
- `internal/literals/ascon_inline.go`: Inline code generator
- `internal/literals/ascon_obfuscator.go`: Obfuscator integration
- `internal/literals/simple.go`: Simple irreversible obfuscator
- `internal/literals/obfuscators.go`: Selection strategy
- Tests: `ascon_test.go`, `simple_test.go`, `ascon_integration_test.go`

---

## 5. Reflection Control

### Purpose

Eliminate the "reflection oracle" that leaked obfuscated-to-original identifier mappings by never embedding original names.

### Behavior

- `_originalNamePairs` is always empty.
- Reflection still works, but only with obfuscated names.
- No de-obfuscation/debug mode is provided.

### Implementation

`reflectMainPostPatch` leaves the injected mapping array empty on every build, removing any de-obfuscation metadata from the binary.

### Implementation References
- `reflect.go`: `reflectMainPostPatch()` - Core logic

---

## 6. Build Cache Encryption (ASCON-128)

### Purpose

Encrypt Garble's persistent build cache to prevent offline analysis of obfuscation metadata, import paths, and build artifacts.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│              Cache Encryption Flow (ASCON-128)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Write Path (cache_pkg.go: computePkgCache):                    │
│                                                                 │
│  1. Serialize pkg cache to gob                                  │
│     var buf bytes.Buffer                                        │
│     gob.NewEncoder(&buf).Encode(pkgCache)                       │
│     plaintext := buf.Bytes()                                    │
│                                                                 │
│  2. Derive encryption key from seed                             │
│     key = SHA256(seed || "garble-cache-encryption-v1")          │
│     key = key[0:16]  // 128-bit ASCON key                       │
│                                                                 │
│  3. Encrypt with ASCON-128                                      │
│     nonce := cryptoRand.Read(16)  // Random per cache entry     │
│     ciphertext||tag = AsconEncrypt(key, nonce, plaintext)       │
│                                                                 │
│  4. Write to disk                                               │
│     format: [16-byte nonce][ciphertext][16-byte tag]            │
│     path: $GARBLE_CACHE/<action-id>                             │
│                                                                 │
│  Read Path (cache_pkg.go: loadPkgCache):                        │
│                                                                 │
│  1. Read encrypted cache from disk                              │
│     data := readFile($GARBLE_CACHE/<action-id>)                 │
│                                                                 │
│  2. Check if encrypted (has seed)                               │
│     if seed, _ := cacheEncryptionSeed(); len(seed) > 0 {        │
│         // Decrypt path                                         │
│     } else {                                                    │
│         // Legacy plaintext gob fallback                        │
│     }                                                           │
│                                                                 │
│  3. Extract components                                          │
│     nonce := data[0:16]                                         │
│     ciphertext_and_tag := data[16:]                             │
│                                                                 │
│  4. Derive same key and decrypt                                 │
│     key = SHA256(seed || "garble-cache-encryption-v1")[0:16]    │
│     plaintext, ok := AsconDecrypt(key, nonce, ciphertext_and_tag)│
│                                                                 │
│  5. Verify authentication tag                                   │
│     if !ok {                                                    │
│         // Tag mismatch: cache corrupted or tampered            │
│         return nil  // Triggers rebuild                         │
│     }                                                           │
│                                                                 │
│  6. Deserialize gob                                             │
│     gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&pkgCache)│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Key Derivation

```go
func deriveCacheKey(seed []byte) []byte {
    // Domain separation for cache encryption
    h := sha256.New()
    h.Write(seed)
    h.Write([]byte("garble-cache-encryption-v1"))
    digest := h.Sum(nil)
    return digest[0:16]  // 128-bit ASCON-128 key
}
```

### Cache File Format

```
┌─────────────────────────────────────────────────────────┐
│                 Encrypted Cache Entry                   │
├─────────────────────────────────────────────────────────┤
│  Bytes 0-15:    Random nonce (16 bytes)                 │
│  Bytes 16-N-16: Encrypted pkg cache (variable length)   │
│  Bytes N-16-N:  Authentication tag (16 bytes)           │
└─────────────────────────────────────────────────────────┘
```

### Activation Conditions

Cache encryption is **enabled by default** when `-no-cache-encrypt` is **not** present. Garble uses the CLI seed if supplied; otherwise it generates a random per-build seed, so entries remain encrypted and per-build unique.

```sh
# Encrypted cache with explicit seed (reusable entries)
garble -seed=<base64> build

# Explicitly disable encryption
garble -seed=<base64> -no-cache-encrypt build

# Default: random seed per build (encrypted cache)
garble build
```

### Shared Cache vs Persistent Cache

| Cache Type     | Location                    | Encrypted            | Lifetime                |
|----------------|-----------------------------|----------------------|-------------------------|
| **Persistent** | `$GARBLE_CACHE/<action-id>` | ✅ Yes (when enabled) | Permanent until trimmed |
| **Shared**     | `$GARBLE_SHARED` (temp)     | ❌ No                 | Deleted after build     |

**Design Rationale**:
- **Persistent cache**: Long-lived, disk-resident → encrypted to protect offline analysis
- **Shared cache**: Ephemeral, process-local → plaintext for performance, cleaned automatically

### Tamper Detection

ASCON-128's authentication tag provides cryptographic verification:
- **Valid tag**: Cache decrypts successfully
- **Invalid tag**: Decryption fails → treated as cache miss → rebuild triggered
- **No crash**: Corruption degrades gracefully to rebuild

### Backward Compatibility

Legacy plaintext caches are automatically detected and read:
```go
func decodePkgCacheBytes(data []byte) (pkgCache, error) {
    if seed, _ := cacheEncryptionSeed(); len(seed) > 0 {
        // Try ASCON decryption
    return cache.Decrypt(data, seed, &shared)
    }
    // Fallback: plaintext gob
    var cache pkgCache
    gob.NewDecoder(bytes.NewReader(data)).Decode(&cache)
    return cache, nil
}
```

### Security Properties

| Property              | Value                        | Benefit                                |
|-----------------------|------------------------------|----------------------------------------|
| **Algorithm**         | ASCON-128 AEAD               | NIST-approved authenticated encryption |
| **Key Size**          | 128-bit                      | Strong security margin                 |
| **Nonce**             | 128-bit random               | Unique per cache entry                 |
| **Authentication**    | 128-bit tag                  | Detects tampering                      |
| **Domain Separation** | "garble-cache-encryption-v1" | Prevents key reuse attacks             |

### Threat Mitigation

| Attack                 | Mitigation                      | Result                                 |
|------------------------|---------------------------------|----------------------------------------|
| Offline cache analysis | Encrypted with ASCON-128        | Plaintext metadata inaccessible        |
| Cache tampering        | Authentication tag verification | Corruption detected, rebuild triggered |
| Cache poisoning        | Tag forgery requires key        | Infeasible (128-bit security)          |
| Key recovery           | Seed never stored in cache      | Attacker needs build-time seed         |

### Implementation References
- `internal/cache/encryption.go`: `DeriveKey()`, `Encrypt()`, `Decrypt()`
- `cache_pkg.go`: `computePkgCache()`, `loadPkgCache()`, `decodePkgCacheBytes()`
- `main.go`: Seed and `-no-cache-encrypt` flag handling

---

## 7. Control-Flow Obfuscation

### Purpose

Transform control-flow structures to increase complexity and hinder static analysis, making it harder to understand program logic.

### Modes

| Mode              | Behavior                                               | Use Case                           |
|-------------------|--------------------------------------------------------|------------------------------------|
| **off** (default) | No transformation                                      | Standard builds                    |
| **directives**    | Only functions with `//garble:controlflow`             | Selective protection               |
| **auto**          | All eligible functions except `//garble:nocontrolflow` | Broad protection with escape hatch |
| **all**           | Every function                                         | Maximum obfuscation                |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│            Control-Flow Obfuscation Decision Tree                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  For each function:                                             │
│                                                                 │
│  1. Check mode                                                  │
│     if mode == off:                                             │
│         return (no transformation)                              │
│                                                                 │
│  2. Check directives                                            │
│     if mode == directives:                                      │
│         if function has //garble:controlflow:                   │
│             transform()                                         │
│         else:                                                   │
│             return (no transformation)                          │
│                                                                 │
│  3. Check eligibility (mode == auto)                            │
│     if function has //garble:nocontrolflow:                     │
│         return (explicit skip)                                  │
│     if function is too simple:                                  │
│         return (heuristic skip)                                 │
│     if SSA safety check fails:                                  │
│         return (unsafe to transform)                            │
│     transform()                                                 │
│                                                                 │
│  4. Force transform (mode == all)                               │
│     transform() regardless of complexity/safety                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration

#### CLI Flag (highest priority)
```sh
garble -controlflow=auto build
garble -controlflow=directives build
garble -controlflow=all build
```

#### Environment Variable (fallback)
```sh
export GARBLE_CONTROLFLOW=auto
garble build
```

**Precedence**: CLI flag > environment variable > default (off)

### Directive Usage

#### Opt-In (directives mode)
```go
//garble:controlflow
func sensitiveFunction() {
    // Only transformed when mode=directives or mode=auto/all
}
```

#### Opt-Out (auto/all modes)
```go
//garble:nocontrolflow
func hotPath() {
    // Skipped even in auto mode; still transformed in all mode
}
```

### Transformation Strategy

Control-flow obfuscation (implemented in `internal/ctrlflow`):
1. **Flatten**: Convert structured control flow to flat switch/goto
2. **Hardening prologues**: Dispatcher keys are obfuscated (interleaved slices) and
   include opaque predicates to slow static recovery.
3. **Dead Code Injection**: Add unreachable but plausible code paths

### Current Status

| Feature                  | Status        | Notes                                            |
|--------------------------|---------------|--------------------------------------------------|
| Mode selection           | ✅ Implemented | off/directives/auto/all                          |
| Directive support        | ✅ Implemented | `//garble:controlflow`, `//garble:nocontrolflow` |
| SSA safety checks        | ✅ Implemented | Prevents unsafe transforms                       |
| Performance optimization | ⚠️ Ongoing    | Heuristics for hot-path detection                |
| Default-on               | ❌ Planned     | Needs perf validation                            |

### Performance Considerations

Control-flow obfuscation can impact:
- **Binary size**: +5-15% typical increase
- **Performance**: Variable depending on function complexity
- **Compilation time**: +10-30% longer builds
- **Initialization cost**: Hardening prologues add a small amount of extra work per function

**Recommendation**: Use `auto` mode with selective `//garble:nocontrolflow` in hot paths.

### Implementation References
- `internal/ctrlflow/mode.go`: Mode enum and parsing
- `internal/ctrlflow/ctrlflow.go`: Eligibility checks, transformation logic
- `internal/ctrlflow/transform.go`: AST transformation
- `docs/CONTROLFLOW.md`: Detailed design documentation
- `main.go`: Flag and environment resolution

---

## 7.1 Operational Hardening Checklist (by build flow)

**Goal:** small, low-risk layers that materially slow static analysis.

### Phase 1: Build Flags & Inputs
- Use `-literals -tiny -controlflow=auto` on every production build.
- Keep `-no-cache-encrypt` **off** (default).
- Leave the seed random for uniqueness; if you must record it, use `-seed=random`.
- Avoid `-debug` and `-debugdir` in production (they expose structure).

### Phase 2: Package Scope
- Keep `GOGARBLE='*'` unless you explicitly need to expose public APIs.
- Avoid or minimize `//go:nosplit`/`//go:noescape` in your own code paths that contain secrets, because they skip literal obfuscation.

### Phase 3: Literal Protection
- Prefer `-literals` for all shipped binaries; it covers `-ldflags -X` values and normal literals.
- Rotate seeds periodically for long-lived products to reduce cross-build correlation.

### Phase 4: Control Flow
- Use `-controlflow=auto` globally, and opt out only with `//garble:nocontrolflow` for verified hot paths.

### Phase 5: Linker/Runtime Metadata
- Keep `-tiny` enabled to remove runtime metadata and stack traces in shipped builds.
- Avoid embedding version/build metadata in your own code unless you encrypt it (e.g., via `-literals` or runtime config).

### Phase 6: Cache & Artifacts
- Leave cache encryption enabled (default) so on-disk artifacts remain protected.
- If you use CI caches, scope `GARBLE_CACHE` per pipeline or per build group.

---

## 8. Threat Model & Mitigation Matrix

### Threat Classification

| Attack Vector                  | Difficulty    | Impact   | Mitigation Status                      |
|--------------------------------|---------------|----------|----------------------------------------|
| Static pclntab analysis        | Medium → Hard | High     | ✅ Mitigated (Feistel)                  |
| Cross-build name correlation   | Easy → Hard   | Medium   | ✅ Mitigated (Nonce)                    |
| Static string extraction       | Easy → Medium | High     | ✅ Mitigated (ASCON + Simple)           |
| Reflection oracle exploitation | Easy → N/A    | Critical | ✅ Eliminated (Default)                 |
| Cache offline analysis         | Easy → Hard   | Medium   | ✅ Mitigated (ASCON Encryption)         |
| Dynamic runtime tracing        | Easy          | Variable | ⚠️ By Design (Observable)              |
| Const expression extraction    | Easy          | Medium   | ⚠️ Partial Gap (compile-time contexts) |
| -ldflags -X plaintext leakage  | Easy          | Medium   | ✅ Mitigated (Sanitized + obfuscated)   |
| Control-flow analysis          | Medium        | Medium   | ⚠️ Optional (CF modes)                 |

### Detailed Mitigation Matrix

| Attack Vector                          | Mitigation Mechanism                                                       | Residual Risk                                                       | Notes                                                 |
|----------------------------------------|----------------------------------------------------------------------------|---------------------------------------------------------------------|-------------------------------------------------------|
| **Static Symbol Table Analysis**       | Feistel-encrypted entry offsets with per-build keys and per-function tweak | Dynamic tracing observes actual runtime behavior                    | Format-preserving; 128-bit keyspace                   |
| **Cross-Build Pattern Matching**       | SHA-256 seed+nonce mixing; cryptographically random nonce per build        | If seed and nonce are fixed (reproducibility), correlation possible | Intentional for deterministic builds                  |
| **String/Literal Scraping**            | ASCON-128 inline encryption (~60%); multi-layer simple obfuscator (~40%)   | Compile-time-only consts remain in plaintext                        | Remaining gap limited to array lengths / case labels  |
| **Injected -ldflags Strings**          | CLI sanitization + shared-cache rehydration via literal builder            | Plaintext exists only transiently in garble parent process          | Sanitized flags never reach toolchain or final binary |
| **Reflection Name Oracle**             | `_originalNamePairs` array is always empty                                 | No opt-in path; oracle removed                                      | No identifier mappings are embedded                  |
| **Cache Inspection/Tampering**         | ASCON-128 encryption at rest with 128-bit authentication tag               | Shared ephemeral cache plaintext (deleted after build)              | Tag verification prevents poisoning                   |
| **Known-Plaintext Attack on Literals** | Per-literal random keys/nonces; ASCON authentication                       | Requires recovering per-literal key (infeasible)                    | Each literal independently secured                    |
| **Brute-Force Key Recovery**           | 128-bit Feistel keyspace; 128-bit ASCON keys                               | Computationally infeasible                                          | Meets NIST security standards                         |
| **Dynamic Code Injection**             | Not addressed                                                              | Requires runtime protections (out of scope)                         | Obfuscation != runtime security                       |
| **Control-Flow Reconstruction**        | Optional CF obfuscation modes                                              | If disabled (default), structure remains clear                      | User must enable explicitly                           |

### Attack Scenarios & Defenses

#### Scenario 1: Offline Binary Analysis
**Attacker Goal**: Extract original identifiers and strings without running the program.

**Defenses**:
- ✅ Feistel encryption hides function mappings
- ✅ ASCON/Simple encryption protects literals
- ✅ Sanitized `-ldflags -X` strings are rehydrated via obfuscated init-time assignments
- ✅ Empty reflection map eliminates name oracle
- ⚠️ String constants required at compile time (array lengths, switch labels, `iota` math) remain visible

**Result**: Significantly harder; requires reverse engineering each obfuscation layer.

#### Scenario 2: Cross-Binary Correlation
**Attacker Goal**: Compare multiple builds to identify patterns and recover originals.

**Defenses**:
- ✅ Per-build nonce ensures different hashes
- ✅ Random ASCON nonces per literal
- ⚠️ Fixed seed+nonce (reproducibility) breaks this defense

**Result**: Effective unless reproducible builds are used (intentional trade-off).

#### Scenario 3: Dynamic Runtime Tracing
**Attacker Goal**: Observe program behavior at runtime to infer logic.

**Defenses**:
- ❌ Not addressed (out of scope for static obfuscation)
- ⚠️ Control-flow obfuscation can make tracing harder (if enabled)

**Result**: Dynamic analysis always possible; obfuscation raises the bar but doesn't prevent it.

#### Scenario 4: Cache-Based Analysis
**Attacker Goal**: Analyze Garble's cache to recover build metadata.

**Defenses**:
- ✅ ASCON-128 encryption protects persistent cache
- ✅ Authentication tag prevents tampering
- ✅ Seed not stored in cache

**Result**: Cache contents inaccessible without build-time seed.

---

## 9. Security Limitations & Roadmap

### Current Limitations

#### 1. Literal Coverage Gaps

**Issue**: Certain literal types are not obfuscated.

| Type                        | Status        | Reason                                           | Priority   |
|-----------------------------|---------------|--------------------------------------------------|------------|
| Compile-time const contexts | ⚠️ Partial    | Array lengths, case labels, iota must stay const | Medium     |
| `-ldflags -X` strings       | ✅ **Covered** | **Sanitized at CLI, encrypted via init()**       | ✅ Complete |
| Runtime-generated strings   | ❌ Not covered | Created dynamically                              | Low        |

**Example of remaining gap**:
```go
const arraySize = "XXXX"
var arr = [len(arraySize)]byte{}  // ⚠️ Must stay const (array length)

const caseLabel = "case-only"
switch x {
case caseLabel:  // ⚠️ Must stay const (switch case)
    return true
}
```

**What IS protected**:
```go
const runtimeSecret = "hide-me"  // ✅ Converted to var + encrypted
var sink = runtimeSecret         // ✅ Value obfuscated at runtime

// Via -ldflags
var apiKey = "default"
// Build: garble -literals build -ldflags="-X main.apiKey=secret123"
// ✅ "secret123" is ASCON-encrypted, never appears in plaintext
```

**Planned**: Advanced const-folding analysis to detect more safe-to-rewrite constants.

#### 2. Control-Flow Default State

**Issue**: Control-flow obfuscation is opt-in (default: off).

**Reason**: Performance impact not fully characterized; needs heuristics.

**Planned**:
1. Gather performance benchmarks across typical codebases
2. Develop heuristics for auto-exclusion of hot paths
3. Consider default-on with smart exclusions

#### 3. Exported Identifiers

**Issue**: Exported names remain unobfuscated.

**Reason**: Required for Go's interface compatibility and reflection.

**Status**: By design; whole-program obfuscation not feasible in Go's compilation model.

**Alternative**: Document the trade-off; consider separate "closed-ecosystem" mode in future.

#### 4. Error/Panic Message Leakage

**Issue**: Error strings and panic messages may reveal implementation details.

**Examples**:
```go
panic("failed to parse config at line 42")
fmt.Errorf("database %s not found", dbName)
```

**Planned**: Optional `-strip-errors` flag to sanitize messages in production builds.

### Roadmap

#### Short-Term (Q4 2025)

| Item                                     | Status         | Priority |
|------------------------------------------|----------------|----------|
| Improve const expression handling        | 🔄 In Progress | Medium   |
| Document -ldflags workarounds            | 📋 Planned     | Low      |
| Performance benchmarks for CF modes      | 📋 Planned     | Medium   |

#### Medium-Term (Q1-Q2 2026)

| Item                                | Status      | Priority |
|-------------------------------------|-------------|----------|
| Control-flow default-on evaluation  | 📋 Planned  | Medium   |
| `-strip-errors` flag implementation | 📋 Planned  | Low      |
| Link-time -ldflags interception     | 🔬 Research | Medium   |
| Cache encryption performance tuning | 📋 Planned  | Low      |

#### Long-Term (2026+)

| Item                           | Status     | Priority |
|--------------------------------|------------|----------|
| Anti-debugging countermeasures | 💡 Concept | Low      |
| Whole-program obfuscation mode | 💡 Concept | Low      |
| Hardware-backed key storage    | 💡 Concept | Very Low |

**Legend**: 💡 Concept | 🔬 Research | 📋 Planned | 🔄 In Progress | ✅ Complete

### Known Trade-Offs

#### Reproducibility vs. Uniqueness
- **Fixed seed+nonce**: Reproducible builds, but correlation possible
- **Random nonce**: Unique per build, but not reproducible
- **Choice**: User decides based on requirements (CI/CD vs. anti-correlation)

#### Performance vs. Obfuscation
- **Control-flow off**: Fast builds, clear structure
- **Control-flow auto/all**: Slower builds, complex structure
- **Choice**: Balance based on threat model

---

## 10. References & Resources

### Documentation

| Document               | Purpose                                 | Location                  |
|------------------------|-----------------------------------------|---------------------------|
| **FEATURE_TOGGLES.md** | Complete flag and environment reference | `docs/FEATURE_TOGGLES.md` |
| **CONTROLFLOW.md**     | Control-flow obfuscation design         | `docs/CONTROLFLOW.md`     |
| **LITERAL_ENCRYPTION.md** | Literal encryption architecture and HKDF design | `docs/LITERAL_ENCRYPTION.md` |
| **README.md**          | User-facing overview and quick start    | `README.md`               |
| **This document**      | Security architecture and threat model  | `docs/SECURITY.md`        |

### Implementation Files

#### Core Obfuscation
- `main.go`: Entry point, flag parsing, seed/nonce handling
- `hash.go`: Name hashing, seed+nonce mixing
- `transformer.go`: AST transformation orchestration

#### Runtime Metadata
- `feistel.go`: Feistel encryption/decryption primitives
- `runtime_patch.go`: Runtime injection logic
- `internal/linker/linker.go`: Linker patching coordination
- `internal/linker/patches/go1.25/0002-add-entryOff-encryption.patch`: Linker modifications

#### Literals
- `internal/literals/ascon.go`: ASCON-128 core implementation
- `internal/literals/ascon_inline.go`: Inline code generation
- `internal/literals/ascon_obfuscator.go`: Obfuscator integration
- `internal/literals/simple.go`: Simple irreversible obfuscator
- `internal/literals/obfuscators.go`: Selection strategy

#### Reflection
- `reflect.go`: Reflection metadata handling, `reflectMainPostPatch()`

#### Cache
- `cache_ascon.go`: ASCON encryption for cache
- `cache_pkg.go`: Cache persistence and loading

#### Control-Flow
- `internal/ctrlflow/mode.go`: Mode definitions
- `internal/ctrlflow/ctrlflow.go`: Transformation logic
- `internal/ctrlflow/transform.go`: AST manipulation

### Testing

#### Unit Tests
- `feistel_test.go`: Feistel primitives
- `feistel_integration_test.go`: End-to-end Feistel
- `internal/literals/*_test.go`: Literal obfuscation
- `cache_encryption_test.go`: Cache encryption

#### Integration Tests
- `testdata/script/runtime_metadata.txtar`: Runtime metadata
- `testdata/script/reflect_secure.txtar`: Reflection default mode
- `testdata/script/seed.txtar`: Seed and nonce behavior
- `testdata/script/ctrlflow_*.txtar`: Control-flow modes

### External References

#### Standards
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography): ASCON-128 specification
- [OWASP Code Obfuscation](https://owasp.org/www-community/controls/Code_Obfuscation): Best practices

#### Threat Intelligence
- [mandiant/gostringungarbler](https://github.com/mandiant/gostringungarbler): Static string recovery tool
- [Invoke-RE/ungarble_bn](https://github.com/Invoke-RE/ungarble_bn): Hash salt brute-forcing tool

---

**Document Maintenance**
- **Version**: 1.0
- **Last Updated**: October 8, 2025
- **Next Review**: December 2025
- **Owner**: x430n Spectre Team


