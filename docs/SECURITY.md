# Garble hardened Security Architecture

**Last Updated**: January 2025
**Status**: ✅ Production Ready

This document provides the comprehensive technical security architecture of Garble's obfuscation mechanisms. It details each security component with its implementation, threat model, and operational characteristics.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Seed & Nonce Architecture](#2-seed--nonce-architecture)
3. [Literal Obfuscation (Stealth Cipher Architecture)](#3-literal-obfuscation-stealth-cipher-architecture)
4. [Reflection Control](#4-reflection-control)
5. [Build Cache Encryption (ASCON-128)](#5-build-cache-encryption-ascon-128)
6. [Control-Flow Obfuscation](#6-control-flow-obfuscation)
7. [Operational Hardening Checklist](#7-operational-hardening-checklist)
8. [Threat Model & Mitigation Matrix](#8-threat-model--mitigation-matrix)
9. [Security Limitations & Roadmap](#9-security-limitations--roadmap)
10. [References & Resources](#10-references--resources)

---

## 1. Executive Summary

### Security Posture Snapshot

| Component          | Status      | Implementation                                          |
|--------------------|-------------|---------------------------------------------------------|
| Literal Protection | ✅ Deployed  | Per-build random SPN cipher + lightweight transforms    |
| Name Hashing       | ✅ Deployed  | SHA-256 with per-build nonce mixing                     |
| Reflection Oracle  | ✅ Mitigated | Always empty; original identifiers never embedded       |
| Cache Encryption   | ✅ Deployed  | ASCON-128 at rest with authentication                   |
| Control-Flow       | ⚠️ Optional | Multiple modes available; default off                   |

### Key Security Properties

- **Per-Build Uniqueness**: Every build uses a cryptographically random nonce mixed with the seed, ensuring symbol names and keys differ even with identical source code (unless explicitly reproduced).
- **Stealth Literal Protection**: Strings and constants are encrypted using a per-build random substitution-permutation network. No fixed cryptographic constants (AES S-boxes, ASCON IVs, etc.) appear in the output binary, defeating findcrypt and YARA-based signature scanners.
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
│   Name Hashing    Literal Keys    Cache Keys               │
│   (per-package)   (per-literal)   (ASCON-128)              │
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

## 3. Literal Obfuscation (Stealth Cipher Architecture)

### Purpose

Transform string and numeric literals into encrypted or obfuscated expressions that resolve at runtime, preventing static extraction via tools like `strings` or `gostringungarbler`.

Packages that include low-level compiler directives (e.g., `//go:nosplit`, `//go:noescape`) skip literal obfuscation to avoid unsafe runtime behavior. Garble logs the first triggering directive and position during the build.

### Design Philosophy — Stealth First

The literal obfuscation architecture is built around a core principle: **no fixed cryptographic constants in the output binary**. Traditional AES/ASCON-based approaches embed recognisable S-boxes and IVs that signature scanners (findcrypt, YARA rules) immediately flag. Garble instead:

1. Generates a **per-build random 256-byte S-box** via Fisher-Yates shuffle.
2. Uses it in a multi-round **substitution-permutation network (SPN)** with CBC-like diffusion.
3. Embeds the S-box, inverse S-box, and round keys as literal arrays in generated code — fully unique per build.

### Architecture Overview

Garble employs multiple obfuscation strategies selected by weighted random per literal for defense-in-depth:

1. **Custom Cipher** (primary, ~60% weight): Per-build random SPN with Fisher-Yates S-box
2. **Swap** (~10%): Random position pair swaps
3. **Split** (~10%): Random chunk splitting and independent scrambling
4. **Shuffle** (~10%): Full byte permutation
5. **Seed** (~10%): PRNG-based XOR masks

### Custom Cipher Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Custom Cipher (Per-Build Random SPN)                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Build Time (internal/literals/custom_cipher_obfuscator.go):    │
│                                                                 │
│  1. Generate random 256-byte S-box via Fisher-Yates shuffle     │
│     sbox := fisherYatesSbox(rand)   // unique permutation       │
│     invSbox := invertSbox(sbox)     // for decryption           │
│                                                                 │
│  2. Generate random round keys (4-6 rounds)                     │
│     rounds := 4 + rand.Intn(3)                                 │
│     keyBytes := randomBytes(rounds)                             │
│                                                                 │
│  3. Encrypt plaintext with SPN                                  │
│     for each round:                                             │
│       byte[0] ^= keyByte[round]                                │
│       for i > 0: byte[i] ^= keyByte[round] ^ byte[i-1]  (CBC) │
│       for all: byte[i] = sbox[byte[i]]  (substitution)         │
│                                                                 │
│  4. Emit inline decryption code (AST)                           │
│     • Embeds invSbox as [256]byte literal                       │
│     • Embeds keyBytes as []byte literal                         │
│     • Generates inverse SPN loop                                │
│     • No imports required (pure Go arithmetic)                  │
│                                                                 │
│  Runtime (generated code):                                      │
│                                                                 │
│  func() string {                                                │
│      data := []byte{...ciphertext...}                           │
│      invSbox := [256]byte{...}                                  │
│      keyBytes := []byte{...}                                    │
│      // Decrypt: reverse rounds                                 │
│      for r := len(keyBytes)-1; r >= 0; r-- {                   │
│          // Inverse substitution                                │
│          // Inverse CBC diffusion                               │
│          // XOR with round key                                  │
│      }                                                          │
│      return string(data)                                        │
│  }()                                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Custom Cipher Properties

| Property               | Value                                | Benefit                                       |
|------------------------|--------------------------------------|-----------------------------------------------|
| **S-box**              | Random 256-byte permutation          | No fixed constants for signature matching     |
| **Rounds**             | 4-6 (random per invocation)          | Variable structure defeats pattern analysis   |
| **Diffusion**          | CBC-like byte chaining               | Single byte change propagates to all output   |
| **Key material**       | Random per-build round keys          | Unique cipher instance per build              |
| **Code signature**     | None detectable                      | Passes findcrypt, YARA, entropy heuristics    |
| **Performance**        | O(n × rounds) per literal            | Lightweight inline decrypt                    |
| **Zeroization**        | Yes                                  | Key material scrubbed post-decrypt            |

### Obfuscator Selection Strategy

Implemented in `internal/literals/strategy_registry.go` with weighted selection:

```
Strategy selection (approximate):
- Custom Cipher: ~60%  (weight 6)
- Swap:          ~10%  (weight 1)
- Split:         ~10%  (weight 1)
- Shuffle:       ~10%  (weight 1)
- Seed:          ~10%  (weight 1)

Literals > 2KB use only linear-time strategies (split, swap, shuffle, seed)
to avoid excessive compilation overhead.
```

### `-ldflags -X` Protection

**Status**: ✅ **Fully Protected**

Go's `-ldflags -X` flag allows injecting string values at link time:

```sh
go build -ldflags="-X main.apiKey=sk_live_51234567890abcdefABCDEF"
```

**Traditional Vulnerability**: These strings appear in plaintext in the binary.

**Garble Protection Pipeline**:

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 1: FLAG SANITIZATION (main.go)                       │
├──────────────────────────────────────────────────────────────┤
│  Input:  -ldflags="-X main.apiKey=sk_live_51234567890..."    │
│  → Extracted & cached in LinkerInjectedStrings               │
│  → Rewritten: -ldflags="-X main.apiKey="  (empty to linker) │
│  ✅ Go toolchain NEVER sees the original value               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Phase 2: RUNTIME INJECTION (transformer.go)                 │
├──────────────────────────────────────────────────────────────┤
│  Injects: func init() { apiKey = <obfuscated("secret")> }   │
│  ✅ Uses identical obfuscation as normal string literals     │
└──────────────────────────────────────────────────────────────┘
```

**Security Guarantees**:

| Attack Vector                   | Normal Build           | Garble Build                |
|---------------------------------|------------------------|-----------------------------|
| `strings binary \| grep apiKey` | ❌ Plaintext found      | ✅ Not found                 |
| Static analysis                 | ❌ Immediate extraction | ⚠️ Requires reversing the runtime decode path |
| Hex editor search               | ❌ Visible bytes        | ✅ Only ciphertext           |
| Memory dump (runtime)           | ⚠️ Always plaintext    | ⚠️ Decrypted in memory      |

### Current Status

| Feature             | Status               | Notes                                             |
|---------------------|----------------------|---------------------------------------------------|
| String literals     | ✅ Obfuscated         | Custom cipher + lightweight transforms            |
| Numeric literals    | ✅ Obfuscated         | When `-literals` enabled                          |
| Byte slices         | ✅ Obfuscated         | Treated as literals                               |
| Const expressions   | ⚠️ Partially covered | Safe string consts rewritten; compile-time remain |
| -ldflags -X strings | ✅ Covered            | Sanitised at flag parse; runtime decrypt          |

### Implementation References
- `internal/literals/custom_cipher.go`: SPN cipher, Fisher-Yates S-box generation
- `internal/literals/custom_cipher_obfuscator.go`: Obfuscator integration and AST code gen
- `internal/literals/obfuscators.go`: Strategy selection and weighted registry
- `internal/literals/strategy_registry.go`: Weight-based random selection
- `internal/literals/swap.go`, `split.go`, `shuffle.go`, `seed.go`: Lightweight transforms
- Tests: `custom_cipher_test.go`, `fuzz_test.go`, `strategy_registry_test.go`

---

## 4. Reflection Control

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

## 5. Build Cache Encryption (ASCON-128)

### Purpose

Encrypt Garble's persistent build cache to prevent offline analysis of obfuscation metadata, import paths, and build artifacts.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Cache Encryption Flow (ASCON-128)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Write Path:                                                    │
│  1. Serialize pkg cache to gob                                  │
│  2. Derive key: SHA256(seed || "garble-cache-encryption-v1")    │
│  3. Encrypt with ASCON-128 (random 16-byte nonce)               │
│  4. Write to disk: [nonce][ciphertext][tag]                     │
│                                                                 │
│  Read Path:                                                     │
│  1. Read encrypted cache from disk                              │
│  2. Derive same key, decrypt with ASCON-128                     │
│  3. Verify authentication tag (tamper detection)                │
│  4. Deserialize gob into pkg cache                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Note**: ASCON-128 is used **only** for build cache encryption (build-time, never in the output binary). Literal obfuscation uses the per-build random cipher instead, which produces no detectable cryptographic signatures.

### Activation

Cache encryption is **enabled by default** when `-no-cache-encrypt` is **not** present. Garble uses the CLI seed if supplied; otherwise it generates a random per-build seed.

### Security Properties

| Property              | Value                        | Benefit                                |
|-----------------------|------------------------------|----------------------------------------|
| **Algorithm**         | ASCON-128 AEAD               | NIST-approved authenticated encryption |
| **Key Size**          | 128-bit                      | Strong security margin                 |
| **Nonce**             | 128-bit random               | Unique per cache entry                 |
| **Authentication**    | 128-bit tag                  | Detects tampering                      |
| **Domain Separation** | "garble-cache-encryption-v1" | Prevents key reuse attacks             |

### Implementation References
- `internal/cache/encryption.go`: `DeriveKey()`, `Encrypt()`, `Decrypt()`
- `internal/literals/ascon.go`: Core ASCON-128 implementation (shared)
- `cache_pkg.go`: `computePkgCache()`, `loadPkgCache()`, `decodePkgCacheBytes()`
- `main.go`: Seed and `-no-cache-encrypt` flag handling

---

## 6. Control-Flow Obfuscation

### Purpose

Transform control-flow structures to increase complexity and hinder static analysis, making it harder to understand program logic.

### Modes

| Mode              | Behavior                                               | Use Case                           |
|-------------------|--------------------------------------------------------|------------------------------------|
| **off** (default) | No transformation                                      | Standard builds                    |
| **directives**    | Only functions with `//garble:controlflow`             | Selective protection               |
| **auto**          | All eligible functions except `//garble:nocontrolflow` | Broad protection with escape hatch |
| **all**           | Every function                                         | Maximum obfuscation                |

### Transformation Strategy

1. **Flatten**: Convert structured control flow to flat switch/goto dispatch
2. **Hardening prologues**: Dispatcher keys are obfuscated and include opaque predicates
3. **Dead Code Injection**: Add unreachable but plausible code paths
4. **Trash blocks**: Inject dead code to increase complexity

### Performance Considerations

- **Binary size**: +5-15% typical increase
- **Performance**: Variable depending on function complexity
- **Compilation time**: +10-30% longer builds

**Recommendation**: Use `auto` mode with selective `//garble:nocontrolflow` in hot paths.

### Implementation References
- `internal/ctrlflow/mode.go`: Mode enum and parsing
- `internal/ctrlflow/ctrlflow.go`: Eligibility checks, transformation logic
- `internal/ctrlflow/transform.go`: AST transformation
- `docs/CONTROLFLOW.md`: Detailed design documentation

---

## 7. Operational Hardening Checklist

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
| Cross-build name correlation   | Easy → Hard   | Medium   | ✅ Mitigated (Nonce)                    |
| Static string extraction       | Easy → Medium | High     | ✅ Mitigated (Random cipher + diversity)|
| Reflection oracle exploitation | Easy → N/A    | Critical | ✅ Eliminated (Default)                 |
| Cache offline analysis         | Easy → Hard   | Medium   | ✅ Mitigated (ASCON Encryption)         |
| Signature scanner detection    | Easy → N/A    | Medium   | ✅ Eliminated (No fixed constants)      |
| Dynamic runtime tracing        | Easy          | Variable | ⚠️ By Design (Observable)              |
| Const expression extraction    | Easy          | Medium   | ⚠️ Partial Gap (compile-time contexts) |
| -ldflags -X plaintext leakage  | Easy          | Medium   | ✅ Mitigated (Sanitized + obfuscated)   |
| Control-flow analysis          | Medium        | Medium   | ⚠️ Optional (CF modes)                 |

### Detailed Mitigation Matrix

| Attack Vector                          | Mitigation Mechanism                                                         | Residual Risk                                                       |
|----------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------|
| **Cross-Build Pattern Matching**       | SHA-256 seed+nonce mixing; cryptographically random nonce per build          | If seed and nonce are fixed (reproducibility), correlation possible |
| **String/Literal Scraping**            | Per-build random SPN cipher (~60%); lightweight transforms (~40%)            | Compile-time-only consts remain in plaintext                        |
| **Signature Scanner (findcrypt/YARA)** | Fisher-Yates S-box generation; no AES/ASCON constants in output binary       | None — no fixed constants to match                                  |
| **Injected -ldflags Strings**          | CLI sanitization + shared-cache rehydration via literal builder              | Plaintext exists only transiently in garble parent process          |
| **Reflection Name Oracle**             | `_originalNamePairs` array is always empty                                   | No opt-in path; oracle removed                                      |
| **Cache Inspection/Tampering**         | ASCON-128 encryption at rest with 128-bit authentication tag                 | Shared ephemeral cache plaintext (deleted after build)              |
| **Known-Plaintext Attack on Literals** | Per-literal random keys; unique S-box per build                              | Requires recovering per-build cipher parameters (infeasible)        |
| **Dynamic Code Injection**             | Not addressed                                                                | Requires runtime protections (out of scope)                         |
| **Control-Flow Reconstruction**        | Optional CF obfuscation modes                                                | If disabled (default), structure remains clear                      |

### Attack Scenarios & Defenses

#### Scenario 1: Offline Binary Analysis
**Attacker Goal**: Extract original identifiers and strings without running the program.

**Defenses**:
- ✅ Per-build random cipher protects literals with no recognisable crypto signatures
- ✅ Sanitized `-ldflags -X` strings are rehydrated via obfuscated init-time assignments
- ✅ Empty reflection map eliminates name oracle
- ⚠️ String constants required at compile time (array lengths, switch labels, `iota` math) remain visible

**Result**: Significantly harder; requires reverse engineering each obfuscation layer per build.

#### Scenario 2: Cross-Binary Correlation
**Attacker Goal**: Compare multiple builds to identify patterns and recover originals.

**Defenses**:
- ✅ Per-build nonce ensures different hashes
- ✅ Random cipher parameters per build
- ⚠️ Fixed seed+nonce (reproducibility) breaks this defense

**Result**: Effective unless reproducible builds are used (intentional trade-off).

#### Scenario 3: Signature-Based Detection (AV/EDR)
**Attacker Goal**: Use findcrypt, YARA rules, or AV heuristics to flag the binary.

**Defenses**:
- ✅ No AES S-boxes, ASCON IVs, or other fixed cryptographic constants in output
- ✅ Fisher-Yates S-box is a random permutation — looks like ordinary data
- ✅ Generated code uses standard Go arithmetic (XOR, array indexing) — no crypto API imports

**Result**: Binary appears as normal obfuscated Go, not as "encrypted" or "packed".

#### Scenario 4: Dynamic Runtime Tracing
**Attacker Goal**: Observe program behavior at runtime to infer logic.

**Defenses**:
- ❌ Not addressed (out of scope for static obfuscation)
- ⚠️ Control-flow obfuscation can make tracing harder (if enabled)

**Result**: Dynamic analysis always possible; obfuscation raises the bar but doesn't prevent it.

#### Scenario 5: Cache-Based Analysis
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

| Type                        | Status        | Reason                                           |
|-----------------------------|---------------|--------------------------------------------------|
| Compile-time const contexts | ⚠️ Partial    | Array lengths, case labels, iota must stay const |
| `-ldflags -X` strings       | ✅ **Covered** | Sanitized at CLI, encrypted via init()           |
| Runtime-generated strings   | ❌ Not covered | Created dynamically                              |

#### 2. Control-Flow Default State

Control-flow obfuscation is opt-in (default: off). Performance impact not fully characterized.

#### 3. Exported Identifiers

Exported names remain unobfuscated by default — required for Go's interface compatibility and reflection. Use `-force-rename` to override at your own risk.

#### 4. Error/Panic Message Leakage

Error strings and panic messages may reveal implementation details.

### Roadmap

#### Short-Term

| Item                                     | Status         | Priority |
|------------------------------------------|----------------|----------|
| Improve const expression handling        | 🔄 In Progress | Medium   |
| Performance benchmarks for CF modes      | 📋 Planned     | Medium   |

#### Medium-Term

| Item                                | Status      | Priority |
|-------------------------------------|-------------|----------|
| Control-flow default-on evaluation  | 📋 Planned  | Medium   |
| `-strip-errors` flag implementation | 📋 Planned  | Low      |
| Cache encryption performance tuning | 📋 Planned  | Low      |

#### Long-Term

| Item                           | Status     | Priority |
|--------------------------------|------------|----------|
| Anti-debugging countermeasures | 💡 Concept | Low      |
| Whole-program obfuscation mode | 💡 Concept | Low      |

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
| **FEATURES.md**        | Complete flag and environment reference  | `docs/FEATURES.md`        |
| **CONTROLFLOW.md**     | Control-flow obfuscation design         | `docs/CONTROLFLOW.md`     |
| **LITERAL_ENCRYPTION.md** | Literal encryption architecture      | `docs/LITERAL_ENCRYPTION.md` |
| **README.md**          | User-facing overview and quick start    | `README.md`               |
| **This document**      | Security architecture and threat model  | `docs/SECURITY.md`        |

### Implementation Files

#### Core Obfuscation
- `main.go`: Entry point, flag parsing, seed/nonce handling
- `hash.go`: Name hashing, seed+nonce mixing
- `transformer.go`: AST transformation orchestration

#### Literals
- `internal/literals/custom_cipher.go`: Per-build random SPN cipher
- `internal/literals/custom_cipher_obfuscator.go`: AST code generation
- `internal/literals/obfuscators.go`: Weighted strategy selection
- `internal/literals/strategy_registry.go`: Registry with weight support
- `internal/literals/swap.go`, `split.go`, `shuffle.go`, `seed.go`: Lightweight transforms

#### Reflection
- `reflect.go`: Reflection metadata handling, `reflectMainPostPatch()`

#### Cache
- `internal/cache/encryption.go`: ASCON-128 encryption for cache
- `internal/literals/ascon.go`: Core ASCON-128 implementation
- `cache_pkg.go`: Cache persistence and loading

#### Control-Flow
- `internal/ctrlflow/mode.go`: Mode definitions
- `internal/ctrlflow/ctrlflow.go`: Transformation logic
- `internal/ctrlflow/transform.go`: AST manipulation

### Testing

#### Unit Tests
- `internal/literals/custom_cipher_test.go`: Cipher roundtrip, S-box bijectivity, no-fixed-constants
- `internal/literals/fuzz_test.go`: Literal obfuscation fuzzing
- `internal/literals/strategy_registry_test.go`: Weight distribution
- `cache_encryption_test.go`: Cache encryption roundtrip

#### Integration Tests
- `testdata/script/seed.txtar`: Seed and nonce behavior
- `testdata/script/ctrlflow_*.txtar`: Control-flow modes

### External References

#### Standards
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography): ASCON-128 specification (cache encryption)

#### Threat Intelligence
- [mandiant/gostringungarbler](https://github.com/mandiant/gostringungarbler): Static string recovery tool
- [Invoke-RE/ungarble_bn](https://github.com/Invoke-RE/ungarble_bn): Hash salt brute-forcing tool

---

**Document Maintenance**
- **Last Updated**: January 2025
- **Owner**: AeonDave


