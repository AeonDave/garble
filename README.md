# garble hardened (Efesto)

> **Security-hardened fork of [github.com/burrowers/garble](https://github.com/burrowers/garble)** — enhanced obfuscation and anti-analysis for Go binaries.  
> See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Installation

```sh
go install github.com/AeonDave/garble@latest
```

Or clone and build:

```sh
git clone https://github.com/AeonDave/garble
cd garble && go install ./...
```

Requires **Go 1.25+**.

---

## What happens without any flag (`garble build`)

Even with zero user-supplied flags, `garble build` already produces a significantly
hardened binary compared to a plain `go build`. The table below shows everything
that is applied **automatically**:

| Protection | How | Why it matters |
|---|---|---|
| **Identifier renaming** | SHA-256(name + seed + nonce) → short base64 hash | Strips function names, type names, and package paths from the binary — tools like GoReSym and `strings` no longer recover them. |
| **Package path hashing** | Same hash scheme applied to import paths | Prevents import path enumeration by disassemblers (IDA, Ghidra). |
| **File / position hashing** | File names and line numbers replaced with hashes | Stack traces still work internally but leak no original source paths. |
| **Random seed** | A fresh cryptographic seed is generated per build | Every build produces different hashes; identical source → different binary, defeating diff-based analysis. |
| **Build info stripped** | `-buildvcs=false`, `runtime.Version()` → `"unknown"` | `go version -m binary` reveals nothing. |
| **Module info stripped** | `debug.ReadBuildInfo()` returns empty | No module path, dependency list, or VCS revision. |
| **Debug info stripped** | `-ldflags="-w -s"` injected automatically | No DWARF sections, no symbol table — disassemblers lose named symbols. |
| **Build ID removed** | `-buildid=""` | Removes the Go build ID that can fingerprint compiler version and source. |
| **Trimpath** | `-trimpath` with extended temp dir handling | No `/home/user/go/src/…` paths leak into the binary. |
| **Export-aware renaming** | Exported names follow Go ABI requirements | The binary still works correctly with reflect, interfaces, plugins. |

**Result**: A plain `garble build` already makes the binary unreadable to `strings`,
GoReSym, and basic IDA/Ghidra analysis. But the **actual string values** remain in
plaintext inside the binary — an analyst running `strings binary | grep password`
will still find them.

---

## What each flag adds

### `-literals` — Literal encryption

**The single most important flag for protecting secrets.**

| What changes | Detail |
|---|---|
| String/byte/numeric literals | Replaced at compile time with encrypted ciphertext + inline decryptor |
| Cipher | Per-build random SPN (Substitution-Permutation Network), 4-6 rounds, Fisher-Yates 256-byte S-box — no AES, no ASCON, no fixed constants in the output |
| Strategy diversity | ~60% custom cipher, ~10% each for Swap/Split/Shuffle/Seed — each literal gets a randomly chosen strategy |
| `-ldflags=-X` strings | Intercepted at parse time, encrypted, and injected via obfuscated `init()` |
| Key zeroization | Inline scrub after decryption to minimize key lifetime in memory |

**Without `-literals`**: `strings binary | grep API_KEY` → finds it in plaintext.  
**With `-literals`**: `strings binary | grep API_KEY` → nothing. At runtime the string is decrypted only when needed.

```sh
# Protect API keys, credentials, URLs
garble -literals build -ldflags="-X main.apiKey=sk_live_ABC123" ./cmd/myapp
```

**Trade-offs**: Small binary size increase (~5-15%), minor runtime overhead per literal (decrypt + zeroize).

---

### `-tiny` — Minimal binary size

| What changes | Detail |
|---|---|
| Position info | Removed entirely (not just hashed) |
| Panic/fatal printing | Runtime printing code removed |
| `GODEBUG` | Ignored at runtime |
| Symbol names | Additional names omitted from binary sections |
| Net effect | ~15% smaller binary |

**Without `-tiny`**: Panics print "`goroutine 1 [running]: <hashed>.func1()`" — still reveals structure.  
**With `-tiny`**: Panics silently crash with no output. `recover` still works.

**Trade-offs**: Debugging is virtually impossible; stack traces are empty.

---

### `-controlflow` — Control-flow obfuscation

Four modes, each adds more protection:

| Mode | What it does | Build time impact |
|---|---|---|
| `off` (default) | Nothing | None |
| `directives` | Obfuscates only functions annotated with `//garble:controlflow` | Minimal |
| `auto` | Automatically selects safe candidate functions | Moderate |
| `all` | Obfuscates all eligible functions, most aggressive | Highest |

**What the obfuscation looks like**:
- Structured `if/else/switch/for` → replaced with opaque jump-table dispatch
- Dead code injection with plausible but unreachable branches
- Opaque predicates (always-true/always-false conditions that resist static analysis)
- XOR-encrypted dispatcher keys
- Delegate tables to hide real call targets

**Without `-controlflow`**: IDA/Ghidra decompile clean `if/else` structures.  
**With `-controlflow=auto`**: Decompiler produces unreadable spaghetti with hundreds of switch-cases.

Opt out per function: `//garble:nocontrolflow`

---

### `-seed` — Deterministic builds

| What changes | Detail |
|---|---|
| Default (no `-seed`) | Fresh random seed per build — maximum uniqueness |
| `-seed=random` | Same as default but **prints the seed** for later reproduction |
| `-seed=<base64>` | Fixed seed — same source + same seed + same nonce = identical binary |

Combine with `GARBLE_BUILD_NONCE=<base64>` for fully deterministic CI/CD builds.

**Without fixed seed**: Every build produces a unique binary (good for stealth, bad for reproducibility).  
**With fixed seed+nonce**: Byte-identical binaries for auditing, signing, compliance.

---

### `-force-rename` — Rename exported methods

Normally, exported methods that might satisfy interfaces are left unchanged.
`-force-rename` renames them too.

**Without**: Public API names like `ServeHTTP` remain in the binary.  
**With**: Even `ServeHTTP` is hashed. May break interface satisfaction — use only when the binary exposes no public APIs.

---

### `-no-cache-encrypt` — Disable cache encryption

By default, garble encrypts its on-disk build cache with ASCON-128 (keyed by the build seed).

**Without this flag**: Cache entries are encrypted — an attacker reading `~/.cache/garble` sees ciphertext.  
**With this flag**: Cache is plaintext. Only useful for debugging or environments where disk encryption is already in place.

---

### Environment variables

| Variable | Purpose |
|---|---|
| `GOGARBLE` | Glob patterns for packages to obfuscate. Default `*` = everything. Example: `GOGARBLE='./internal/...'` |
| `GARBLE_BUILD_NONCE` | Fixed base64 nonce for reproducible builds (combine with `-seed=<value>`) |
| `GARBLE_CACHE` | Override cache directory (default: `~/.cache/garble`) |
| `GARBLE_CONTROLFLOW_DEBUG` | Set to `1` to log skip reasons for control-flow obfuscation |

---

## Recommended configurations

### Default protection (recommended for most cases)

```sh
garble -literals -tiny -controlflow=auto build ./cmd/myapp
```

This enables all major protections. The binary will have:
- No readable function names, package paths, or file paths
- All string literals encrypted with per-build random ciphers
- Control flow obfuscated with jump tables and dead code
- Minimal binary size with stripped metadata
- No debug info, no symbol table, no build info

### Reproducible CI/CD

```sh
GARBLE_BUILD_NONCE=a1b2c3d4e5f6g7h8 \
  garble -seed=myFixedSeed -literals -tiny -controlflow=auto build ./cmd/myapp
```

### Library with public API

```sh
GOGARBLE='./internal/...' garble -literals build ./cmd/myapp
```

Protects internal code while keeping public interface names readable.

---

## Security posture

Garble applies **defense in depth** — multiple independent layers ensure that no single
bypass defeats all protections. For the full threat model, see [docs/SECURITY.md](docs/SECURITY.md).

| Layer | What it stops |
|---|---|
| **Name hashing** | Symbol recovery tools (GoReSym, IDA Go analysis, Ghidra plugins) return empty results |
| **Literal encryption** | `strings`, YARA, and byte-pattern scanners find no plaintext secrets |
| **No fixed crypto constants** | findcrypt / YARA S-box signatures match nothing — S-box is random per build |
| **Per-build uniqueness** | No universal signature or rule can match all builds |
| **Polymorphic decryption stubs** | Each literal site has unique variable names and randomly selected MBA (Mixed Boolean-Arithmetic) XOR encodings — pattern-matching deobfuscators fail |
| **Control-flow flattening** | Decompilers produce unreadable output; analyst time increases significantly |
| **Opaque predicates & dead code** | Static analysis and emulation boundary detection are confused by unreachable branches |
| **Reflect ABI hardening** | Injected runtime code uses short opaque identifiers — decompilers see no recognisable names |
| **Build metadata stripping** | `go version -m`, `debug.ReadBuildInfo()`, DWARF, symbol table — all empty |
| **Cache encryption** | On-disk build cache is ASCON-128 encrypted, keyed to the build seed |

**Known limitation**: Go's `runtime.slicebytetostring` is an unavoidable convergence
point for all `[]byte → string` conversions. Emulation-based tools (Unicorn/vstack)
can still recover decrypted strings by emulating each stub individually. Our mitigations
(MBA, polymorphism, control-flow) raise the cost of automated recovery but do not
eliminate it. See [docs/ROADMAP.md](docs/ROADMAP.md) for planned improvements.

---

## Additional hardening checklist

Things that complement garble but are outside its scope:

- **Always ship with** `-literals -tiny -controlflow=auto` — this is the baseline.
- **Keep cache encryption ON** (default) — avoid `-no-cache-encrypt` in production.
- **Rotate seeds** for long-lived products to defeat cross-build correlation.
- **Keep secrets out of compile-time const contexts** — array sizes, `case` labels,
  `iota` math must stay plaintext.
- **Use `GOGARBLE='*'`** unless you need specific packages unobfuscated.
- **Avoid `-debugdir` and `-debug`** in production — they leak obfuscation structure.
- **UPX/packing**: garble does not pack binaries. If binary size or entropy analysis is
  a concern, consider adding a packer as a post-build step — but note that packers add
  their own detection signatures.
- **Code signing**: Sign your final binary to prevent tampering and add legitimacy.
- **Supply-chain**: Pin your garble version and Go version for reproducible audits.

---

## How garble works

The tool wraps calls to the Go compiler and linker to transform the build:

1. **Parse & type-check** — Load all packages via `go/parser` + `go/types`
2. **Name hashing** — Replace identifiers with SHA-256(seed + nonce + name) → base64
3. **Literal encryption** (`-literals`) — Replace string/byte/numeric literals with ciphertext + inline decryptor
4. **Control-flow** (`-controlflow`) — SSA transform → jump-table dispatch + dead code
5. **Position obfuscation** — Hash file/line info (or remove entirely with `-tiny`)
6. **Linker patches** — Strip symbols, DWARF, build ID, VCS info
7. **Cache encryption** — Encrypt build cache with ASCON-128 AEAD

Garble obfuscates one package at a time (matching Go's compilation model) and fully
supports Go's build cache for incremental builds.

### Speed

`garble build` takes about 2× a normal `go build` — it does two builds internally.
The first to load and type-check the code, the second to compile the obfuscated output.
Incremental builds are cached normally.

### Determinism

Garble builds are deterministic: same source + same seed + same nonce = identical binary.
By default, a random seed is generated per build for maximum uniqueness.

---

## Hardening pipeline

```
                    ┌──────────────────────────┐
                    │     Go Source Files      │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   Parse & Type-check     │
                    │   (go/parser + go/types) │
                    └────────────┬─────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
   ┌──────────────────┐ ┌───────────────┐ ┌─────────────────┐
   │  Name Hashing    │ │  -literals    │ │  -controlflow   │
   │ ─────────────────│ │ ──────────────│ │ ────────────────│
   │ SHA-256 + seed   │ │ Weighted      │ │ SSA transform   │
   │ + per-build nonce│ │ strategy      │ │ jump tables     │
   │ base64 6-12 char │ │ selection     │ │ dead code inject│
   │ export-preserving│ │      │        │ │ opaque predicate│
   └──────────────────┘ │      ▼        │ │ XOR dispatcher  │
                        │ ┌───────────┐ │ │ delegate tables │
                        │ │ Per-build │ │ └─────────────────┘
                        │ │ random    │ │
                        │ │ cipher    │ │
                        │ │ (SPN)     │ │
                        │ ├───────────┤ │
                        │ │ Swap/     │ │
                        │ │ Split/    │ │
                        │ │ Shuffle/  │ │
                        │ │ Seed      │ │
                        │ └─────┬─────┘ │
                        │       │       │
                        │       ▼       │
                        │ Key zeroize   │
                        │ after decrypt │
                        └───────┬───────┘
                                │
                   ┌────────────▼──────────────┐
                   │  Position Obfuscation     │
                   │  filenames → hashes       │
                   │  (-tiny: removed entirely)│
                   └────────────┬──────────────┘
                                │
                   ┌────────────▼─────────────┐
                   │  Linker Patches          │
                   │  strip symbols (-s)      │
                   │  strip DWARF  (-w)       │
                   │  drop build ID           │
                   └────────────┬─────────────┘
                                │
                   ┌────────────▼─────────────┐
                   │  Cache Encryption        │
                   │  ASCON-128 AEAD          │
                   │  SHA-256 derived keys    │
                   └────────────┬─────────────┘
                                │
                   ┌────────────▼─────────────┐
                   │   Hardened Binary        │
                   └──────────────────────────┘
```

---

## Use cases

**Why obfuscate a compiled language?** Go binaries include a surprising amount of
source metadata: function names, type names, file paths, module info, even with debug
info stripped. Garble removes this.

- **Commercial software** — Protect proprietary algorithms and business logic
- **API keys & credentials** — `-literals` encrypts `sk_live_…` strings that `go build` leaves in plaintext
- **Anti-reverse-engineering** — Combined with `-controlflow`, decompilers produce unusable output
- **Binary size** — `-tiny` gives ~15% reduction (similar to Android R8/ProGuard obfuscation)
- **AV false positives** — Some Go binaries trigger AV heuristics due to large size and uncommon structure; obfuscation can change the signature enough to avoid these

---

## Caveats

- Exported methods are not renamed by default (needed for interfaces). Use `-force-rename` to override.
- No way to exclude specific files — if obfuscation causes a bug, file an issue.
- `init()` ordering may change because import paths are hashed.
- Go plugins not supported ([#87](https://github.com/burrowers/garble/issues/87)).
- Garble requires `git` for linker patches.
- `runtime.GOROOT` and `debug.ReadBuildInfo` return empty in obfuscated binaries.
  This [can affect timezone loading](https://github.com/golang/go/issues/51473#issuecomment-2490564684).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

