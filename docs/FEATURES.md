# Garble Feature Reference

> Complete reference for every CLI flag, environment variable, and automatic behavior. Reflects the current state of `master`.

---

## Table of Contents

1. [CLI Flags](#cli-flags)
2. [Flag Interactions](#flag-interactions)
3. [Flag Effects Matrix](#flag-effects-matrix)
4. [Environment Variables](#environment-variables)
5. [Internal Environment Variables](#internal-environment-variables)
6. [Developer & Test Variables](#developer--test-variables)
7. [Flags Applied Automatically](#flags-applied-automatically)
8. [Precedence Rules](#precedence-rules)
9. [Recommended Configurations](#recommended-configurations)

---

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-literals` | boolean | `false` | Encrypts string and numeric literals, eligible string constants, and `-ldflags -X` injected values using per-build random ciphers. Performs a pre-pass that rewrites safe `const` strings into `var` declarations. Skips packages containing low-level `//go:` directives (logs the reason). See [LITERAL_ENCRYPTION.md](LITERAL_ENCRYPTION.md). |
| `-tiny` | boolean | `false` | Optimises for binary size. Strips runtime metadata, panic message printers, file/line info, and trace code. Propagates as `_XLINK_TINY=true` for linker patches. Binary size reduction is typically ~15%. |
| `-debug` | boolean | `false` | Emits verbose obfuscation logs to stderr. Does not affect build artifacts or cache keys. |
| `-debugdir` | string (path) | unset | Writes obfuscated Go sources to the given directory for inspection. Directory is recreated on each build (sentinel `.garble-debugdir`). Forces full rebuild (`-a`). |
| `-seed` | base64 / `random` | random | Supplies deterministic entropy for name hashing, literal encryption, and cache keys. Default is a fresh 32-byte seed per build. Use `-seed=random` to print the generated seed. Set a fixed value only for reproducible builds. |
| `-controlflow` | `off` / `directives` / `auto` / `all` | `off` | Selects control-flow obfuscation scope. `auto` respects `//garble:nocontrolflow` directives and skips unsafe SSA shapes. If typecheck fails after transformation, control-flow is disabled for that package (logged). See [CONTROLFLOW.md](CONTROLFLOW.md). |
| `-force-rename` | boolean | `false` | Renames exported methods even if they might implement interfaces. **Use with caution**: may break interface satisfaction. Useful when maximum stealth is needed and the binary does not expose public APIs. |
| `-no-cache-encrypt` | presence flag | absent (encryption ON) | Disables ASCON-128 encryption of Garble's build cache on disk. Encryption is enabled by default. |

---

## Flag Interactions

### Cache encryption
Activates automatically unless `-no-cache-encrypt` is provided. Default builds use the random per-build seed, so cache entries remain encrypted and per-build unique.

### Control-flow scope
Can also be set via `GARBLE_CONTROLFLOW`; the CLI flag always wins.

### Reproducible builds
Combine `-seed=<known>` with `GARBLE_BUILD_NONCE=<known>`. Omit `-no-cache-encrypt` so cache entries stay encrypted with the supplied seed.

### Literal obfuscation & directives
Packages that contain `//go:nosplit`, `//go:noescape`, or similar low-level directives skip literal obfuscation entirely. Garble logs the first triggering directive and its position.

### `-force-rename` & interfaces
When `-force-rename` is set, exported methods on concrete types are renamed even though they may satisfy interface contracts. This **will break** code that relies on implicit interface satisfaction across package boundaries. Only use when:
- The binary is standalone (no plugin/RPC interfaces)
- Maximum name obfuscation is desired
- You have verified the binary works correctly after obfuscation

---

## Flag Effects Matrix

What you gain and lose with each flag:

| Flag | Gains | Trade-offs | Notes |
|------|-------|------------|-------|
| `-literals` | Encrypt string/byte/numeric literals with per-build random ciphers; protect `-ldflags -X` values; multi-strategy diversity | Small runtime cost per literal (decrypt + zeroize); code size increase | Compile-time constants (array sizes, `case` labels, `iota` math) remain in plaintext. |
| `-controlflow=off` | Fastest build and runtime | No control-flow obfuscation | Default. |
| `-controlflow=directives` | Targeted CF obfuscation via `//garble:controlflow` | Manual annotation required | Minimal overhead; use for hotspots. |
| `-controlflow=auto` | Broad CF obfuscation with safe auto-detection | Higher build time and runtime overhead | Skip with `//garble:nocontrolflow` for critical paths. |
| `-controlflow=all` | Maximum CF coverage | Highest overhead; aggressive transforms | `//garble:nocontrolflow` still works. |
| `-tiny` | ~15% smaller binaries; removes file/line info, panic printers | Stack traces become useless; `GODEBUG` ignored | Does not disable `-literals` or `-controlflow`. |
| `-seed=<fixed>` | Deterministic obfuscation (reproducible builds) | Same output if seed+nonce fixed | Set `GARBLE_BUILD_NONCE` for full reproducibility. |
| `-force-rename` | Renames exported methods for maximum stealth | May break interface satisfaction | Only for standalone binaries. |
| `-no-cache-encrypt` | Faster cache I/O in constrained environments | Cache stored in plaintext | Does not affect binary quality. |

---

## Environment Variables

### User-facing

| Variable | Default | Description |
|----------|---------|-------------|
| `GOGARBLE` | `*` (all packages) | Selects which import paths Garble obfuscates. Same pattern syntax as Go's module matching. Example: `GOGARBLE='./internal/...'` to scope obfuscation. |
| `GARBLE_CONTROLFLOW` | unset (= `off`) | Same values as `-controlflow` flag. Only read when the CLI flag is absent. |
| `GARBLE_BUILD_NONCE` | Random 32-byte value | 32-byte nonce (base64, no padding) mixed into every hash. When unset, Garble generates a cryptographic random nonce and prints it. |
| `GARBLE_CACHE` | `${XDG_CACHE_HOME}/garble` | Overrides the on-disk cache root for build metadata and patched toolchain artifacts. Useful for sandboxing or CI cache sharing. |

### Profiling

| Variable | Default | Description |
|----------|---------|-------------|
| `GARBLE_WRITE_CPUPROFILES` | unset | Directory for CPU profiles (`garble-cpu-*.pprof`). Directory must exist. |
| `GARBLE_WRITE_MEMPROFILES` | unset | Directory for heap profiles (`garble-mem-*.pprof`). Triggers `runtime.GC()`. |
| `GARBLE_WRITE_ALLOCS` | unset | Set to `true` to print total heap allocations at exit. For regression tracking. |

---

## Internal Environment Variables

Set by Garble itself for `toolexec` subprocesses and the patched linker. **Do not set manually.**

| Variable | Set by | Purpose |
|----------|--------|---------|
| `GARBLE_SHARED` | Top-level Garble process | Points child processes at the shared gob-encoded build state. Cleared and deleted after the build. |
| `_XLINK_TINY` | Garble | Communicates `-tiny` mode to linker patches for additional metadata stripping. |

---

## Developer & Test Variables

Switches for automated testing and specialized builds. Not for production.

| Variable | Scope | Description |
|----------|-------|-------------|
| `GARBLE_TEST_GOVERSION` | Test scripts | Overrides Go toolchain version for version-mismatch simulation tests. |
| `GARBLE_TEST_LITERALS_OBFUSCATOR_MAP` | `garble_testing` build tag | Comma-separated package→obfuscator index mapping for deterministic fuzz/bench harnesses. |
| `RUN_GARBLE_MAIN` | `bench_test.go`, `main_test.go` | Signals integration tests to invoke the `garble` binary directly. |
| `GARBLE_CONTROLFLOW_DEBUG` | Debug builds | Set to `1` for diagnostic logs of control-flow skip reasons. |

---

## Flags Applied Automatically

Garble applies these flags to every build. You **do not need** to specify them manually:

| Flag | Applied When | Purpose | Code Reference |
|------|-------------|---------|----------------|
| `-trimpath` | All `go list/build` commands | Strips filesystem paths from binaries. Extended with `sharedTempDir` handling to prevent temp directory leaks. | `cache_shared.go`, `transformer.go` |
| `-buildvcs=false` | Always | Omits VCS metadata (git commit, dirty state) from binaries. | `cache_shared.go` |
| `-ldflags="-w"` | Link phase | Strips DWARF debugging information. | `transformer.go` |
| `-ldflags="-s"` | Link phase | Strips symbol table and debug sections completely. | `transformer.go` |
| `-buildid=""` | Link phase | Removes Go build ID to prevent cross-build tracking. | `transformer.go` |
| `-X=runtime.buildVersion=...` | Link phase | Replaces `runtime.Version()` with a standard Go version string. | `transformer.go` |

**Notes:**
- These flags are hardcoded and cannot be overridden.
- Specifying them manually (e.g., `-ldflags="-s -w"`) is redundant.
- `-trimpath` is extended by `alterTrimpath()` to include temporary build directories.

---

## Precedence Rules

1. **CLI flags > Environment variables**: `-controlflow=auto` overrides `GARBLE_CONTROLFLOW=off`.
2. **Re-entrant invocations** inherit state via `GARBLE_SHARED` and the cached seed/nonce.
3. **Security features** (encryption, nonce mixing) depend on both `-seed` and the build nonce — keep them aligned for reproducible hardened builds.
4. When both a CLI flag and env var target the same feature, the CLI flag **always** wins.

---

## Recommended Configurations

### Production (maximum protection)
```bash
garble -literals -tiny -controlflow=auto build ./cmd/myapp
```

### Production with reproducibility
```bash
GARBLE_BUILD_NONCE=<fixed-base64> garble -seed=<fixed-base64> \
  -literals -tiny -controlflow=auto build ./cmd/myapp
```

### Development (fast iteration)
```bash
garble build ./cmd/myapp
```

### Debugging obfuscation issues
```bash
garble -debug -debugdir=/tmp/garble-debug -literals build ./cmd/myapp
```

### Library with public API
```bash
GOGARBLE='./internal/...' garble -seed=random -literals build ./...
```

### Maximum stealth (standalone binary)
```bash
garble -literals -tiny -controlflow=all -force-rename build ./cmd/myapp
```


