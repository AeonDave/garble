# Garble feature toggles

This reference consolidates every command-line flag and environment variable that flips behaviour inside Garble. It reflects the state of `master` as of October 2025 and was assembled by walking the entire repository.

## CLI flags

| Flag                | Values / type                            | Default | Controls                                                                                                                     | Notes & interactions                                                                                                                       |
|---------------------|------------------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `-literals`         | boolean                                  | `false` | Enables literal obfuscation (strings, numbers, eligible string constants, `-ldflags -X` injections) via `internal/literals`. | Performs a pre-pass that rewrites safe `const` strings into vars; affects build outputs and cache keys. No environment alias.              |
| `-tiny`             | boolean                                  | `false` | Optimises for binary size at the cost of reversibility.                                                                      | Propagates as `GARBLE_LINK_TINY=true` for the patched linker. Combines with `-reversible` but favours smaller binaries.                    |
| `-debug`            | boolean                                  | `false` | Emits verbose obfuscation logs to stderr.                                                                                    | Does not change build artefacts; skipped in build cache keys.                                                                              |
| `-debugdir`         | string (path)                            | unset   | Writes obfuscated Go sources to the given directory.                                                                         | Directory is recreated on each build (sentinel `.garble-debugdir`). Forces `go` to rebuild dependencies (`-a`).                            |
| `-seed`             | base64 string or `random`                | unset   | Supplies deterministic entropy for name hashing, literal mangling, and cache encryption.                                     | When `random`, a fresh 32-byte seed is generated and printed to stderr. Without a seed Garble derives entropy solely from the build nonce; cache encryption then requires `-cache-encrypt-nonce`. |
| `-reversible`       | boolean                                  | `false` | Keeps enough metadata to support `garble reverse` and easier debugging.                                                      | Weakens obfuscation. Propagated to the linker as `GARBLE_LINK_REVERSIBLE=true`.                                                            |
| `-controlflow`      | enum: `off`, `directives`, `auto`, `all` | `off`   | Selects the scope for control-flow obfuscation transforms.                                                                   | CLI value wins over `GARBLE_CONTROLFLOW`. `auto` respects `//garble:nocontrolflow` directives and skips unsafe SSA shapes.                 |
| `-no-cache-encrypt` | boolean (presence flag)                  | `false` | Disables ASCON encryption of Garble's build cache.                                                                           | Encryption is on by default when this flag is absent and either a seed or `-cache-encrypt-nonce` is provided.                              |
| `-cache-encrypt-nonce` | boolean (presence flag)               | `false` | Encrypts the cache using the build nonce when no seed is present, producing per-build cache entries.                         | Useful when CI cannot provision a long-term seed but still requires encrypted caches; pair with `GARBLE_BUILD_NONCE` for determinism.      |

### Flag interactions worth noting

- **Cache encryption** activates when a seed is present or when `-cache-encrypt-nonce` requests the build-nonce fallback. `-no-cache-encrypt` turns it off even with a seed or fallback.
- **Control-flow scope** can also be set through `GARBLE_CONTROLFLOW`; the CLI flag always takes precedence.
- **Reproducible builds** typically combine `-seed=<known>` with `GARBLE_BUILD_NONCE=<known>` and omit `-no-cache-encrypt` so cache entries stay encrypted with the supplied seed.

## Environment variables (regular build usage)

| Variable                   | Default                                             | Purpose                                                                                                | Notes                                                                                                                    |
|----------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `GOGARBLE`                 | `*` (obfuscate every package)                       | Selects which import paths Garble obfuscates. Accepts the same pattern syntax as Go's module matching. | Used in build hashing. Example: `GOGARBLE=./cmd/foo,...` to scope obfuscation.                                           |
| `GARBLE_CONTROLFLOW`       | unset → behaves like `off`                          | Provides the same values as the `-controlflow` flag (`off`, `directives`, `auto`, `all`).              | Only read when the CLI flag is absent.                                                                                   |
| `GARBLE_BUILD_NONCE`       | Random 32-byte value generated per build            | Injects a deterministic 32-byte nonce (base64 *without* padding) to stabilise hashes across builds.    | When unset, Garble draws a cryptographically random nonce and prints `-nonce chosen at random` when randomness was used. |
| `GARBLE_CACHE`             | `${XDG_CACHE_HOME}/garble` (or platform equivalent) | Overrides the on-disk cache root Garble uses for build metadata and patched toolchain artifacts.       | Helpful for sandboxing or sharing caches across CI jobs.                                                                 |
| `GARBLE_WRITE_CPUPROFILES` | unset                                               | When set to a directory, collects a CPU profile `garble-cpu-*.pprof` for the top-level Garble process. | Directory must exist; profile is closed automatically on exit.                                                           |
| `GARBLE_WRITE_MEMPROFILES` | unset                                               | Writes a heap profile `garble-mem-*.pprof` into the specified directory just before exit.              | Triggers a `runtime.GC()` to capture fresh statistics.                                                                   |
| `GARBLE_WRITE_ALLOCS`      | unset → disabled                                    | If set to `true`, prints total heap allocations (`garble allocs: <n>`) at exit.                        | Intended for instrumentation and regression tracking.                                                                    |

## Environment variables managed internally

These are populated by Garble itself so that its `toolexec` subprocesses and the patched linker see consistent settings. They are documented here for completeness; end-users normally should not set them manually.

| Variable                 | Set by                   | Purpose                                                                                    | Notes                                                                                                            |
|--------------------------|--------------------------|--------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `GARBLE_SHARED`          | Top-level Garble process | Points child processes at the shared gob-encoded build state.                              | Cleared and deleted after the build. A pre-existing value allows nested invocations to reuse the same workspace. |
| `LINK_SEED`              | Garble                   | Base64-encoded 32-byte Feistel seed used to encrypt runtime metadata (e.g. method tables). | Must be present; linker panics if missing.                                                                       |
| `GARBLE_LINK_REVERSIBLE` | Garble                   | Communicates whether reversible mode is enabled.                                           | Set to `true` when `-reversible`; otherwise `false`.                                                             |
| `GARBLE_LINK_TINY`       | Garble                   | Communicates whether tiny binaries are requested.                                          | Read by linker patches to strip additional metadata.                                                             |

## Developer/test harness variables

The repository also defines a handful of switches that assist automated testing or specialised builds. They do not normally affect production usage but are listed for completeness.

| Variable                              | Scope                                            | Purpose                                                                                                                              | Notes                                                                                        |
|---------------------------------------|--------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `GARBLE_TEST_GOVERSION`               | Test scripts (`testdata/script/goversion.txtar`) | Overrides the Go toolchain version that `main.go` compares against the build's recorded version.                                     | Lets tests simulate running under mismatched toolchains. Not meant for CI/production builds. |
| `GARBLE_TEST_LITERALS_OBFUSCATOR_MAP` | Builds with the `garble_testing` tag             | Provides a comma-separated mapping of package → obfuscator index so literal fuzz/bench harnesses can pick deterministic obfuscators. | Required when compiling the benchmarking helper under `scripts/bench_literals.go`.           |
| `RUN_GARBLE_MAIN`                     | `bench_test.go` & `main_test.go`                 | Signals the integration tests to invoke the `garble` binary instead of stubbing commands.                                            | Ignored outside the test harness.                                                            |
| `GARBLE_TEST_REVERSING`               | `testdata/script/cgo.txtar` sample program       | Toggles additional logging inside the fixture binary to exercise `garble reverse`.                                                   | Read by the sample program, not by Garble itself.                                            |

## Flags Applied Automatically

Garble automatically applies the following flags to build commands. You **do not need** to specify them manually:

| Flag                              | Applied When                          | Purpose                                                                                                                        | Code Reference                                |
|-----------------------------------|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| `-trimpath`                       | Always (all `go list/build` commands) | Strips filesystem paths from binaries. Garble extends this with `sharedTempDir` handling to prevent temporary directory leaks. | `cache_shared.go`, `transformer.go` |
| `-buildvcs=false`                 | Always                                | Omits VCS metadata (git commit hash, dirty state) from binaries.                                                               | `cache_shared.go`                         |
| `-ldflags="-w"`                   | Link phase only                       | Strips DWARF debugging information (file/line mappings, variable names).                                                       | `transformer.go`                         |
| `-ldflags="-s"`                   | Link phase only                       | Strips symbol table and debug sections completely.                                                                             | `transformer.go`                         |
| `-buildid=""`                     | Link phase only                       | Removes Go build ID to prevent binary tracking across builds.                                                                  | `transformer.go`                         |
| `-X=runtime.buildVersion=unknown` | Link phase only                       | Replaces `runtime.Version()` output with "unknown" instead of "go1.X.Y".                                                       | `transformer.go`                         |

**Important Notes:**
- These flags are **hardcoded** and cannot be overridden by user input.
- Manual specification (e.g., adding `-ldflags="-s -w"` yourself) is redundant and has no effect.
- `-trimpath` is extended by Garble's `alterTrimpath()` function to include temporary build directories.

## Quick precedence checklist

- CLI flags are parsed once at process startup; re-entrant invocations inherit state via `GARBLE_SHARED` and the cached seed/nonce.
- When both a CLI flag and an environment variable target the same feature, the CLI flag wins (`-controlflow` over `GARBLE_CONTROLFLOW`, `-seed` over any inherited entropy).
- Encryption and other security-sensitive features rely on both `-seed` and the build nonce; keep them aligned when creating reproducible yet hardened builds.

