# garble hardened

Install from this repository (recommended for this fork):

- Clone: https://github.com/AeonDave/garble
- From the repo root: run `go install ./...`

Notes
- The module path remains `mvdan.cc/garble` for compatibility; using a local clone ensures you install this fork.
- Alternatively, to install the upstream module, use `go install mvdan.cc/garble@latest`.

Obfuscate Go code by wrapping the Go toolchain. Requires Go 1.25 or later.

	garble build [build flags] [packages]

The tool also supports `garble test` to run tests with obfuscated code,
`garble run` to obfuscate and execute simple programs,
and `garble reverse` to de-obfuscate text such as stack traces.
Run `garble -h` to see all available commands and flags.

### Quick start

1. Install from this repo:
  - `git clone https://github.com/AeonDave/garble`
  - `cd garble && go install ./...`
2. Obfuscate your binary: `garble build ./cmd/myapp`.
3. Make builds reproducible: provide both a seed and a build nonce.
  - Example: `garble -seed=Z3JhZmY build ./cmd/myapp`
  - And set `GARBLE_BUILD_NONCE` to a fixed base64 value when you need identical outputs across runs.

See [docs/FEATURE_TOGGLES.md](docs/FEATURE_TOGGLES.md) for a complete flag and environment reference.

You can also use `go install mvdan.cc/garble@master` to install the latest development version.

### Purpose

Produce a binary that works as well as a regular build, but that has as little
information about the original source code as possible.

The tool is designed to be:

* Coupled with `cmd/go`, to support modules and build caching
* Deterministic and reproducible, given the same initial source code
* Reversible given the original source, to de-obfuscate panic stack traces

### Mechanism

The tool wraps calls to the Go compiler and linker to transform the Go build, in
order to:

* Replace as many useful identifiers as possible with short base64 hashes
* Replace package paths with short base64 hashes
* Replace filenames and position information with short base64 hashes
* Remove all [build](https://go.dev/pkg/runtime/#Version) and [module](https://go.dev/pkg/runtime/debug/#ReadBuildInfo) information
* Strip debugging information and symbol tables via `-ldflags="-w -s"`
* [Obfuscate literals](#literal-obfuscation), if the `-literals` flag is given
* Remove [extra information](#tiny-mode), if the `-tiny` flag is given
* Apply [control-flow obfuscation](docs/CONTROLFLOW.md), if `-controlflow` is enabled

By default, the tool obfuscates all the packages being built.
You can manually specify which packages to obfuscate via `GOGARBLE`,
a comma-separated list of glob patterns matching package path prefixes.
This format is borrowed from `GOPRIVATE`; see `go help private`.

Note that commands like `garble build` will use the `go` version found in your
`$PATH`. To use different versions of Go, you can
[install them](https://go.dev/doc/manage-install#installing-multiple)
and set up `$PATH` with them. For example, for Go 1.17.1:

```sh
$ go install golang.org/dl/go1.17.1@latest
$ go1.17.1 download
$ PATH=$(go1.17.1 env GOROOT)/bin:${PATH} garble build
```

### Use cases

A common question is why a code obfuscator is needed for Go, a compiled language.
Go binaries include a surprising amount of information about the original source;
even with debug information and symbol tables stripped, many names and positions
remain in place for the sake of traces, reflection, and debugging.

Some use cases for Go require sharing a Go binary with the end user.
If the source code for the binary is private or requires a purchase,
its obfuscation can help discourage reverse engineering.

A similar use case is a Go library whose source is private or purchased.
Since Go libraries cannot be imported in binary form, and Go plugins
[have their shortcomings](https://github.com/golang/go/issues/19282),
sharing obfuscated source code becomes an option.
See [#369](https://github.com/burrowers/garble/issues/369).

Obfuscation can also help with aspects entirely unrelated to licensing.
For example, the `-tiny` flag can make binaries 15% smaller,
similar to the [common practice in Android](https://developer.android.com/build/shrink-code#obfuscate) to reduce app sizes.
Obfuscation has also helped some open source developers work around
anti-virus scans incorrectly treating Go binaries as malware.

### Key flags and environment knobs

- **`-literals`** – Scrambles string and numeric literals. Expect a modest CPU cost; perfect when protecting messages or secrets baked into the binary.
- **`-controlflow`** (`off`, `directives`, `auto`, `all`) – Adds jump-heavy control-flow. Start with `auto` for broad protection while skipping risky functions.
- **`-tiny`** – Strips file/line metadata for smaller binaries. Combine with `-reversible` only if you still need `garble reverse`.
- **`-reversible`** – Keeps breadcrumbs so `garble reverse` can de-obfuscate stack traces. Leave off for maximum security.
- **`-seed`** / **`GARBLE_BUILD_NONCE`** – Provide reproducible randomness. Pair a fixed seed with a fixed nonce when you need identical builds in CI.
- **`GOGARBLE`** – Limit obfuscation to selected packages. Example: `GOGARBLE=./internal/...` to leave public commands untouched.
- **`-no-cache-encrypt`** – Opt out of cache encryption. By default Garble encrypts its cache whenever a seed is available.

The full matrix of switches, defaults, and precedence rules lives in [docs/FEATURE_TOGGLES.md](docs/FEATURE_TOGGLES.md).

### Literal obfuscation

Using the `-literals` flag causes literal expressions such as strings to be
replaced with more complex expressions that resolve to the same value at run time.
This feature is opt-in, as it can cause slow-downs depending on the input code and size of literals.

Garble uses multiple obfuscation strategies for defense-in-depth:
* ASCON-128 authenticated encryption with inline decryption code (used frequently)
* Reversible simple obfuscator for small and performance-sensitive cases

Notes and limits
- Literals used in constant expressions cannot be obfuscated, since they are folded at compile time (e.g. values in a `const` block).
- Strings injected via `-ldflags=-X` are not currently covered by `-literals`.

### Reversible obfuscation

The `-reversible` flag controls whether original identifier names are embedded for tooling.

- Default (no `-reversible`): reversibility metadata is omitted, and the reflection name map stays empty. This avoids leaking original names in the binary.
- With `-reversible`: the reflection mapping is populated to enable `garble reverse` and improve debugging. This is an explicit security trade‑off.

Recommendation
- Leave `-reversible` off for production builds.
- Enable it in development/staging when you need to de‑obfuscate stack traces with `garble reverse`.

### Tiny mode

With the `-tiny` flag, even more information is stripped from the Go binary.
Position information is removed entirely, rather than being obfuscated.
Runtime code which prints panics, fatal errors, and trace/debug info is removed.
Many symbol names are also omitted from binary sections at link time.
All in all, this can make binaries about 15% smaller.

With this flag, no panics or fatal runtime errors will ever be printed, but they
can still be handled internally with `recover` as normal. In addition, the
`GODEBUG` environmental variable will be ignored.

Note that this flag can make debugging crashes harder, as a panic will simply
exit the entire program without printing a stack trace, and source code
positions and many names are removed.
Similarly, `garble reverse` is generally not useful in this mode.

### Control flow obfuscation

See: [docs/CONTROLFLOW.md](docs/CONTROLFLOW.md)

### Security snapshot

Recent releases focus on raising the bar for reverse engineers while keeping the tooling practical:

- Fresh names every build – Garble mixes your seed with a per-build nonce, so identical sources still produce different symbol hashes unless you fix both values.
- Encrypted literals when `-literals` is enabled – many string literals are protected with inline ASCON, raising the cost of static string scraping.
- Optional reversibility – keep `-reversible` off in production, enable it in staging to recover stack traces with `garble reverse`.
- Hardened cache – when a seed is present (and `-no-cache-encrypt` is not set), Garble encrypts its on-disk cache automatically.

Want the deep dive? The design notes and threat model live in [docs/SECURITY.md](docs/SECURITY.md).

### Speed

`garble build` should take about twice as long as `go build`, as it needs to
complete two builds. The original build, to be able to load and type-check the
input code, and then the obfuscated build.

Garble obfuscates one package at a time, mirroring how Go compiles one package
at a time. This allows Garble to fully support Go's build cache; incremental
`garble build` calls should only re-build and re-obfuscate modified code.

Note that the first call to `garble build` may be comparatively slow,
as it has to obfuscate each package for the first time. This is akin to clearing
`GOCACHE` with `go clean -cache` and running a `go build` from scratch.

Garble also makes use of its own cache to reuse work, akin to Go's `GOCACHE`.
It defaults to a directory under your user's cache directory,
such as `~/.cache/garble`, and can be placed elsewhere by setting `GARBLE_CACHE`.

### Determinism and seeds

Just like Go, garble builds are deterministic and reproducible in nature.
This has significant benefits, such as caching builds and being able to use
`garble reverse` to de-obfuscate stack traces.

By default, garble will obfuscate each package in a unique way,
which will change if its build input changes: the version of garble, the version
of Go, the package's source code, or any build parameter such as GOOS or -tags.
This is a reasonable default since guessing those inputs is very hard.

You can use the `-seed` flag to provide your own obfuscation randomness seed.
Reusing the same seed can help produce the same code obfuscation,
which can help when debugging or reproducing problems.
Regularly rotating the seed can also help against reverse-engineering in the long run,
as otherwise one can look at changes in how Go's standard library is obfuscated
to guess when the Go or garble versions were changed across a series of builds.

To always use a different seed for each build, use `-seed=random`.
Note that extra care should be taken when using custom seeds:
if a `-seed` value used in a build is lost, `garble reverse` will not work.

In addition to the seed, garble derives a build nonce which is mixed into every obfuscated name.
The nonce is printed when `-seed=random` is used and can be provided explicitly via the
`GARBLE_BUILD_NONCE` environment variable. For reproducible builds – and for `garble reverse`
to succeed – make sure to preserve both the seed and the nonce that were used for the original build.
If either value is lost, the obfuscation cannot be undone.

For teams who deliberately do not want reversal to be possible, avoid recording those values.
Without the corresponding seed and nonce, the resulting binaries are effectively non-reversible.


### Caveats

Most of these can improve with time and effort. The purpose of this section is
to document the current shortcomings of this tool.

* Exported methods are never obfuscated at the moment, since they could
  be required by interfaces. This area is a work in progress; see
  [#3](https://github.com/burrowers/garble/issues/3).

* Aside from `GOGARBLE` to select patterns of packages to obfuscate,
  there is no supported way to exclude obfuscating a selection of files or packages.
  More often than not, a user would want to do this to work around a bug; please file the bug instead.

* Go programs [are initialized](https://go.dev/ref/spec#Program_initialization) one package at a time,
  where imported packages are always initialized before their importers,
  and otherwise they are initialized in the lexical order of their import paths.
  Since garble obfuscates import paths, this lexical order may change arbitrarily.

* Go plugins are not currently supported; see [#87](https://github.com/burrowers/garble/issues/87).

* Garble requires `git` to patch the linker. That can be avoided once go-gitdiff
  supports [non-strict patches](https://github.com/bluekeyes/go-gitdiff/issues/30).

* APIs like [`runtime.GOROOT`](https://pkg.go.dev/runtime#GOROOT)
  and [`runtime/debug.ReadBuildInfo`](https://pkg.go.dev/runtime/debug#ReadBuildInfo)
  will not work in obfuscated binaries. This [can affect loading timezones](https://github.com/golang/go/issues/51473#issuecomment-2490564684), for example.

### Contributing

We welcome new contributors. If you would like to contribute, see
[CONTRIBUTING.md](CONTRIBUTING.md) as a starting point.
