# Literal Encryption

**Last updated:** 27 October 2025  
**Status:** Hardened and production-ready

This document describes how Garble protects literals when the `-literals` flag
is enabled. It explains key derivation, the obfuscation pipeline, and the
available strategies so security reviewers can reason about coverage and
determinism across Linux and Windows builds.

## Goals

- Keep plaintext strings, byte slices, and `-ldflags -X` payloads out of the
  final binary.
- Guarantee deterministic output when the same seed and nonce are supplied.
- Mix in per-file entropy so repeating literals never reuse the exact key pair.
- Fall back to reversible transforms when explicitly requested via
  `-reversible`, while keeping the irreversible pipeline the default.

## Key Derivation

Key material is produced by `literals.NewHKDFKeyProvider` (see
`internal/literals/key_provider.go`). The provider:

1. Receives a master secret from `transformer.newLiteralKeyProvider`
   (`transformer.go:1246`).  
   - With `-seed`, the secret is `combineSeedAndNonce(seed, nonce)`.
   - Without `-seed`, the package’s `GarbleActionID` hash acts as the master.
2. Copies the package-level salt (`GarbleActionID`) and file identifier
   (a slashified relative path) into HKDF’s `info`.
3. Calls `hkdf.Extract` and `hkdf.Expand` with SHA-256, deriving 32 bytes per
   request, split into:
   - 16 bytes: ASCON-128 key
   - 16 bytes: Nonce

The HKDF `info` structure encodes:

```
context || 0x00 || packageSalt || 0x00 || fileID || 0x00 || counter
```

Two context strings are used to provide domain separation:

- `garble/literals/ascon:v1` for authenticated encryption
- `garble/literals/irreversible:v1` for irreversible subkeys

Each literal increments the counter, ensuring per-literal uniqueness while
remaining reproducible within the same seed/nonce build.

## Literal Transformation Pipeline

Literal obfuscation is orchestrated by `literals.Builder` (`internal/literals/literals.go`):

1. `transformer` constructs a builder per file with the HKDF provider.
2. Constant declarations that can safely become variables are rewritten so they
   can flow through the standard obfuscators.
3. Every literal expression is replaced with a closure that:
   - Obtains deterministic randomness from `obfRand`
   - Selects an obfuscation strategy
   - Emits inline decode code
   - Calls the inline helper and returns the runtime value
4. `-ldflags=-X` assignments are rewritten into an `init` function that routes
   through the same builder (`transformer.go:1285`), guaranteeing encrypted
   injected strings.

## Obfuscation Strategies

`internal/literals/obfuscators.go` registers multiple strategies to provide
defence in depth. The primary options are:

### ASCON-128 (default path)

- Implemented in `internal/literals/ascon_obfuscator.go`.
- Pulls a fresh key/nonce via HKDF for every literal.
- Mixes deterministic “external keys” (opaque integers carried through closure
  parameters) into the key and nonce before encryption so two identical literals
  still yield different ciphertext.
- Encrypts data using the inlined ASCON implementation (`internal/literals/ascon_inline.go`).
- Emits runtime code:
  1. Calls the inline decrypt helper with embedded key, nonce, and ciphertext.
  2. Verifies the authentication tag.
  3. Returns the plaintext (slicing away junk padding for strings).
- Panics if authentication fails, signalling tampering or decode errors.

### Irreversible simple transforms

- Implemented across `simple.go`, `shuffle.go`, `swap.go`, `split.go`, and
  friends.
- Used for specialised cases and as fallbacks when ASCON is not selected.
- Each strategy rewrites the literal through deterministic arithmetic,
  shuffling, or Feistel-style mixes using HKDF-derived material.
- When `-reversible` is **disabled** (production default), helpers from
  `irreversible_inline.go` add additional Feistel rounds and S-box substitution
  so the decode path does not reveal the original data in a single step.

### Reversible mode

- `-reversible` flips a package-level switch (`internal/literals/literals.go:38`)
  allowing the reversible obfuscator to be chosen, ensuring compatibility with
  `garble reverse`. Security reviewers should treat this as a deliberate
  downgrade for debugging only.

### External keys

All strategies may introduce “external keys” (`obfuscators.go:152`). These are
deterministically generated integers (uint8–uint64) threaded through lambda
parameters. At decode time they:

- Provide extra entropy for arithmetic scramblers.
- Force the generated closure to accept seemingly unrelated arguments, making
  static analysis harder.
- Optionally hide their values behind the proxy dispatcher, so the literal’s
  true key bits do not appear as constants.

## Determinism and Seeds

- Providing both `-seed` and `GARBLE_BUILD_NONCE` yields byte-identical
  binaries.  
  HKDF draws from `combineSeedAndNonce`, so every literal uses the same key
  material across deterministic rebuilds.
- Without a seed, the package’s `GarbleActionID` guarantees stability within a
  build while still being unique per compilation.
- HKDF state lives entirely in memory; no key material is written to disk.

## Testing

The literal pipeline is validated by a mix of unit, integration, and fuzz
tests:

- `go test ./internal/literals` exercises the HKDF provider, ASCON encode/decode
  paths, reversible helpers, and builder behaviour.
- `internal/literals/ascon_obfuscator_test.go` checks per-literal authenticity,
  external key mixing, and the inline decrypt helper.
- `internal/literals/fuzz_test.go` runs `FuzzObfuscate` to catch decode
  mismatches under random inputs.
- `go test -fuzz=FuzzObfuscate -fuzztime=30s ./internal/literals` (from
  `Agents.md`) is recommended for CI hardening.

When reviewing production builds, also run `go test ./...` and the race-detector
variant to ensure deterministic HKDF usage under concurrency.

## Operational Guidance

- Enable `-literals` for any build that ships outside your organisation.
- Pair it with `-controlflow=auto` and `-seed=random` for the strongest default
  posture.
- Keep `-reversible` off in production; only enable it when you need
  `garble reverse` for debugging.
- Treat ASCON authentication failures as tampering indicators—the binary will
  panic with a clear `garble: literal authentication failed` message.

## References

- `transformer.go:1246` – Key provider hook-up.
- `internal/literals/key_provider.go` – HKDF implementation.
- `internal/literals/ascon_obfuscator.go` – ASCON backend.
- `internal/literals/obfuscators.go` – Strategy registry and external keys.
- `docs/SECURITY.md` – Threat model for literal protection.
