# Literal Encryption

**Last updated:** January 2025
**Status:** Hardened and production-ready

This document describes how Garble protects literals when the `-literals` flag
is enabled. It explains the obfuscation pipeline and the available strategies
so security reviewers can reason about coverage and stealth.

## Goals

- Keep plaintext strings, byte slices, and `-ldflags -X` payloads out of the
  final binary.
- Guarantee deterministic output when the same seed and nonce are supplied.
- Generate **no fixed cryptographic constants** in the output binary that
  signature scanners (findcrypt, YARA rules) could match.
- Apply layered transforms mixing substitution, permutation, and arithmetic
  obfuscation.

## Design Principles

The literal encryption pipeline is designed with **stealth-first** philosophy:

1. **No detectable crypto signatures**: Unlike AES S-boxes or ASCON IVs, all
   cipher parameters are randomly generated per build. Every build produces
   a unique S-box permutation via Fisher-Yates shuffle.
2. **Per-build randomness**: The PRNG seed drives all parameter generation,
   so deterministic builds are still possible with `-seed`.
3. **Strategy diversity**: Multiple obfuscation strategies are randomly
   selected, preventing pattern-matching on a single approach.

## Literal Transformation Pipeline

Literal obfuscation is orchestrated by `literals.Builder` (`internal/literals/literals.go`):

1. `transformer` constructs a builder per file.
2. Constant declarations that can safely become variables are rewritten so they
   can flow through the standard obfuscators.
3. Every literal expression is replaced with a closure that:
   - Obtains deterministic randomness from `obfRand`
   - Selects an obfuscation strategy (weighted random)
   - Emits inline decode code
   - Returns the runtime value
4. `-ldflags=-X` assignments are rewritten into an `init` function that routes
   through the same builder, guaranteeing encrypted injected strings.

## Obfuscation Strategies

`internal/literals/obfuscators.go` registers multiple strategies with weighted
selection to provide defence in depth.

### Custom Cipher (primary, ~60% selection weight)

- Implemented in `internal/literals/custom_cipher.go` and
  `internal/literals/custom_cipher_obfuscator.go`.
- Uses a **per-build random 256-byte S-box** generated via Fisher-Yates shuffle.
- Applies a multi-round substitution-permutation network:
  1. **Substitution**: Each byte passes through the random S-box.
  2. **Diffusion**: CBC-like chaining with per-round random key bytes.
- Rounds vary between 4-6 per invocation for added diversity.
- **No fixed constants**: The S-box, inverse S-box, and round keys are all
  embedded as literal arrays in the generated code. Since they are random per
  build, no signature scanner can match them.
- **Polymorphic variable names**: Every decryption stub uses randomly generated
  variable names (e.g. `_a3x`, `_q7m`) instead of predictable names. This
  breaks pattern-matching heuristics in decompilers and deobfuscation scripts.
- **Mixed Boolean-Arithmetic (MBA)**: XOR operations in the decryption stubs
  are randomly replaced with algebraically equivalent MBA expressions:
  - `a ^ b` may become `(a | b) - (a & b)` or `(a + b) - 2*(a & b)`
  - This changes the instruction-level pattern in compiled binaries, making
    pattern-based detection of decryption loops harder for automated tools.
- External keys may be mixed in for additional obfuscation.

### Swap

- Implemented in `internal/literals/swap.go`.
- Generates random swap position pairs and reverses them at runtime.
- O(n) decode with index-based unshuffling.

### Split

- Implemented in `internal/literals/split.go`.
- Splits data into random-sized chunks, each independently scrambled.
- Reassembled at runtime via concatenation.

### Shuffle

- Implemented in `internal/literals/shuffle.go`.
- Applies a random permutation to byte positions.
- Decoded via inverse permutation lookup at runtime.

### Seed

- Implemented in `internal/literals/seed.go`.
- Uses a seed-based PRNG to generate XOR masks.
- Lightweight and fast for small literals.

### External keys

All strategies may introduce external keys (`obfuscators.go`). These are
deterministically generated integers (uint8-uint64) threaded through lambda
parameters. At decode time they:

- Provide extra entropy for arithmetic scramblers.
- Force the generated closure to accept seemingly unrelated arguments, making
  static analysis harder.
- Optionally hide their values behind the proxy dispatcher, so the literal's
  true key bits do not appear as constants.

## Strategy Selection

Strategies are selected via **weighted random** selection from the registry:

| Strategy | Weight | Approximate Probability |
|----------|--------|------------------------|
| cipher   | 6      | ~60%                   |
| swap     | 1      | ~10%                   |
| split    | 1      | ~10%                   |
| shuffle  | 1      | ~10%                   |
| seed     | 1      | ~10%                   |

The custom cipher handles the majority of literals for strong protection,
while lightweight strategies add diversity to prevent pattern recognition.

## Determinism and Seeds

- Providing both `-seed` and `GARBLE_BUILD_NONCE` yields byte-identical
  binaries. Every literal uses the same PRNG sequence across deterministic
  rebuilds.
- Garble generates a random seed per build when no explicit `-seed` is given,
  keeping each build unique while remaining deterministic within that build.

## Testing

The literal pipeline is validated by a mix of unit, integration, and fuzz tests:

- `go test ./internal/literals` exercises the builder, custom cipher
  roundtrips, strategy selection, and all obfuscator paths.
- `internal/literals/custom_cipher_test.go` verifies encrypt/decrypt
  roundtrips, S-box permutation validity, inline code generation, absence
  of known crypto constants, MBA algebraic equivalence for all 256x256
  byte pairs, polymorphic code generation across seeds, and variable
  name uniqueness.
- `internal/literals/fuzz_test.go` runs `FuzzObfuscate` to catch decode
  mismatches under random inputs.
- `go test -fuzz=FuzzObfuscate -fuzztime=30s ./internal/literals` is
  recommended for CI hardening.

## Operational Guidance

- Enable `-literals` for any build that ships outside your organisation.
- Pair it with `-controlflow=auto` and `-tiny` for the strongest default posture
  (a random seed is generated per build by default).
- Use `-force-rename` to also rename exported methods (may break interface
  satisfaction in some cases).
- Packages with low-level compiler directives (for example `//go:nosplit`) skip
  literal obfuscation; Garble logs the first triggering directive and position.

## References

- `internal/literals/custom_cipher.go` - Custom cipher implementation.
- `internal/literals/custom_cipher_obfuscator.go` - Strategy wrapper.
- `internal/literals/obfuscators.go` - Strategy registry and external keys.
- `internal/literals/strategy_registry.go` - Weighted strategy selection.
- `docs/SECURITY.md` - Threat model for literal protection.
