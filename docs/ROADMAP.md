# Roadmap

Future improvements and research directions for garble hardened.

---

## Planned

### Polymorphic variable names in all strategies

The swap, split, shuffle, and seed literal strategies still use a fixed variable
name (`data`). Extending the polymorphic naming from the custom cipher to all
strategies would eliminate the last predictable identifier across the entire
literal encryption pipeline.

**Complexity**: Low  
**Impact**: Moderate — completes coverage for the remaining ~40% of literal sites

### Opaque predicates in literal decryption stubs

Inject always-true/false branches directly into decryption stub code blocks.
Currently opaque predicates are only used in control-flow flattening, not in
`-literals` stubs. Adding them would confuse emulation boundary detection.

**Complexity**: Medium  
**Impact**: High — forces emulators to handle unreachable paths or risk incorrect results

### Decryption stub splitting

Split a single decryption sequence across multiple generated functions instead of
emitting it as one contiguous block. Emulation-based tools assume decryption happens
in a single basic block sequence; splitting breaks this assumption.

**Complexity**: Medium  
**Impact**: High — Unicorn-based tools would need to follow cross-function calls

### Instruction reordering

Where statements are order-independent (e.g., independent variable assignments),
randomly permute their order. This adds variation without changing semantics.

**Complexity**: Low  
**Impact**: Low-to-moderate — adds entropy to instruction layout

---

## Evaluated and deferred

### Anti-emulation checks

Detect Unicorn or other emulators at runtime and return garbage data.

**Why deferred**: Adds runtime overhead, risks false positives on uncommon hardware
or sandboxed environments, and provides limited benefit against sophisticated
attackers who can patch the checks out.

### VM-based obfuscation

Replace decryption stubs with bytecode interpreted by a custom virtual machine.

**Why deferred**: Extremely high implementation complexity, severe performance cost,
and the VM interpreter itself becomes a target for analysis. Not justified given
the current threat model.

### Decryption key spreading

Derive decryption keys from runtime state (goroutine ID, stack depth, timing)
instead of embedding them inline.

**Why deferred**: Breaks deterministic builds, complicates caching, and introduces
fragile dependencies on runtime internals that may change across Go versions.

---

## Known limitations (fundamental to Go)

These cannot be fixed without patching the Go runtime or compiler:

- **`runtime.slicebytetostring` anchor**: All `[]byte → string` conversions go
  through this function. Emulation-based tools use it to locate decryption sites.
- **`pclntab` / `moduledata`**: Go runtime metadata structures that survive
  stripping. Required by the runtime for stack unwinding and garbage collection.
- **Compile-time constants**: Array sizes, `case` labels, `iota` expressions
  must remain as plaintext literals — Go's type system requires them at compile time.
