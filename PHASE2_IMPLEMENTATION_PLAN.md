# Phase 2: Hybrid Lazy Decryption Table

## Status: 🚀 STARTED

## Architecture Overview

**Key Innovation:** Separate encryption (linker) from decryption (runtime init), keep hot path (entry()) clean.

### Components

#### 1. Linker Enhancement (cmd/link/internal/ld/pcln.go)
**File:** `internal/linker/patches/go1.25/0003-add-entryOff-feistel-table.patch`

**Tasks:**
- [x] Feistel encrypt (entryOff, nameOff) pairs
- [ ] Generate decryption table as new symbol: `runtime.feistelDecryptTable`
- [ ] Table format: `[]uint64` where each entry = `(encryptedOff << 32) | originalOff`
- [ ] Embed Feistel seed in table header (first 8 bytes)
- [ ] Pass table to runtime via linker symbol

**Table Structure:**
```
Offset | Size | Content
-------|------|----------------------------------------------------------
0x00   | 32   | Feistel seed (SHA-256 hash, for runtime decryption)
0x20   | 4    | Entry count (uint32)
0x24   | 4    | Flags (uint32): bit 0 = reversible mode
0x28   | 8*N  | Entries: [(encrypted_entryOff<<32)|original_entryOff, ...]
```

#### 2. Runtime Initialization (runtime/symtab.go)
**File:** `runtime_patch.go` → injects into `runtime/symtab.go`

**Tasks:**
- [ ] Add package-level variable: `var feistelLookupTable map[uint32]uint32`
- [ ] Inject `init()` function to populate table from linker symbol
- [ ] Read `runtime.feistelDecryptTable` symbol
- [ ] Parse seed from table header
- [ ] Decrypt all entries using Feistel
- [ ] Populate map: `encryptedOffset → originalOffset`

**Pseudo-code:**
```go
var feistelLookupTable map[uint32]uint32

func init() {
    // Read linker-generated table
    tableData := getLinkerSymbol("runtime.feistelDecryptTable")
    
    seed := tableData[0:32]
    count := binary.LittleEndian.Uint32(tableData[32:36])
    flags := binary.LittleEndian.Uint32(tableData[36:40])
    
    reversible := (flags & 0x01) != 0
    
    if reversible {
        // Derive Feistel keys
        keys := deriveFeistelKeys(seed)
        
        // Decrypt all entries
        feistelLookupTable = make(map[uint32]uint32, count)
        for i := 0; i < count; i++ {
            offset := 40 + i*16
            encEntryOff := binary.LittleEndian.Uint32(tableData[offset:])
            encNameOff := binary.LittleEndian.Uint32(tableData[offset+4:])
            
            origEntryOff, origNameOff := feistelDecrypt32Pair(encEntryOff, encNameOff, keys)
            
            feistelLookupTable[encEntryOff] = origEntryOff
            // Store nameOff mapping too if needed
        }
    } else {
        // Irreversible mode: no decryption possible
        feistelLookupTable = nil
    }
}
```

#### 3. Runtime Access (runtime/symtab.go - entry() method)
**File:** `runtime_patch.go` → modifies `entry()` method

**Tasks:**
- [ ] Modify `entry()` to check if encryption is active
- [ ] Simple map lookup instead of direct access
- [ ] Fallback to original value if not in map

**Modified entry():**
```go
func (f funcInfo) entry() uintptr {
    entryOff := f.entryOff
    
    // If Feistel table exists, lookup decrypted value
    if feistelLookupTable != nil {
        if decrypted, ok := feistelLookupTable[entryOff]; ok {
            entryOff = decrypted
        }
    }
    
    return f.datap.textAddr(entryOff)
}
```

**Why This Works:**
- ✅ No crypto in hot path (just map lookup)
- ✅ Map lookup is O(1) and fast
- ✅ No stack issues (simple conditional)
- ✅ Compatible with existing runtime

#### 4. Hash Function Update
**File:** `hash.go`

**Tasks:**
- [ ] Keep `feistelSeed()` function from Phase 1
- [ ] Used by both linker and runtime

#### 5. Main Entry Point
**File:** `main.go`

**Tasks:**
- [ ] Pass `feistelSeed()` to linker via environment
- [ ] Pass `-reversible` flag to linker
- [ ] No changes to garble CLI (flag already exists)

#### 6. Transformer Update
**File:** `transformer.go`

**Tasks:**
- [ ] Call `updateEntryOffset(file)` for `runtime/symtab.go`
- [ ] Inject Feistel helper functions into runtime package
- [ ] Inject init() function
- [ ] Inject modified entry() method

## Implementation Steps

### Step 1: Update Linker Patch ✏️ NEXT
**File:** Create new `0003-add-entryOff-feistel-table.patch`

1. Import Feistel functions from Phase 1
2. Generate encrypted metadata
3. Create table symbol with proper format
4. Link table into binary

### Step 2: Runtime Table Infrastructure
**File:** `runtime_patch.go`

1. Add Feistel cipher functions to runtime via AST
2. Add table lookup map variable
3. Inject init() function to populate table
4. Modify entry() to use table

### Step 3: Integration
**Files:** `hash.go`, `main.go`, `transformer.go`, `internal/linker/linker.go`

1. Wire environment variables
2. Connect linker to runtime
3. Test flag combinations

### Step 4: Testing
**Files:** `testdata/script/runtime_metadata.txtar`, new tests

1. Test reversible mode (-reversible)
2. Test irreversible mode (default)
3. Test runtime.FuncForPC still works
4. Benchmark overhead (expect ~0 in hot path)

## Success Criteria

- [ ] Linker generates Feistel-encrypted metadata
- [ ] Runtime init() successfully decrypts table
- [ ] entry() uses table lookup (no crashes)
- [ ] runtime.FuncForPC works correctly
- [ ] All existing tests pass
- [ ] New integration tests pass
- [ ] Performance: <5% overhead compared to baseline

## Advantages Over Phase 1

| Aspect | Phase 1 | Phase 2 |
|--------|---------|---------|
| Crypto in entry() | ❌ Causes crash | ✅ None (table lookup) |
| Stack safety | ❌ morestack on g0 | ✅ Safe map access |
| Performance | ❌ N/A (crashes) | ✅ O(1) map lookup |
| Runtime APIs | ❌ Broken | ✅ Working |
| Complexity | 🔴 High (inline crypto) | 🟢 Low (init once) |

## Current Status

**Phase 1:** ✅ Complete - Feistel cipher tested (8/8 tests pass)  
**Phase 2:** 🚀 Starting - Hybrid table approach  

**Next Action:** Create linker patch to generate decryption table
