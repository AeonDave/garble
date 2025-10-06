# Phase 2 Runtime Patch Implementation

## Runtime Modifications Required

### 1. Add Feistel Functions to Runtime Package
Inject into `runtime/symtab.go` (or separate file):

```go
// Feistel cipher for runtime metadata decryption
func feistelRound(right uint32, key []byte) uint32 {
    h := fnv.New32a()
    var buf [4]byte
    binary.LittleEndian.PutUint32(buf[:], right)
    h.Write(buf[:])
    h.Write(key)
    return h.Sum32()
}

func feistelDecrypt32Pair(left, right uint32, keys [4][]byte) (uint32, uint32) {
    for i := 3; i >= 0; i-- {
        newRight := left
        newLeft := right ^ feistelRound(left, keys[i])
        left = newLeft
        right = newRight
    }
    return left, right
}

func deriveFeistelKeys(baseSeed []byte) [4][]byte {
    var keys [4][]byte
    for i := 0; i < 4; i++ {
        h := fnv.New32a()
        h.Write(baseSeed)
        h.Write([]byte("round_"))
        h.Write([]byte{byte('0' + i)})
        keys[i] = h.Sum(nil)
    }
    return keys
}
```

### 2. Add Global Lookup Table
```go
// Global decryption map: encrypted offset → original offset
var feistelLookupTable map[uint32]uint32
var feistelNameLookupTable map[uint32]uint32
```

### 3. Inject init() Function
```go
func init() {
    // Check if table symbol exists (may not exist in non-reversible mode)
    tableData := //go:linkname getSymbol runtime.feistelDecryptTable
    if tableData == nil {
        return
    }
    
    // Parse table header
    seed := tableData[0:32]
    entryCount := binary.LittleEndian.Uint32(tableData[32:36])
    flags := binary.LittleEndian.Uint32(tableData[36:40])
    
    reversible := (flags & 0x01) != 0
    if !reversible {
        return
    }
    
    // Derive Feistel keys from seed
    keys := deriveFeistelKeys(seed)
    
    // Initialize maps
    feistelLookupTable = make(map[uint32]uint32, entryCount)
    feistelNameLookupTable = make(map[uint32]uint32, entryCount)
    
    // Decrypt all entries
    offset := 40
    for i := uint32(0); i < entryCount; i++ {
        encEntryOff := binary.LittleEndian.Uint32(tableData[offset:])
        origEntryOff := binary.LittleEndian.Uint32(tableData[offset+4:])
        encNameOff := binary.LittleEndian.Uint32(tableData[offset+8:])
        origNameOff := binary.LittleEndian.Uint32(tableData[offset+12:])
        
        feistelLookupTable[encEntryOff] = origEntryOff
        feistelNameLookupTable[encNameOff] = origNameOff
        
        offset += 16
    }
}
```

### 4. Modify entry() Method
```go
// Original:
// func (f funcInfo) entry() uintptr {
//     return f.datap.textAddr(f.entryOff)
// }

// Modified:
func (f funcInfo) entry() uintptr {
    entryOff := f.entryOff
    
    // Decrypt if table exists
    if feistelLookupTable != nil {
        if decrypted, ok := feistelLookupTable[entryOff]; ok {
            entryOff = decrypted
        }
    }
    
    return f.datap.textAddr(entryOff)
}
```

## Implementation Strategy

The challenge is that we need to inject complex code into the runtime via AST manipulation.

### Option A: Full AST Generation (Current Approach - Complex)
Generate all code as AST nodes in `runtime_patch.go`

**Pros:**
- Pure Go, no external tools
- Follows existing pattern

**Cons:**
- Extremely verbose (100s of lines of AST for simple code)
- Hard to maintain
- Error-prone

### Option B: Template-based Injection (Recommended for Phase 2)
1. Write actual Go code in a template file
2. Parse it to AST
3. Inject parsed AST into target file

**Pros:**
- Write normal Go code
- Easy to read and maintain
- Less error-prone

**Cons:**
- Need to parse Go code at build time

### Option C: Source Code Patch (Simplest)
Create a proper Git patch like the linker, but for runtime files

**Pros:**
- Standard approach (same as linker)
- No AST manipulation needed
- Easy to review and maintain

**Cons:**
- More fragile to Go version changes
- Need separate patch per Go version

## Recommendation

For Phase 2, use **Option C** (Source Code Patch) because:
1. Linker already uses this approach successfully
2. We're already creating patches for different Go versions
3. Much simpler than AST manipulation for complex code
4. The runtime code is relatively stable between versions

We'll create:
- `internal/runtime/patches/go1.25/0001-add-feistel-decryption.patch`

This patch will modify `runtime/symtab.go` to add all the necessary code.

## Next Steps

1. Create runtime patch file
2. Add runtime patch loading to transformer
3. Test with reversible mode
4. Verify runtime APIs still work
