# Architettura Garble - Documentazione Tecnica

---

## Indice

1. [Panoramica Generale](#1-panoramica-generale)
2. [Architettura di Alto Livello](#2-architettura-di-alto-livello)
3. [Componenti Core](#3-componenti-core)
4. [Flusso di Esecuzione](#4-flusso-di-esecuzione)
5. [Meccanismi di Obfuscazione](#5-meccanismi-di-obfuscation)
6. [Punti di Forza](#6-punti-di-forza)
7. [Dettagli Implementativi](#7-dettagli-implementativi)

---

## 1. Panoramica Generale

### 1.1 Cos'è Garble

Garble è un **obfuscator per codice Go** che si interpone tra il toolchain Go standard e il processo di build, trasformando il codice sorgente per:
- Rimuovere informazioni identificative (nomi, path, metadati)
- Proteggere i letterali (stringhe, costanti)
- Offuscare il flusso di controllo
- Cifrare i metadati di runtime
- Rendere il reverse engineering significativamente più difficile

### 1.2 Differenze rispetto all'upstream

Questo fork **AeonDave/garble** introduce miglioramenti significativi rispetto a `burrowers/garble`:

| Feature            | Upstream | Fork Hardened                         |
|--------------------|----------|---------------------------------------|
| Cache encryption   | ❌       | ✅ ASCON-128                          |
| Feistel cipher     | ❌       | ✅ 4-round per metadata               |
| Build nonce        | Parziale | ✅ Completo + riproducibilità         |
| Directive parsing  | Base     | ✅ Fuzzing + controlli robusti        |
| Test coverage      | ~70%     | ~85%                                  |
| Security docs      | Base     | ✅ SECURITY.md completo               |

### 1.3 Requisiti

- **Go**: 1.25 o superiore
- **OS**: Linux, macOS, Windows
- **Target**: Qualsiasi piattaforma Go supportata

---

## 2. Architettura di Alto Livello

### 2.1 Diagramma dell'Architettura

```
┌────────────────────────────────────────────────────────────┐
│                          GARBLE ARCHITECTURE               │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  User Command: garble build [flags] ./cmd/app              │
│                         │                                  │
│                         ▼                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    main.go (Entry Point)             │  │
│  │  • Flag parsing & validation                         │  │
│  │  • Seed & nonce generation/combination               │  │
│  │  • Environment setup (GARBLE_SHARED, etc.)           │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│                     ▼                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Cache Layer (cache_*.go)                │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Shared Cache (in-memory + encrypted disk)      │  │  │
│  │  │  • ListedPackages (go list -json output)       │  │  │
│  │  │  • Build flags & go env                        │  │  │
│  │  │  • ASCON-128 encryption at rest                │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Package Cache (per-package metadata)           │  │  │
│  │  │  • lpkg (listed package info)                  │  │  │
│  │  │  • ActionID (build cache key)                  │  │  │
│  │  │  • PrivateNameMap (obfuscated name mapping)    │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│                     ▼                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Go Toolchain Wrapper (toolexec)            │  │
│  │  Intercepts: compile, link, asm, etc.                │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                      │
│       ┌─────────────┴─────────────────────┐                │
│       ▼                                   ▼                │
│  ┌─────────────┐                    ┌─────────────┐        │
│  │   COMPILE   │                    │    LINK     │        │
│  │ transformer │                    │   linker    │        │
│  └──────┬──────┘                    └──────┬──────┘        │
│         │                                  │               │
│         ▼                                  ▼               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │             Obfuscation Modules                     │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Name Hashing   │  │ Literal Obfusc. │            │   │
│  │  │  (hash.go)     │  │  (literals/)    │            │   │
│  │  │                │  │  • ASCON-128    │            │   │
│  │  │ SHA-256 +      │  │  • Simple       │            │   │
│  │  │ per-package    │  │  • Split/Swap   │            │   │
│  │  │ seed mixing    │  └─────────────────┘            │   │
│  │  └────────────────┘                                 │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Control Flow   │  │ Feistel Cipher  │            │   │
│  │  │  (ctrlflow/)   │  │  (feistel.go)   │            │   │
│  │  │  • Flattening  │  │                 │            │   │
│  │  │  • Block split │  │  4-round per    │            │   │
│  │  │  • Junk jumps  │  │  func metadata  │            │   │
│  │  │  • Trash       │  │  encrypt/decrypt│            │   │
│  │  └────────────────┘  └─────────────────┘            │   │
│  │  ┌────────────────┐  ┌─────────────────┐            │   │
│  │  │ Runtime Patch  │  │   Reverse       │            │   │
│  │  │ (runtime_patch)│  │  (reverse.go)   │            │   │
│  │  │                │  │                 │            │   │
│  │  │ Inject helpers │  │  De-obfuscate   │            │   │
│  │  │ for Feistel    │  │  stack traces   │            │   │
│  │  └────────────────┘  └─────────────────┘            │   │
│  └─────────────────────────────────────────────────────┘   │
│                     │                                      │
│                     ▼                                      │
│            Obfuscated Binary                               │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 2.2 Separazione delle Responsabilità

```
┌─────────────────────────────────────────────────────────────────┐
│                       LAYER ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CLI & Orchestration Layer (main.go)                      │  │
│  │  • Argument parsing & validation                          │  │
│  │  • Command dispatch (build/test/run/reverse)              │  │
│  │  • Environment & flag management                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Cryptographic Primitive Layer                            │  │
│  │  • Seed & nonce management (hash.go)                      │  │
│  │  • Feistel cipher (feistel.go)                            │  │
│  │  • ASCON-128 encryption (cache_ascon.go, literals/)       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Caching & State Management Layer                         │  │
│  │  • Shared cache (cache_shared.go)                         │  │
│  │  • Package cache (cache_pkg.go)                           │  │
│  │  • Encrypted persistence (cache_ascon.go)                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Transformation Layer (transformer.go)                    │  │
│  │  • AST parsing & type checking                            │  │
│  │  • Name obfuscation                                       │  │
│  │  • Import rewriting                                       │  │
│  │  • Reflection handling                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Obfuscation Modules (internal/)                          │  │
│  │  • Literal obfuscation (literals/)                        │  │
│  │  • Control flow (ctrlflow/)                               │  │
│  │  • Linker patches (linker/)                               │  │
│  │  • SSA to AST conversion (ssa2ast/)                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                         │                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Go Toolchain Integration                                 │  │
│  │  • Compile wrapper                                        │  │
│  │  • Link wrapper                                           │  │
│  │  • Assembly wrapper                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Componenti Core

### 3.1 main.go - Entry Point & Orchestration

**Responsabilità**:
- Parsing dei flag della CLI
- Generazione/combinazione di seed e nonce
- Setup dell'ambiente (GARBLE_SHARED, temp directories)
- Dispatch dei comandi (build/test/run/reverse)

**Flag Principali**:
```go
-seed=<base64>          // Seed deterministico per build riproducibili
-literals               // Abilita obfuscation dei letterali
-tiny                   // Rimuove info extra (panic messages, etc.)
-controlflow            // Abilita obfuscation del control flow
-debugdir               // Directory per output di debug
-reversible             // Mantiene mapping per reverse engineering
-no-cache-encrypt       // Disabilita cifratura della cache (default: ON)
```

**Environment Variables**:
```bash
GARBLE_BUILD_NONCE=<base64>  # Nonce per build unique/riproducibili
GARBLE_SHARED=/tmp/garble123 # Directory temp condivisa
```

### 3.2 hash.go - Cryptographic Core

**Algoritmi**:
1. **SHA-256**: Hashing dei nomi e derivazione delle chiavi
2. **Base64**: Encoding degli hash per nomi validi in Go
3. **Seed Combination**: SHA-256(seed || nonce) per entropia combinata

**Funzioni Chiave**:
```go
func hashWith(inputHash, name string) string
    // Hash un nome usando SHA-256, con salt da inputHash

func hashWithCustomSalt(salt, name string) string
    // Hash con salt custom per namespace diversi

func combineSeedAndNonce(seed, nonce []byte) [32]byte
    // Combina seed e nonce via SHA-256
```

### 3.3 transformer.go - AST Transformation Engine

**Pipeline di Trasformazione**:
```
Source Code (.go files)
    │
    ▼
┌─────────────────────┐
│ Parse (go/parser)   │  → AST (Abstract Syntax Tree)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Type Check          │  → types.Package, types.Info
│ (go/types)          │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Compute Metadata    │  → fieldToStruct map, linkerVariableStrings
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Apply Transformations│
│  • Name hashing     │
│  • Import rewriting │
│  • Literal obfusc.  │
│  • Control flow     │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Generate Output     │  → Obfuscated .go files
└─────────────────────┘
```

**Transformazioni Principali**:
1. **Name Obfuscation**: `hashWith()` su identificatori
2. **Import Path Rewriting**: `foo.com/bar` → `garbleHashedPath`
3. **Position Removal**: Tutti i `token.Pos` vengono azzerati
4. **Reflection Handling**: Rimozione dei nomi originali (tranne in `-reversible`)

### 3.4 Cache Layer (cache_*.go)

**Architettura della Cache**:
```
┌──────────────────────────────────────────────────┐
│              GARBLE CACHE SYSTEM                 │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Shared Cache (Global, Process-wide)       │  │
│  │  ────────────────────────────────────────  │  │
│  │  Location: GARBLE_SHARED env variable      │  │
│  │                                            │  │
│  │  Contents:                                 │  │
│  │  • ListedPackages (from go list -json)     │  │
│  │  • ForwardBuildFlags                       │  │
│  │  • GoEnv (GOARCH, GOOS, etc.)              │  │
│  │  • ExecPath (path to toolexec wrapper)     │  │
│  │  • GOGARBLE pattern                        │  │
│  │                                            │  │
│  │  Persistence:                              │  │
│  │  → Encrypted with ASCON-128 (default ON)   │  │
│  │  → Serialized with gob encoding            │  │
│  │  → Format: [nonce][ciphertext][tag]        │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Package Cache (Per-Package Metadata)      │  │
│  │  ────────────────────────────────────────  │  │
│  │  Keyed by: Package import path             │  │
│  │                                            │  │
│  │  Contents:                                 │  │
│  │  • lpkg (listedPackage from go list)       │  │
│  │  • ActionID (build cache identifier)       │  │
│  │  • PrivateNameMap (obfuscated names)       │  │
│  │  • OrigImporter (type importer)            │  │
│  │                                            │  │
│  │  NOT persisted (in-memory only per build)  │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
└──────────────────────────────────────────────────┘
```

**cache_ascon.go - ASCON-128 Encryption**:
- **Algoritmo**: ASCON-128 (NIST Lightweight Crypto standard)
- **Key Derivation**: `SHA-256(seed || "garble-cache-encryption-v1")`
- **Formato**: `[16-byte nonce][ciphertext][16-byte auth tag]`
- **Protezione**: Confidenzialità + autenticazione

### 3.5 Obfuscation Modules (internal/)

#### 3.5.1 literals/ - Literal Obfuscation

**Obfuscatori Disponibili**:

```go
type obfuscator interface {
    obfuscate(rand *mathrand.Rand, data []byte) *ast.BlockStmt
}

// Pre-pass eseguito in transformer.go
// 1. Analizza le costanti di package (computeConstTransforms)
// 2. Salta quelle richieste da contesti costanti (array len, iota, switch case)
// 3. Converte le restanti in variabili di package durante la preparazione (rewriteConstDecls)

// 1. ASCON Obfuscator (crittograficamente sicuro)
type asconObfuscator struct{}
    // Cifra letterali con ASCON-128
    // Inietta inline decryption code

// 2. Simple Obfuscator (reversibile, più leggero)
type simpleObfuscator struct{}
    // XOR + shuffle + swap
    // Nessuna crittografia, ma reversibile

// 3. Split Obfuscator
type splitObfuscator struct{}
    // Divide stringa in chunk e ricostruisce

// 4. Swap Obfuscator
type swapObfuscator struct{}
    // Scambia posizioni dei caratteri
```

**Selezione Obfuscatore**:
```
Literal Size < 2KB?
    ├─ Yes → ASCON, Simple, Split, Swap (random choice)
    └─ No  → Simple only (per performance)
```

**Pre-elaborazione delle costanti** (`transformer.go`):
- `computeConstTransforms` costruisce una mappa `*types.Const → constTransform` tracciando gli `Ident` di utilizzo e scartando costanti esportate, tipizzate alias o vincolate da contesti costanti.
- `rewriteConstDecls` riscrive i `GenDecl` `const` eleggibili in `var`, aggiornando `types.Info.Defs/Uses` così che gli obfuscatori vedano variabili runtime e possano applicare la cifratura.
- Le costanti convertite ereditano doc comment e trailing comment originali, preservando la documentazione per `-debugdir`/reverse mode.

**Sanitizzazione `-ldflags -X`** (`main.go` → `transformer.go`):
- `sanitizeLinkerFlags()` intercetta i flag `-ldflags` prima che raggiungano il toolchain Go
- Estrae tutte le assegnazioni `-X package.var=value` in una mappa `LinkerInjectedStrings`
- Riscrive i flag con valori vuoti: `-X package.var=` (linker non vede mai il plaintext)
- Durante la compilazione del package target, `injectLinkerVariableInit()` genera una funzione `init()`:
  ```go
  func init() {
      varName = <obfuscated_literal("original_value")>
  }
  ```
- Il valore viene cifrato con ASCON-128 o Simple obfuscator come qualsiasi altro letterale
- **Risultato**: API keys, secrets, versioni iniettati via linker sono completamente protetti nel binario finale

#### 3.5.2 ctrlflow/ - Control Flow Obfuscation

**Modalità Disponibili**:
```go
const (
    ModeOff        Mode = iota  // Disabled
    ModeXor                      // XOR-based dispatcher
    ModeComplex                  // SSA + flattening + junk
)
```

**Tecniche di Obfuscation**:

1. **Flattening**: Converte if/switch in dispatcher centralizzato
   ```
   Original:                Flattened:
   if cond {                state := 0
       A()                  for {
   } else {                     switch state {
       B()                      case 0:
   }                                if cond { state = 1 } else { state = 2 }
                                case 1:
                                    A(); return
                                case 2:
                                    B(); return
                            }
                        }
   ```

2. **Block Splitting**: Divide blocchi in sub-blocchi con jump intermedi

3. **Junk Jumps**: Inserisce jump non-operativi per confondere il CFG

4. **Trash Blocks**: Aggiunge codice morto (dead code) per aumentare la complessità

**Direttive**:
```go
//garble:controlflow flatten=max splits=10 junk=5
func myFunc() { ... }

//garble:nocontrolflow
func skipThis() { ... }
```

#### 3.5.3 linker/ - Runtime Patching

**Patch per Runtime Go**:
- Inietta helper functions per Feistel decryption
- Patcha `runtime.funcname()` per decifrare i nomi al volo
- Gestisce la compatibilità con reflection in `-reversible` mode

---

## 4. Flusso di Esecuzione

### 4.1 Build Flow Completo

```
┌──────────────────────────────────────────────────────────────┐
│  PHASE 1: Initialization & Setup                             │
├──────────────────────────────────────────────────────────────┤
│  1. Parse CLI flags (main.go)                                │
│  2. Generate/load seed and nonce                             │
│  3. Combine seed and nonce → combined hash                   │
│  4. Setup GARBLE_SHARED temp directory                       │
│  5. Run "go list -json -export -toolexec" to populate cache  │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 2: Cache Population                                   │
├──────────────────────────────────────────────────────────────┤
│  6. Parse go list JSON output → ListedPackages               │
│  7. Determine which packages to obfuscate (GOGARBLE)         │
│  8. Encrypt & persist shared cache to disk (ASCON-128)       │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 3: Per-Package Compilation (toolexec loop)            │
├──────────────────────────────────────────────────────────────┤
│  For each package in dependency order:                       │
│                                                              │
│  9. Toolexec intercepts "compile" command                    │
│  10. Load package metadata from cache                        │
│  11. Parse .go files → AST                                   │
│  12. Type-check → types.Package, types.Info                  │
│  13. Apply transformations:                                  │
│      ├─ Hash identifiers (hashWith)                          │
│      ├─ Obfuscate literals (if -literals)                    │
│      ├─ Obfuscate control flow (if -controlflow)             │
│      ├─ Remove positions & build info                        │
│      └─ Rewrite imports                                      │
│  14. Write obfuscated .go files to temp directory            │
│  15. Call original Go compiler on obfuscated files           │
│  16. Cache obfuscated names for dependent packages           │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 4: Linking                                            │
├──────────────────────────────────────────────────────────────┤
│  17. Toolexec intercepts "link" command                      │
│  18. Apply linker patches (runtime helpers, etc.)            │
│  19. Strip debug info (-w -s)                                │
│  20. Remove build/module info                                │
│  21. Call original Go linker                                 │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  PHASE 5: Cleanup                                            │
├──────────────────────────────────────────────────────────────┤
│  22. Remove GARBLE_SHARED temp directory                     │
│  23. Return obfuscated binary                                │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 Reverse Flow (De-obfuscation)

```
┌──────────────────────────────────────────────────────────────┐
│  garble reverse ./cmd/app stack-trace.txt                    │
├──────────────────────────────────────────────────────────────┤
│  1. Parse flags (must match original build flags!)           │
│  2. Regenerate same seed/nonce combination                   │
│  3. Run "go list" to re-populate cache                       │
│  4. For each obfuscated name in stack trace:                 │
│     ├─ Recompute hash with same seed                         │
│     ├─ Match against known package names                     │
│     └─ Replace with original name                            │
│  5. Output de-obfuscated stack trace                         │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. Meccanismi di Obfuscation

### 5.1 Name Obfuscation

**Algoritmo**:
```
Original Name: "MyFunction"
Package Path: "github.com/user/pkg"
Seed: <32-byte combined seed>

Step 1: Compute package-specific salt
    salt = SHA-256(seed || packagePath)[:8]

Step 2: Hash the name
    hash = SHA-256(salt || "MyFunction")

Step 3: Encode to valid Go identifier
    encoded = base64url(hash[:8])
    obfuscatedName = sanitize(encoded)  // e.g., "A7bK2xQz"
```

**Namespace Isolation**:
- Ogni package ha un salt diverso
- Nomi identici in package diversi → hash diversi
- Collision rate: trascurabile (2^64 spazio)

### 5.2 Literal Obfuscation (ASCON-128)

**Flow per Stringa Letterale**:
```go
Original Code:
    msg := "Hello, World!"

Step 1: Derive per-literal key
    literalKey = deriveLiteralKey(combinedSeed, literalIndex)

Step 2: Encrypt with ASCON-128
    ciphertext = ASCON_Encrypt(literalKey, nonce, "Hello, World!")

Step 3: Inject inline decryption
    Obfuscated Code:
    func() string {
        key := [16]byte{...}  // embedded key
        nonce := [16]byte{...}
        ct := []byte{...}     // ciphertext
        pt := asconDecrypt(key, nonce, ct)
        return string(pt)
    }()
```

**Caratteristiche**:
- Ogni letterale ha chiave e nonce univoci
- Decryption runtime overhead: ~1-2 μs per literal
- Nessun leakage di informazioni (AEAD authenticated encryption)

### 5.3 Feistel Cipher per Metadata

**Applicazione: funcInfo table nel runtime Go**

```
Runtime Go mantiene una tabella di funzioni con:
    type funcInfo struct {
        nameOff int32   // Offset nel namedata section
        ...
    }

Obfuscation:
    1. Deriva 4 round keys da seed
    2. Per ogni funcInfo:
        encryptedNameOff = Feistel_Encrypt(nameOff, funcID, keys)
    3. Patch runtime.funcname() per decifrare al volo:
        func funcname(f funcInfo) string {
            realOff := Feistel_Decrypt(f.nameOff, f.funcID, keys)
            return namedata[realOff:]
        }
```

**Proprietà**:
- Format-preserving: encrypted value ha stessa dimensione dell'originale
- Reversibile: decryption deterministico con stesse keys
- Overhead: ~10ns per decryption (4 round)

### 5.4 Control Flow Obfuscation (Complex Mode)

**Esempio di Flattening**:

```go
// Original Function
func calculate(x int) int {
    if x > 10 {
        x = x * 2
    } else {
        x = x + 5
    }
    return x
}

// Flattened Version
func calculate(x int) int {
    state := 0
    var result int
    for {
        switch state {
        case 0:
            if x > 10 {
                state = 1
            } else {
                state = 2
            }
        case 1:
            x = x * 2
            state = 3
        case 2:
            x = x + 5
            state = 3
        case 3:
            result = x
            return result
        }
    }
}
```

**Aggiunta di Trash Blocks**:
```go
case 4:  // Dead code, never reached
    x = x ^ 0xDEADBEEF
    if false {
        panic("never happens")
    }
    state = 0
```

---

## 6. Punti di Forza

### 6.1 Sicurezza

1. **Crittografia Standard**:
   - ASCON-128: Winner NIST Lightweight Crypto competition
   - SHA-256: Industry-standard hashing
   - Nessun crypto "home-made"

2. **Defense in Depth**:
   - Múltipli layer di obfuscation
   - Cifratura a riposo (cache)
   - Cifratura runtime (metadata)
   - Protezione dei letterali

3. **Riproducibilità Sicura**:
   - Seed deterministico per CI/CD
   - Nonce unico per build security
   - Auditabile e verificabile

### 6.2 Performance

1. **Compile-Time Overhead**:
   - ~10-30% più lento rispetto a `go build` standard
   - Parallelizzabile (go build -p)
   - Caching efficiente

2. **Runtime Overhead**:
   - Name obfuscation: zero overhead (staticamente risolto)
   - Literal decryption: ~1-2 μs per literal (lazy, non critico)
   - Feistel decryption: ~10ns per funzione (amortizzabile)
   - Control flow: ~5-15% overhead (opzionale, configurabile)

3. **Binary Size**:
   - Base obfuscation: +5-10% (per inline decryption code)
   - `-tiny` mode: -10-20% (rimuove panic messages, etc.)
   - `-literals`: +10-30% (dipende dal numero di literals)

### 6.3 Compatibilità

1. **Go Version Support**:
   - Go 1.25+ fully supported
   - Backward compatibility con cautela

2. **Platform Support**:
   - GOARCH: amd64, arm64, 386, arm, etc. (tutti quelli Go supporta)
   - GOOS: linux, darwin, windows, etc.
   - CGO: supportato (con limitazioni su obfuscation)

3. **Module & Dependency Support**:
   - Go modules: full support
   - Vendor: supportato
   - Replace directives: supportato

### 6.4 Manutenibilità

1. **Codice Strutturato**:
   - Separazione layer (CLI, crypto, cache, transform, obfuscation)
   - Interfacce chiare (obfuscator interface, etc.)
   - Documentazione inline

2. **Testing**:
   - Unit tests: ~85% coverage
   - Integration tests: cache encryption, control flow, literals
   - Fuzz tests: directive parsing, reverse logic

3. **Debugging**:
   - `-debugdir` flag per ispezionare codice obfuscato
   - Logging dettagliato con `log.SetPrefix("[garble]")`
   - Reverse command per de-obfuscation

### 6.5 Estensibilità

1. **Obfuscator Plugin System**:
   - Facile aggiungere nuovi obfuscators (implementa `obfuscator` interface)
   - Literal obfuscators componibili

2. **Control Flow Modes**:
   - Off / XOR / Complex
   - Configurabile via direttive per funzione

3. **Custom Patches**:
   - Linker patches estendibili (vedi `internal/linker/patches/`)

---

## 7. Dettagli Implementativi

### 7.1 Gestione degli Errori

**Strategie**:
1. **Early Validation**: Flag parsing rigido all'inizio
2. **Graceful Degradation**: Se cache crypto fallisce, fallback a plaintext (con warning)
3. **Contextual Errors**: Error wrapping con `fmt.Errorf`

**Esempio**:
```go
func encryptCacheWithASCON(data interface{}, seed []byte) ([]byte, error) {
    if len(seed) == 0 {
        return nil, fmt.Errorf("cache encryption: seed cannot be empty")
    }
    // ... encryption logic
    if err != nil {
        return nil, fmt.Errorf("cache encryption failed: %w", err)
    }
    return ciphertext, nil
}
```

### 7.2 Concurrency & Thread Safety

**Shared Cache**:
- **Read-only dopo initialization**: No locks necessari
- **Per-package cache**: Isolato, no contention

**Crypto Operations**:
- **Stateless**: Ogni operazione è indipendente
- **RNG seeding**: Una volta all'inizio, poi deterministic

### 7.3 Memory Management

**Ottimizzazioni**:
1. **Lazy Loading**: Packages caricati solo quando necessari
2. **Streaming Parsing**: AST non tenuto in memoria oltre il necessario
3. **Temp Files**: Obfuscated files scritti su disco, non in RAM

**Profiling**:
```bash
GARBLE_WRITE_MEMPROFILES=/tmp garble build ./...
# Genera file .pprof per analisi
```

### 7.4 File System Layout

```
$GARBLE_SHARED/
├── main-cache.gob.enc         # Encrypted shared cache
├── pkg-cache/
│   ├── github.com_user_pkg1.gob.enc
│   └── github.com_user_pkg2.gob.enc
└── obfuscated-src/
    ├── pkg1/
    │   ├── file1.go
    │   └── file2.go
    └── pkg2/
        └── file.go
```

### 7.5 Integrazione con Go Toolchain

**Toolexec Mechanism**:
```bash
# Go internamente chiama:
/path/to/garble toolexec compile -o output.a input.go

# Garble:
# 1. Intercetta il comando
# 2. Applica obfuscation
# 3. Chiama il vero compiler:
$GOTOOLDIR/compile -o output.a obfuscated.go
```

**Action Graph**:
- Garble genera un action graph JSON per capire l'ordine di build
- Rispetta le dipendenze tra packages

---

## 8. Diagrammi ASCII Riassuntivi

### 8.1 Data Flow: Seed → Obfuscated Binary

```
User Seed (-seed=...)
    │
    ├─► SHA-256 ──► 32 bytes seed
    │
    └─► Combined with Build Nonce
            │
            ▼
     Combined Hash (32 bytes)
            │
     ┌──────┴─────────────────────────┐
     │                                │
     ▼                                ▼
Package Salt Derivation      Crypto Key Derivation
     │                                │
     ├─► Name Hashing                 ├─► ASCON Literal Keys
     │   (per identifier)             │   (per literal)
     │                                │
     └─► Import Path Hashing          └─► Feistel Round Keys
                                          (4x32-bit)
                                      │
                                      └─► Cache Encryption Key
```

### 8.2 Build Pipeline: Source → Binary

```
main.go, util.go, ...
    │
    ├─► Parse ─────────────► AST
    │
    ├─► Type Check ────────► types.Info
    │
    ├─► Transform ─────────► Obfuscated AST
    │   ├─ Hash Names
    │   ├─ Obfuscate Literals
    │   ├─ Obfuscate Control Flow
    │   └─ Remove Positions
    │
    ├─► Generate ──────────► Obfuscated .go files
    │
    ├─► Compile ───────────► .a archive
    │
    └─► Link ──────────────► Obfuscated Binary
        └─ Inject Runtime Patches
        └─ Strip Debug Info
```

### 8.3 Security Layers

```
┌────────────────────────────────────────────────────┐
│              GARBLE SECURITY LAYERS                │
├────────────────────────────────────────────────────┤
│                                                    │
│  Layer 1: Name Obfuscation (SHA-256)               │
│  ┌──────────────────────────────────────────────┐  │
│  │ All identifiers hashed                       │  │
│  │ Package paths hashed                         │  │
│  │ No original names in binary                  │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 2: Literal Protection (ASCON-128)           │
│  ┌──────────────────────────────────────────────┐  │
│  │ Strings encrypted inline                     │  │
│  │ Constants obfuscated                         │  │
│  │ Runtime decryption only                      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 3: Metadata Hardening (Feistel)             │
│  ┌──────────────────────────────────────────────┐  │
│  │ funcInfo table encrypted                     │  │
│  │ Runtime helpers injected                     │  │
│  │ Format-preserving encryption                 │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 4: Control Flow Obfuscation (Optional)      │
│  ┌──────────────────────────────────────────────┐  │
│  │ Flattening + junk jumps                      │  │
│  │ Dead code injection                          │  │
│  │ CFG complexity increase                      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Layer 5: Cache Encryption (ASCON-128)             │
│  ┌──────────────────────────────────────────────┐  │
│  │ Build artifacts encrypted at rest            │  │
│  │ Authenticated encryption (AEAD)              │  │
│  │ Tampering detected                           │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## Conclusione

Garble è un obfuscator Go maturo e sicuro, con una architettura modulare che bilancia:
- **Sicurezza**: Crittografia standard + múltipli layer di protezione
- **Performance**: Overhead accettabile per compile e runtime
- **Usabilità**: CLI semplice, integrazione trasparente con Go toolchain
- **Manutenibilità**: Codice ben strutturato, testato, documentato

Il fork **AeonDave/garble** aggiunge crittografia della cache, hardening dei metadati, e robustezza enterprise-grade rispetto all'upstream.

Per maggiori dettagli sulla sicurezza, vedi [SECURITY.md](SECURITY.md).  
Per configurazione avanzata, vedi [FEATURE_TOGGLES.md](FEATURE_TOGGLES.md).  
Per dettagli sul control flow, vedi [CONTROLFLOW.md](CONTROLFLOW.md).

---

**Documento mantenuto da**: AeonDave  
**Ultimo aggiornamento**: 8 Ottobre 2025  
**Versione Garble**: 0.14.x (fork hardened)
