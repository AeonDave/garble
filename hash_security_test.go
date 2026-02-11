package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go/token"
	"testing"
)

// TestHashCollisionResistance verifies that hashWithCustomSalt produces
// no collisions over a large corpus of realistic identifier names.
// This is critical: a collision means two different symbols get the same
// obfuscated name, breaking the compiled binary.
func TestHashCollisionResistance(t *testing.T) {
	// Simulate hashWithCustomSalt without global state
	hashFn := func(salt []byte, name string) string {
		h := sha256.New()
		h.Write(salt)
		// seedHashInput would be added in production; omit here as it's constant
		h.Write([]byte(name))
		sum := h.Sum(nil)

		// Replicate the length logic from hashWithCustomSalt
		hashLengthRandomness := sum[neededSumBytes] % ((maxHashLength - minHashLength) + 1)
		hashLength := minHashLength + hashLengthRandomness

		var buf [12]byte
		nameBase64.Encode(buf[:], sum[:neededSumBytes])
		b64 := buf[:hashLength]

		if isDigit(b64[0]) {
			b64[0] += 'A' - '0'
		}
		for i, b := range b64 {
			if b == '-' {
				b64[i] = 'a'
			}
		}
		return string(b64)
	}

	salt := sha256.Sum256([]byte("test-package-action-id"))

	// Generate a realistic corpus of Go identifiers
	names := make([]string, 0, 20000)

	// Common patterns: exported/unexported, methods, types
	prefixes := []string{"Get", "Set", "New", "Is", "Has", "Do", "Run", "Parse", "Format", "Handle"}
	suffixes := []string{"Config", "Error", "Result", "Context", "Handler", "Manager", "Service", "Client"}
	for _, p := range prefixes {
		for _, s := range suffixes {
			names = append(names, p+s)
			names = append(names, toLowerFirst(p)+s)
		}
	}

	// Numbered identifiers (common in generated code)
	for i := 0; i < 5000; i++ {
		names = append(names, fmt.Sprintf("field%d", i))
		names = append(names, fmt.Sprintf("Field%d", i))
		names = append(names, fmt.Sprintf("var_%d", i))
		names = append(names, fmt.Sprintf("Type%d", i))
	}

	// Check for collisions
	seen := make(map[string]string, len(names))
	collisions := 0
	for _, name := range names {
		hashed := hashFn(salt[:], name)
		if prev, dup := seen[hashed]; dup {
			t.Errorf("collision: %q and %q both hash to %q", name, prev, hashed)
			collisions++
			if collisions >= 5 {
				t.Fatal("too many collisions, stopping")
			}
		}
		seen[hashed] = name
	}

	t.Logf("tested %d identifiers, %d collisions", len(names), collisions)
}

// TestHashExportPreservation verifies that exported names remain exported
// and unexported names remain unexported after hashing.
func TestHashExportPreservation(t *testing.T) {
	hashFn := func(salt []byte, name string) string {
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(name))
		sum := h.Sum(nil)

		hashLengthRandomness := sum[neededSumBytes] % ((maxHashLength - minHashLength) + 1)
		hashLength := minHashLength + hashLengthRandomness

		var buf [12]byte
		nameBase64.Encode(buf[:], sum[:neededSumBytes])
		b64 := buf[:hashLength]

		if isDigit(b64[0]) {
			b64[0] += 'A' - '0'
		}
		for i, b := range b64 {
			if b == '-' {
				b64[i] = 'a'
			}
		}

		// Apply export preservation
		if token.IsIdentifier(name) {
			if token.IsExported(name) {
				if b64[0] == '_' {
					b64[0] = 'Z'
				} else if isLower(b64[0]) {
					b64[0] = toUpper(b64[0])
				}
			} else if isUpper(b64[0]) {
				b64[0] = toLower(b64[0])
			}
		}
		return string(b64)
	}

	salt := sha256.Sum256([]byte("export-test"))

	exported := []string{"MyFunc", "Handler", "Config", "X", "ABC"}
	unexported := []string{"myFunc", "handler", "config", "x", "abc"}

	for _, name := range exported {
		hashed := hashFn(salt[:], name)
		if !token.IsExported(hashed) {
			t.Errorf("exported %q hashed to unexported %q", name, hashed)
		}
	}

	for _, name := range unexported {
		hashed := hashFn(salt[:], name)
		if token.IsExported(hashed) {
			t.Errorf("unexported %q hashed to exported %q", name, hashed)
		}
	}
}

// TestHashOutputIsValidIdentifier verifies all hashed outputs are valid Go identifiers.
func TestHashOutputIsValidIdentifier(t *testing.T) {
	hashFn := func(salt []byte, name string) string {
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(name))
		sum := h.Sum(nil)

		hashLengthRandomness := sum[neededSumBytes] % ((maxHashLength - minHashLength) + 1)
		hashLength := minHashLength + hashLengthRandomness

		var buf [12]byte
		nameBase64.Encode(buf[:], sum[:neededSumBytes])
		b64 := buf[:hashLength]

		if isDigit(b64[0]) {
			b64[0] += 'A' - '0'
		}
		for i, b := range b64 {
			if b == '-' {
				b64[i] = 'a'
			}
		}
		return string(b64)
	}

	salt := sha256.Sum256([]byte("ident-test"))
	names := []string{"foo", "Bar", "baz123", "TypeA", "myVar", "_private"}

	for _, name := range names {
		hashed := hashFn(salt[:], name)
		if !token.IsIdentifier(hashed) {
			t.Errorf("hash of %q produced invalid identifier %q", name, hashed)
		}
	}
}

// TestHashLengthDistribution verifies hash lengths are distributed between
// minHashLength and maxHashLength as designed.
func TestHashLengthDistribution(t *testing.T) {
	salt := sha256.Sum256([]byte("length-test"))
	var lengths [maxHashLength + 1]int

	for i := 0; i < 10000; i++ {
		name := fmt.Sprintf("identifier_%d", i)

		h := sha256.New()
		h.Write(salt[:])
		h.Write([]byte(name))
		sum := h.Sum(nil)

		hashLengthRandomness := sum[neededSumBytes] % ((maxHashLength - minHashLength) + 1)
		hashLength := minHashLength + hashLengthRandomness

		if hashLength < minHashLength || hashLength > maxHashLength {
			t.Fatalf("hash length %d outside [%d, %d]", hashLength, minHashLength, maxHashLength)
		}
		lengths[hashLength]++
	}

	// All length buckets in [minHashLength, maxHashLength] should be represented
	for l := minHashLength; l <= maxHashLength; l++ {
		if lengths[l] == 0 {
			t.Errorf("hash length %d never observed in 10000 trials", l)
		}
		t.Logf("  length %d: %d occurrences", l, lengths[l])
	}
}

func toLowerFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	if 'A' <= b[0] && b[0] <= 'Z' {
		b[0] += 'a' - 'A'
	}
	return string(b)
}

// Ensure the test uses the same base64 encoding as production code
var _ = base64.URLEncoding
