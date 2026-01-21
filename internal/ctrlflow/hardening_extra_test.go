package ctrlflow

import (
	"go/ast"
	"math/rand"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestRandomHardeningKeySizeRange(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		size := randomHardeningKeySize(rnd)
		if size < hardeningKeyMinBytes {
			t.Fatalf("size=%d < min", size)
		}
		if size >= hardeningKeyMinBytes+hardeningKeyRandomRange {
			t.Fatalf("size=%d >= max", size)
		}
	}
}

func TestGenerateKeysUniqueness(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	keys := generateKeys(32, []int{1, 2, 3}, rnd)
	seen := make(map[int]bool)
	for _, k := range keys {
		if k == 0 {
			t.Fatal("key must be non-zero")
		}
		if k == 1 || k == 2 || k == 3 {
			t.Fatalf("key %d should be blacklisted", k)
		}
		if seen[k] {
			t.Fatalf("duplicate key %d", k)
		}
		seen[k] = true
	}
}

func TestNewDispatcherHardeningUnknownPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = newDispatcherHardening([]string{"unknown"})
}

func TestDelegateTableHardeningProducesRemap(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	dispatcher := []cfgInfo{{StoreVar: makeSsaInt(1), CompareVar: makeSsaInt(1)}, {StoreVar: makeSsaInt(2), CompareVar: makeSsaInt(2)}}
	ssaRemap := make(map[ssa.Value]ast.Expr)

	decl, stmt := (delegateTableHardening{}).Apply(dispatcher, ssaRemap, rnd)
	if decl == nil || stmt == nil {
		t.Fatal("expected decl and stmt")
	}
	if len(ssaRemap) != len(dispatcher)*2 {
		t.Fatalf("expected remap entries, got %d", len(ssaRemap))
	}
}
