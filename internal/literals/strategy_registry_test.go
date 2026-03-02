package literals

import (
	"testing"
)

func TestStrategyRegistryPickEmpty(t *testing.T) {
	r := newStrategyRegistry()
	if got := r.pickGeneral(nil); got != nil {
		t.Fatal("expected nil general obfuscator for empty registry")
	}
	if got := r.pickLinear(nil); got != nil {
		t.Fatal("expected nil linear obfuscator for empty registry")
	}
}

func TestStrategyRegistryRegisterDuplicatePanics(t *testing.T) {
	r := newStrategyRegistry()
	r.register("one", swap{})
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate register")
		}
	}()
	r.register("one", swap{})
}

func TestStrategyRegistryNamesAndLookup(t *testing.T) {
	r := newStrategyRegistry()
	r.register("a", swap{})
	r.register("b", swap{})
	r.register("c", split{}, withLinearSupport())

	names := r.names()
	if len(names) != 3 {
		t.Fatalf("names length=%d, want 3", len(names))
	}
	if names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Fatalf("names order=%v", names)
	}
	if _, ok := r.byName("b"); !ok {
		t.Fatal("expected to find strategy b")
	}
	if _, ok := r.byName("missing"); ok {
		t.Fatal("did not expect to find missing strategy")
	}
}
