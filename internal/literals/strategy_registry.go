package literals

import (
	"fmt"
	mathrand "math/rand"
	"sync"
)

type strategyOption func(*strategyConfig)

type strategyConfig struct {
	linear bool
	weight int // selection weight (higher = more likely). Default 1.
}

func withLinearSupport() strategyOption {
	return func(cfg *strategyConfig) { cfg.linear = true }
}

func withWeight(w int) strategyOption {
	return func(cfg *strategyConfig) { cfg.weight = w }
}

type strategyEntry struct {
	obf    obfuscator
	weight int
}

type strategyRegistry struct {
	mu      sync.RWMutex
	entries map[string]strategyEntry
	general []string
	linear  []string
}

func newStrategyRegistry() *strategyRegistry {
	return &strategyRegistry{
		entries: make(map[string]strategyEntry),
	}
}

func (r *strategyRegistry) register(name string, obf obfuscator, opts ...strategyOption) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		panic(fmt.Sprintf("duplicate literal obfuscation strategy: %s", name))
	}
	cfg := strategyConfig{weight: 1}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.weight < 1 {
		cfg.weight = 1
	}
	r.entries[name] = strategyEntry{obf: obf, weight: cfg.weight}
	r.general = append(r.general, name)
	if cfg.linear {
		r.linear = append(r.linear, name)
	}
}

func (r *strategyRegistry) weightedPick(rand *mathrand.Rand, pool []string) obfuscator {
	if len(pool) == 0 {
		return nil
	}
	totalWeight := 0
	for _, name := range pool {
		totalWeight += r.entries[name].weight
	}
	pick := rand.Intn(totalWeight)
	for _, name := range pool {
		pick -= r.entries[name].weight
		if pick < 0 {
			return r.entries[name].obf
		}
	}
	return r.entries[pool[len(pool)-1]].obf
}

func (r *strategyRegistry) pickGeneral(rand *mathrand.Rand) obfuscator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.weightedPick(rand, r.general)
}

func (r *strategyRegistry) pickLinear(rand *mathrand.Rand) obfuscator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var pool []string
	if len(r.linear) > 0 {
		pool = r.linear
	} else {
		pool = r.general
	}
	return r.weightedPick(rand, pool)
}

func (r *strategyRegistry) names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.general))
	copy(names, r.general)
	return names
}

func (r *strategyRegistry) byName(name string) (obfuscator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[name]
	return e.obf, ok
}

var defaultStrategies = newStrategyRegistry()

func registerStrategy(name string, obf obfuscator, opts ...strategyOption) {
	defaultStrategies.register(name, obf, opts...)
}

// RegisteredStrategyNames returns the identifiers of all registered literal
// obfuscation strategies in registration order. It is primarily used by
// tooling and tests to reference specific strategies without exposing the
// underlying implementation type.
func RegisteredStrategyNames() []string {
	return defaultStrategies.names()
}

func strategyByName(name string) (obfuscator, bool) {
	return defaultStrategies.byName(name)
}

func pickGeneralStrategy(rand *mathrand.Rand) obfuscator {
	return defaultStrategies.pickGeneral(rand)
}

func pickLinearStrategy(rand *mathrand.Rand) obfuscator {
	return defaultStrategies.pickLinear(rand)
}
