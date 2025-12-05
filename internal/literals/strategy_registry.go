package literals

import (
	"fmt"
	mathrand "math/rand"
	"sync"
)

type strategyOption func(*strategyConfig)

type strategyConfig struct {
	linear bool
}

func withLinearSupport() strategyOption {
	return func(cfg *strategyConfig) { cfg.linear = true }
}

type strategyRegistry struct {
	mu      sync.RWMutex
	entries map[string]obfuscator
	general []string
	linear  []string
}

func newStrategyRegistry() *strategyRegistry {
	return &strategyRegistry{
		entries: make(map[string]obfuscator),
	}
}

func (r *strategyRegistry) register(name string, obf obfuscator, opts ...strategyOption) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		panic(fmt.Sprintf("duplicate literal obfuscation strategy: %s", name))
	}
	r.entries[name] = obf
	r.general = append(r.general, name)
	cfg := strategyConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.linear {
		r.linear = append(r.linear, name)
	}
}

func (r *strategyRegistry) pickGeneral(rand *mathrand.Rand) obfuscator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.general) == 0 {
		return nil
	}
	name := r.general[rand.Intn(len(r.general))]
	return r.entries[name]
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
	if len(pool) == 0 {
		return nil
	}
	name := pool[rand.Intn(len(pool))]
	return r.entries[name]
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
	obf, ok := r.entries[name]
	return obf, ok
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
