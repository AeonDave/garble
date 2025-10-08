package ctrlflow

import (
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// FuzzParseDirective ensures parseDirective is resilient against arbitrary
// comment bodies and that helper accessors behave safely on the returned map.
//
// It focuses on the directive grammar used by control-flow annotations, which
// historically has been prone to subtle parsing regressions. By exercising the
// parser and then probing directiveParamMap helpers only when the fuzz input
// yields syntactically valid values, we guard against panics while letting the
// fuzzer explore surprising edge cases (extra whitespace, duplicated keys,
// unusual value combinations, etc.).
func FuzzParseDirective(f *testing.F) {
	seeds := []string{
		"//garble:nocontrolflow",
		"//garble:controlflow",
		"//garble:controlflow flatten_passes=1 junk_jumps=2 block_splits=3",
		"//garble:controlflow flatten_passes=max junk_jumps=max block_splits=max",
		"//garble:controlflow flatten_passes=0 junk_jumps=0 block_splits=0 trash_blocks=0",
		"//garble:controlflow flatten_passes=1 junk_jumps=5 block_splits=10 trash_blocks=32 flatten_hardening=xor,delegate_table",
		"//garble:controlflow    flatten_passes=2    junk_jumps=8    ",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		params, ok := parseDirective(input)
		if !ok {
			return
		}
		if params == nil {
			// Directive without parameters is valid; nothing further to validate.
			return
		}

		for key, raw := range params {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				t.Fatalf("empty directive key parsed from %q", input)
			}

			trimmedVal := strings.TrimSpace(raw)
			params[key] = trimmedVal

			// Attempt to exercise helper methods when values look well-formed.
			if trimmedVal == "max" {
				_ = params.GetInt(trimmedKey, 0, 1<<16)
			} else if looksNumeric(trimmedVal) {
				if num, err := strconv.Atoi(trimmedVal); err == nil && num >= 0 && num <= 1<<16 {
					if got := params.GetInt(trimmedKey, 0, 1<<16); got != num {
						t.Fatalf("GetInt mismatch for key %q: got %d want %d", trimmedKey, got, num)
					}
				}
			}

			// Always exercise StringSlice to cover comma-separated handling.
			_ = params.StringSlice(trimmedKey)
		}
	})
}

func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
