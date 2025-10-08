package main

import (
	"io"
	"strings"
	"testing"
)

// FuzzReverseContent stresses the line-by-line reversal helper with
// arbitrary replacement tables and inputs to ensure it never panics and
// always returns a coherent result.
func FuzzReverseContent(f *testing.F) {
	seeds := []struct {
		input string
		pairs []string
	}{
		{"", nil},
		{"plain text without newlines", []string{"foo", "bar"}},
		{"garble/obfuscated.go:1", []string{"garble/", "", "obfuscated", "original"}},
		{"multiple\nlines\nwith\nstacktrace", []string{"\n", " ", ":", " -> "}},
	}

	for _, seed := range seeds {
		if len(seed.pairs) == 0 {
			f.Add(seed.input, "", "", "", "")
			continue
		}
		// Pad to two pairs so that the fuzz target always receives
		// a consistent argument count for strings.NewReplacer.
		pairs := make([]string, 4)
		copy(pairs, seed.pairs)
		f.Add(seed.input, pairs[0], pairs[1], pairs[2], pairs[3])
	}

	f.Fuzz(func(t *testing.T, input, old1, new1, old2, new2 string) {
		// Construct the replacer with two pairs; duplicate replacements are fine.
		replacer := strings.NewReplacer(old1, new1, old2, new2)

		// Use a strings.Builder to capture output and ensure the writer never errors.
		var out strings.Builder
		modified, err := reverseContent(&out, strings.NewReader(input), replacer)
		if err != nil {
			t.Fatalf("reverseContent returned error: %v", err)
		}

		// Verify that reverseContent faithfully writes the entire transformed payload.
		if !modified {
			// When no replacements occur, the output must match the input.
			if out.String() != input {
				t.Fatalf("expected output to match input when unmodified")
			}
		} else {
			// When replacements happen, ensure the output is consistent with direct Replace.
			if want := replacer.Replace(input); out.String() != want {
				t.Fatalf("reverseContent output mismatch: got %q want %q", out.String(), want)
			}
		}

		// Exercise the buffered path by running once more with an io.Discard writer.
		// This ensures coverage for the Write fast-path without allocating strings.
		if _, err := reverseContent(io.Discard, strings.NewReader(input), replacer); err != nil {
			t.Fatalf("reverseContent(io.Discard) returned error: %v", err)
		}
	})
}
