package cmdquoted

import (
	"reflect"
	"testing"
)

func TestSplitBasic(t *testing.T) {
	got, err := Split("a b\t c")
	if err != nil {
		t.Fatalf("Split error: %v", err)
	}
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Split=%v, want %v", got, want)
	}
}

func TestSplitQuotes(t *testing.T) {
	got, err := Split(`"a b" 'c d' e`)
	if err != nil {
		t.Fatalf("Split error: %v", err)
	}
	want := []string{"a b", "c d", "e"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Split=%v, want %v", got, want)
	}
}

func TestSplitUnterminated(t *testing.T) {
	_, err := Split(`"a b`)
	if err == nil {
		t.Fatal("expected unterminated quote error")
	}
}

func TestJoinNoQuotesNeeded(t *testing.T) {
	got, err := Join([]string{"a", "b"})
	if err != nil {
		t.Fatalf("Join error: %v", err)
	}
	if got != "a b" {
		t.Fatalf("Join=%q, want %q", got, "a b")
	}
}

func TestJoinWithSpaces(t *testing.T) {
	got, err := Join([]string{"a b", "c"})
	if err != nil {
		t.Fatalf("Join error: %v", err)
	}
	if got != "'a b' c" {
		t.Fatalf("Join=%q, want %q", got, "'a b' c")
	}
}

func TestJoinWithDoubleQuotes(t *testing.T) {
	got, err := Join([]string{"a'b"})
	if err != nil {
		t.Fatalf("Join error: %v", err)
	}
	if got != "\"a'b\"" {
		t.Fatalf("Join=%q, want %q", got, "\"a'b\"")
	}
}

func TestJoinWithBothQuotesFails(t *testing.T) {
	_, err := Join([]string{"a'\"b"})
	if err == nil {
		t.Fatal("expected error for argument with both quote types")
	}
}

func TestFlagSetAndString(t *testing.T) {
	var f Flag
	if err := f.Set("'a b' c"); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if got := f.String(); got != "'a b' c" {
		t.Fatalf("String=%q, want %q", got, "'a b' c")
	}
}

func TestFlagStringNil(t *testing.T) {
	var f *Flag
	if got := f.String(); got != "" {
		t.Fatalf("String=%q, want empty", got)
	}
}
