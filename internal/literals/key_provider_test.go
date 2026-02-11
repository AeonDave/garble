package literals

import (
	"bytes"
	"testing"
)

func TestHKDFKeyProviderPanicsOnEmptyInputs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty master secret")
		}
	}()
	_ = NewHKDFKeyProvider(nil, []byte("salt"), "file.go")
}

func TestHKDFKeyProviderPanicsOnEmptySalt(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty salt")
		}
	}()
	_ = NewHKDFKeyProvider([]byte("secret"), nil, "file.go")
}

func TestHKDFKeyProviderLengthsAndDeterminism(t *testing.T) {
	provider := NewHKDFKeyProvider([]byte("secret-0123456789"), []byte("salt-0123456789"), "file.go")
	k1, n1 := provider.NextLiteralKeys()
	k2, n2 := provider.NextLiteralKeys()
	if len(k1) != 16 || len(n1) != 16 {
		t.Fatalf("unexpected key/nonce lengths: %d/%d", len(k1), len(n1))
	}
	if len(k2) != 16 || len(n2) != 16 {
		t.Fatalf("unexpected key/nonce lengths: %d/%d", len(k2), len(n2))
	}
	if bytes.Equal(k1, k2) && bytes.Equal(n1, n2) {
		t.Fatal("expected different keys across calls")
	}

	material := provider.NextIrreversibleMaterial(32)
	if len(material) != 32 {
		t.Fatalf("irreversible material length=%d, want 32", len(material))
	}
}
