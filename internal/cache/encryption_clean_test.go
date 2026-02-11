package cache

import (
	"bytes"
	"testing"
)

type cleanTestPayload struct {
	Name  string
	Count int
}

func TestDeriveKeyDeterministic(t *testing.T) {
	seed := []byte("seed")
	k1 := DeriveKey(seed)
	k2 := DeriveKey(seed)
	if k1 != k2 {
		t.Fatal("expected deterministic key")
	}
	k3 := DeriveKey([]byte("other"))
	if k1 == k3 {
		t.Fatal("expected different key for different seed")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	seed := []byte("seed")
	input := cleanTestPayload{Name: "alpha", Count: 3}
	enc, err := Encrypt(input, seed)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	if len(enc) <= NonceSize+TagSize {
		t.Fatalf("encrypted payload too small: %d", len(enc))
	}
	var out cleanTestPayload
	if err := Decrypt(enc, seed, &out); err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if out != input {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", out, input)
	}
}

func TestDecryptWrongSeedFails(t *testing.T) {
	seed := []byte("seed")
	enc, err := Encrypt(cleanTestPayload{Name: "alpha"}, seed)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	var out cleanTestPayload
	if err := Decrypt(enc, []byte("other"), &out); err == nil {
		t.Fatal("expected decrypt error with wrong seed")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	seed := []byte("seed")
	enc, err := Encrypt(cleanTestPayload{Name: "alpha"}, seed)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	enc[len(enc)-1] ^= 0xFF
	var out cleanTestPayload
	if err := Decrypt(enc, seed, &out); err == nil {
		t.Fatal("expected decrypt error for tampered ciphertext")
	}
}

func TestEncryptUsesRandomNonce(t *testing.T) {
	seed := []byte("seed")
	input := cleanTestPayload{Name: "alpha"}
	enc1, err := Encrypt(input, seed)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	sawDifferent := false
	for i := 0; i < 3; i++ {
		enc2, err := Encrypt(input, seed)
		if err != nil {
			t.Fatalf("Encrypt error: %v", err)
		}
		if !bytes.Equal(enc1[:NonceSize], enc2[:NonceSize]) {
			sawDifferent = true
			break
		}
	}
	if !sawDifferent {
		t.Fatal("expected different nonces across encryptions")
	}
}

func TestDecryptShortPayload(t *testing.T) {
	var out cleanTestPayload
	if err := Decrypt([]byte{1, 2, 3}, []byte("seed"), &out); err == nil {
		t.Fatal("expected error for short payload")
	}
}
