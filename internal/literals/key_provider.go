package literals

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyProvider generates per-literal keying material for encryption-based obfuscators.
type KeyProvider interface {
	// NextLiteralKeys returns a unique 16-byte key and 16-byte nonce pair for
	// the ASCON literal backend.
	NextLiteralKeys() (key, nonce []byte)

	// NextIrreversibleMaterial returns deterministic pseudorandom bytes for the
	// irreversible literal backend. The caller specifies how many bytes are
	// required for round subkeys or other material.
	NextIrreversibleMaterial(size int) []byte
}

type keyContext string

const (
	keyContextASCON        keyContext = "garble/literals/ascon:v1"
	keyContextIrreversible keyContext = "garble/literals/irreversible:v1"
)

// hkdfKeyProvider implements KeyProvider using HKDF-SHA256.
type hkdfKeyProvider struct {
	prk         []byte
	packageSalt []byte
	fileID      string
	counter     uint64
}

// NewHKDFKeyProvider constructs a KeyProvider backed by HKDF-SHA256.
//
// masterSecret should come from combineSeedAndNonce(seed, nonce) when a CLI seed
// is provided; otherwise the package GarbleActionID is used. packageSalt must be
// a stable, package-unique identifier such as the GarbleActionID. fileID should
// be a trimmed/relative path that is stable across builds.
func NewHKDFKeyProvider(masterSecret, packageSalt []byte, fileID string) KeyProvider {
	if len(masterSecret) == 0 {
		panic("literals: master secret for HKDF provider is empty")
	}
	if len(packageSalt) == 0 {
		panic("literals: package salt for HKDF provider is empty")
	}
	prk := hkdf.Extract(sha256.New, masterSecret, packageSalt)
	saltCopy := append([]byte(nil), packageSalt...)
	return &hkdfKeyProvider{
		prk:         append([]byte(nil), prk...),
		packageSalt: saltCopy,
		fileID:      fileID,
	}
}

func (p *hkdfKeyProvider) next(context keyContext, size int) []byte {
	if size <= 0 {
		panic("literals: HKDF material size must be positive")
	}

	idx := p.counter
	p.counter++

	info := make([]byte, len(context)+1+len(p.packageSalt)+1+len(p.fileID)+1+8)
	copy(info, context)
	offset := len(context)
	info[offset] = 0
	offset++
	copy(info[offset:], p.packageSalt)
	offset += len(p.packageSalt)
	info[offset] = 0
	offset++
	copy(info[offset:], p.fileID)
	offset += len(p.fileID)
	info[offset] = 0
	offset++
	binary.BigEndian.PutUint64(info[offset:], idx)

	reader := hkdf.Expand(sha256.New, p.prk, info)
	material := make([]byte, size)
	if _, err := io.ReadFull(reader, material); err != nil {
		panic(fmt.Sprintf("literals: hkdf expand failed: %v", err))
	}
	return material
}

func (p *hkdfKeyProvider) NextLiteralKeys() (key, nonce []byte) {
	material := p.next(keyContextASCON, 32)
	key = make([]byte, 16)
	copy(key, material[:16])
	nonce = make([]byte, 16)
	copy(nonce, material[16:32])
	return key, nonce
}

func (p *hkdfKeyProvider) NextIrreversibleMaterial(size int) []byte {
	return p.next(keyContextIrreversible, size)
}
