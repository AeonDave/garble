// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAsconInlineEndToEnd tests that the generated inline ASCON code actually works
// by compiling and executing it
// This test is slow due to compilation - skip unless running integration tests
func TestAsconInlineEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow integration test in short mode")
	}

	// Create temporary directory
	tmpDir := t.TempDir()

	// Test data
	plaintext := []byte("Hello, ASCON inline test!")
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	nonce := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}

	// Encrypt with reference implementation
	ciphertextAndTag := AsconEncrypt(key, nonce, plaintext)

	// Generate test program with inline ASCON
	testProgram := generateTestProgram(key, nonce, ciphertextAndTag, plaintext)

	// Write to file
	testFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(testFile, []byte(testProgram), 0644); err != nil {
		t.Fatalf("Failed to write test program: %v", err)
	}

	// Compile the test program
	binary := filepath.Join(tmpDir, "test.exe")
	cmd := exec.Command("go", "build", "-o", binary, testFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to compile test program: %v\nStderr: %s", err, stderr.String())
	}

	// Run the test program
	cmd = exec.Command(binary)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Test program failed: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check output
	output := strings.TrimSpace(stdout.String())
	expected := string(plaintext)
	if output != expected {
		t.Errorf("Decryption result mismatch:\nGot:      %q\nExpected: %q", output, expected)
	}

	t.Logf("✅ Inline ASCON successfully decrypted: %q", output)
}

// generateTestProgram creates a Go program that uses the inline ASCON implementation
func generateTestProgram(key, nonce, ciphertextAndTag, expectedPlaintext []byte) string {
	// Parse the inline code to ensure it's valid
	fset := token.NewFileSet()
	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName
	}
	helper := &asconInlineHelper{
		funcName: "_garbleAsconDecrypt",
		nameFunc: nameProvider,
	}
	inlineCode := helper.generateInlineAsconCode()

	_, err := parser.ParseFile(fset, "inline.go", "package main\n"+inlineCode, 0)
	if err != nil {
		panic("Generated inline code is invalid: " + err.Error())
	}

	// Generate the test program
	var buf bytes.Buffer
	buf.WriteString("package main\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"fmt\"\n")
	buf.WriteString("\t\"os\"\n")
	buf.WriteString(")\n\n")

	// Add inline ASCON code
	buf.WriteString(inlineCode)
	buf.WriteString("\n\n")

	// Add main function
	buf.WriteString("func main() {\n")
	buf.WriteString("\tkey := []byte{")
	for i, b := range key {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n")

	buf.WriteString("\tnonce := []byte{")
	for i, b := range nonce {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n")

	buf.WriteString("\tciphertextAndTag := []byte{")
	for i, b := range ciphertextAndTag {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n\n")

	buf.WriteString("\tplaintext, ok := _garbleAsconDecrypt(key, nonce, ciphertextAndTag)\n")
	buf.WriteString("\tif !ok {\n")
	buf.WriteString("\t\tfmt.Fprintf(os.Stderr, \"Decryption failed\\n\")\n")
	buf.WriteString("\t\tos.Exit(1)\n")
	buf.WriteString("\t}\n\n")

	buf.WriteString("\texpected := []byte{")
	for i, b := range expectedPlaintext {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n\n")

	buf.WriteString("\tif len(plaintext) != len(expected) {\n")
	buf.WriteString("\t\tfmt.Fprintf(os.Stderr, \"Length mismatch: got %d, want %d\\n\", len(plaintext), len(expected))\n")
	buf.WriteString("\t\tos.Exit(1)\n")
	buf.WriteString("\t}\n\n")

	buf.WriteString("\tfor i := range plaintext {\n")
	buf.WriteString("\t\tif plaintext[i] != expected[i] {\n")
	buf.WriteString("\t\t\tfmt.Fprintf(os.Stderr, \"Byte mismatch at index %d: got 0x%02x, want 0x%02x\\n\", i, plaintext[i], expected[i])\n")
	buf.WriteString("\t\t\tos.Exit(1)\n")
	buf.WriteString("\t\t}\n")
	buf.WriteString("\t}\n\n")

	buf.WriteString("\tfmt.Print(string(plaintext))\n")
	buf.WriteString("}\n")

	// Format the code
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		panic("Failed to format generated program: " + err.Error())
	}

	return string(formatted)
}

// TestAsconInlineWithTampering tests that the inline code detects tampering
// This test is slow due to compilation - skip unless running integration tests
func TestAsconInlineWithTampering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow integration test in short mode")
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Secret message")
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 16)
	}

	ciphertextAndTag := AsconEncrypt(key, nonce, plaintext)

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertextAndTag))
	copy(tampered, ciphertextAndTag)
	tampered[0] ^= 0x01 // Flip a bit

	// Generate test program
	testProgram := generateTamperingTestProgram(key, nonce, tampered)

	// Write and compile
	testFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(testFile, []byte(testProgram), 0644); err != nil {
		t.Fatalf("Failed to write test program: %v", err)
	}

	binary := filepath.Join(tmpDir, "test.exe")
	cmd := exec.Command("go", "build", "-o", binary, testFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to compile test program: %v", err)
	}

	// Run - should detect tampering
	cmd = exec.Command(binary)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	// Should exit with error
	if err == nil {
		t.Errorf("Expected program to detect tampering, but it succeeded")
	}

	// Should print authentication failure message
	if !strings.Contains(stderr.String(), "Authentication failed") {
		t.Errorf("Expected authentication failure message, got: %s", stderr.String())
	}

	t.Logf("✅ Inline ASCON correctly detected tampering")
}

func generateTamperingTestProgram(key, nonce, tampered []byte) string {
	nameProvider := func(r *mathrand.Rand, baseName string) string {
		return baseName
	}
	helper := &asconInlineHelper{
		funcName: "_garbleAsconDecrypt",
		nameFunc: nameProvider,
	}
	inlineCode := helper.generateInlineAsconCode()

	var buf bytes.Buffer
	buf.WriteString("package main\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"fmt\"\n")
	buf.WriteString("\t\"os\"\n")
	buf.WriteString(")\n\n")
	buf.WriteString(inlineCode)
	buf.WriteString("\n\n")
	buf.WriteString("func main() {\n")

	buf.WriteString("\tkey := []byte{")
	for i, b := range key {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n")

	buf.WriteString("\tnonce := []byte{")
	for i, b := range nonce {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n")

	buf.WriteString("\ttampered := []byte{")
	for i, b := range tampered {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("}\n\n")

	buf.WriteString("\t_, ok := _garbleAsconDecrypt(key, nonce, tampered)\n")
	buf.WriteString("\tif ok {\n")
	buf.WriteString("\t\tfmt.Fprintf(os.Stderr, \"ERROR: Tampered data was accepted!\\n\")\n")
	buf.WriteString("\t\tos.Exit(1)\n")
	buf.WriteString("\t}\n\n")

	buf.WriteString("\tfmt.Fprintf(os.Stderr, \"Authentication failed (expected)\\n\")\n")
	buf.WriteString("\tos.Exit(1)\n")
	buf.WriteString("}\n")

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		panic("Failed to format: " + err.Error())
	}

	return string(formatted)
}
