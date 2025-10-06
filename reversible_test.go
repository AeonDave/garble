// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReversibleFlag tests the -reversible flag functionality
func TestReversibleFlag(t *testing.T) {
	t.Parallel()

	// Create temporary directory for test
	tmpDir := t.TempDir()

	// Create simple test program
	testCode := `package main

import "fmt"

const secret = "testdata123"

func main() {
	fmt.Println("Secret:", secret)
}
`
	mainFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(testCode), 0o666); err != nil {
		t.Fatal(err)
	}

	// Create go.mod
	goMod := `module test/reversible

go 1.23
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o666); err != nil {
		t.Fatal(err)
	}

	// Build garble first
	garbleBin := filepath.Join(tmpDir, "garble"+exeExt())
	buildCmd := exec.Command("go", "build", "-o", garbleBin, ".")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build garble: %v", err)
	}

	t.Run("DefaultMode", func(t *testing.T) {
		// Test 1: Default build (irreversible mode - no -reversible flag)
		outBinary := filepath.Join(tmpDir, "secure"+exeExt())
		cmd := exec.Command(garbleBin, "-literals", "build", "-o", outBinary)
		cmd.Dir = tmpDir
		cmd.Env = append(os.Environ(),
			"GARBLE_BUILD_NONCE=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Build failed: %v\nOutput: %s", err, output)
		}

		// Run the binary
		runCmd := exec.Command(outBinary)
		runOutput, err := runCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Verify output contains decrypted secret
		if !strings.Contains(string(runOutput), "Secret: testdata123") {
			t.Errorf("Expected output to contain 'Secret: testdata123', got: %s", runOutput)
		}

		// Verify binary doesn't contain plaintext literal
		binaryData, err := os.ReadFile(outBinary)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Contains(binaryData, []byte("testdata123")) {
			t.Error("Binary contains plaintext literal 'testdata123' (should be obfuscated)")
		}
	})

	t.Run("ReversibleMode", func(t *testing.T) {
		// Test 2: Build with -reversible flag
		outBinary := filepath.Join(tmpDir, "reversible"+exeExt())
		cmd := exec.Command(garbleBin, "-reversible", "-literals", "build", "-o", outBinary)
		cmd.Dir = tmpDir
		cmd.Env = append(os.Environ(),
			"GARBLE_BUILD_NONCE=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Build failed: %v\nOutput: %s", err, output)
		}

		// Run the binary
		runCmd := exec.Command(outBinary)
		runOutput, err := runCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Verify output contains decrypted secret
		if !strings.Contains(string(runOutput), "Secret: testdata123") {
			t.Errorf("Expected output to contain 'Secret: testdata123', got: %s", runOutput)
		}

		// Verify binary doesn't contain plaintext literal (still obfuscated)
		binaryData, err := os.ReadFile(outBinary)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Contains(binaryData, []byte("testdata123")) {
			t.Error("Binary contains plaintext literal 'testdata123' (should be obfuscated even in reversible mode)")
		}
	})
}

// TestReversibleModeReflection tests reflection behavior with -reversible flag
func TestReversibleModeReflection(t *testing.T) {
	t.Parallel()

	// Create temporary directory for test
	tmpDir := t.TempDir()

	// Create test program with reflection
	testCode := `package main

import (
	"fmt"
	"reflect"
)

type TestStruct struct {
	PublicField string
}

func main() {
	t := &TestStruct{PublicField: "hello"}
	typ := reflect.TypeOf(t).Elem()
	fmt.Println("Type:", typ.Name())
}
`
	mainFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(testCode), 0o666); err != nil {
		t.Fatal(err)
	}

	// Create go.mod
	goMod := `module test/reflection

go 1.23
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o666); err != nil {
		t.Fatal(err)
	}

	// Build garble first
	garbleBin := filepath.Join(tmpDir, "garble"+exeExt())
	buildCmd := exec.Command("go", "build", "-o", garbleBin, ".")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build garble: %v", err)
	}

	t.Run("DefaultNoNameMap", func(t *testing.T) {
		// Default mode: _originalNamePairs should be empty
		outBinary := filepath.Join(tmpDir, "secure_reflect"+exeExt())
		cmd := exec.Command(garbleBin, "build", "-o", outBinary)
		cmd.Dir = tmpDir
		cmd.Env = append(os.Environ(),
			"GARBLE_BUILD_NONCE=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Build failed: %v\nOutput: %s", err, output)
		}

		// Read binary
		binaryData, err := os.ReadFile(outBinary)
		if err != nil {
			t.Fatal(err)
		}

		// Verify TestStruct name is NOT in binary (obfuscated)
		if bytes.Contains(binaryData, []byte("TestStruct")) {
			t.Error("Binary contains 'TestStruct' name (should be obfuscated)")
		}
	})

	t.Run("ReversibleWithNameMap", func(t *testing.T) {
		// Reversible mode: reflection should still work but names are obfuscated
		outBinary := filepath.Join(tmpDir, "reversible_reflect"+exeExt())
		cmd := exec.Command(garbleBin, "-reversible", "build", "-o", outBinary)
		cmd.Dir = tmpDir
		cmd.Env = append(os.Environ(),
			"GARBLE_BUILD_NONCE=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Build failed: %v\nOutput: %s", err, output)
		}

		// Run the binary - it should still work with reflection
		runCmd := exec.Command(outBinary)
		runOutput, err := runCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Run failed: %v\nOutput: %s", err, runOutput)
		}

		// Should print "Type: " followed by obfuscated name
		if !strings.Contains(string(runOutput), "Type:") {
			t.Errorf("Expected output to contain 'Type:', got: %s", runOutput)
		}
	})
}

func exeExt() string {
	if os.Getenv("GOOS") == "windows" || (os.Getenv("GOOS") == "" && os.PathSeparator == '\\') {
		return ".exe"
	}
	return ""
}
