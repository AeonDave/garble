package main

import (
	"bytes"
	"encoding/gob"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCacheEncryptionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires building garble binary and spawning external processes")
	}

	garbleBin := buildGarbleBinary(t)

	tempRoot := t.TempDir()
	moduleDir := filepath.Join(tempRoot, "module")
	if err := os.MkdirAll(moduleDir, 0o777); err != nil {
		t.Fatalf("failed to create module dir: %v", err)
	}

	writeFile(t, filepath.Join(moduleDir, "go.mod"), "module example.com/cacheprobe\n\ngo 1.25\n")
	writeFile(t, filepath.Join(moduleDir, "main.go"), `package main

import (
    "fmt"
    "reflect"
)

func main() {
    fmt.Println(reflect.TypeOf(struct{}{}))
}
`)

	cacheDir := filepath.Join(tempRoot, "garble-cache")
	goCacheDir := filepath.Join(tempRoot, "go-cache")
	seed := "dGVzdF9jYWNoZV9zZWVk" // "test_cache_seed"

	baseEnv := append(
		os.Environ(),
		"GARBLE_CACHE="+cacheDir,
		"GOCACHE="+goCacheDir,
		"GARBLE_BUILD_NONCE=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	)

	runGarbleBuild(t, garbleBin, moduleDir, append([]string{}, baseEnv...), "-seed="+seed)

	if !cacheHasFiles(t, cacheDir) {
		t.Fatalf("expected cache files after encrypted build")
	}

	encryptedFiles := cacheFileBytes(t, cacheDir)
	for _, data := range encryptedFiles {
		if err := tryGobDecode(data); err == nil {
			t.Fatalf("encrypted cache unexpectedly decodable via gob")
		}
	}

	if err := os.RemoveAll(cacheDir); err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}

	runGarbleBuild(t, garbleBin, moduleDir, append([]string{}, baseEnv...), "-no-cache-encrypt", "-seed="+seed)

	if !cacheHasFiles(t, cacheDir) {
		t.Fatalf("expected cache files after unencrypted build")
	}

	plaintextFiles := cacheFileBytes(t, cacheDir)
	var decoded bool
	for _, data := range plaintextFiles {
		if err := tryGobDecode(data); err == nil {
			decoded = true
			break
		}
	}
	if !decoded {
		t.Fatalf("unencrypted cache should contain at least one gob-decodable entry")
	}

	if err := os.RemoveAll(cacheDir); err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}

	runGarbleBuild(t, garbleBin, moduleDir, append([]string{}, baseEnv...), "-cache-encrypt-nonce")

	if !cacheHasFiles(t, cacheDir) {
		t.Fatalf("expected cache files after nonce-backed encrypted build")
	}

	for _, data := range cacheFileBytes(t, cacheDir) {
		if err := tryGobDecode(data); err == nil {
			t.Fatalf("nonce-backed encrypted cache unexpectedly decodable via gob")
		}
	}
}

func buildGarbleBinary(t *testing.T) string {
	t.Helper()

	binDir := t.TempDir()
	exe := "garble-integration"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	binPath := filepath.Join(binDir, exe)

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = wd
	}
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build garble binary: %v\n%s", err, out)
	}
	return binPath
}

func runGarbleBuild(t *testing.T, garbleBin, dir string, env []string, args ...string) {
	t.Helper()

	cmdArgs := append(args, "build", ".")
	cmd := exec.Command(garbleBin, cmdArgs...)
	cmd.Dir = dir
	cmd.Env = env

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("garble build failed: %v\n%s", err, out)
	}
}

func cacheHasFiles(t *testing.T, cacheDir string) bool {
	t.Helper()

	buildDir := filepath.Join(cacheDir, "build")
	entries, err := os.ReadDir(buildDir)
	if err != nil {
		t.Fatalf("reading cache dir failed: %v", err)
	}
	return len(entries) > 0
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o666); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func cacheFileBytes(t *testing.T, cacheDir string) [][]byte {
	buildDir := filepath.Join(cacheDir, "build")
	var files [][]byte
	err := filepath.WalkDir(buildDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fileData, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files = append(files, fileData)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no cache files found in %s", buildDir)
	}
	return files
}

func tryGobDecode(data []byte) error {
	var decoded pkgCache
	return gob.NewDecoder(bytes.NewReader(data)).Decode(&decoded)
}
