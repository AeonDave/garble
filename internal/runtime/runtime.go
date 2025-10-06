// Copyright (c) 2025, The Garble Authors.
// See LICENSE for licensing information.

package runtime

import (
	"bytes"
	"embed"
	"fmt"
	"go/version"
	"io/fs"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
)

//go:embed patches/*/*.patch
var runtimePatchesFS embed.FS

// LoadRuntimePatches loads runtime patches for the given Go version
// Returns the patches as byte slices that can be applied to runtime source files
func LoadRuntimePatches(goVersion string) (patches [][]byte, err error) {
	// Extract major version (e.g., "go1.25.1" -> "go1.25")
	majorVersion := version.Lang(goVersion)
	if majorVersion == "" {
		return nil, fmt.Errorf("invalid Go version: %s", goVersion)
	}

	// Read patches directory for this Go version
	patchDir := "patches/" + majorVersion
	entries, err := fs.ReadDir(runtimePatchesFS, patchDir)
	if err != nil {
		return nil, fmt.Errorf("no runtime patches found for %s: %w", majorVersion, err)
	}

	// Load all patch files
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		patchPath := patchDir + "/" + entry.Name()
		patchData, err := fs.ReadFile(runtimePatchesFS, patchPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read patch %s: %w", patchPath, err)
		}
		
		patches = append(patches, patchData)
	}

	if len(patches) == 0 {
		return nil, fmt.Errorf("no patches found in %s", patchDir)
	}

	return patches, nil
}

// ApplyRuntimePatches applies the given patches to the runtime source code
// Returns the patched source code
func ApplyRuntimePatches(originalSource []byte, patches [][]byte) ([]byte, error) {
	result := originalSource
	
	for i, patchData := range patches {
		// Parse the patch
		files, _, err := gitdiff.Parse(bytes.NewReader(patchData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse patch %d: %w", i, err)
		}
		
		if len(files) == 0 {
			return nil, fmt.Errorf("patch %d contains no file changes", i)
		}
		
		// Apply each file's patch
		// For runtime patches, we expect only one file per patch
		for _, file := range files {
			if file.IsDelete || file.IsRename {
				return nil, fmt.Errorf("patch %d: delete/rename operations not supported", i)
			}
			
			// Apply the patch using gitdiff
			patched, err := applyPatch(result, file)
			if err != nil {
				return nil, fmt.Errorf("failed to apply patch %d to %s: %w", i, file.NewName, err)
			}
			result = patched
		}
	}
	
	return result, nil
}

// applyPatch applies a single file patch to source code
func applyPatch(source []byte, file *gitdiff.File) ([]byte, error) {
	lines := bytes.Split(source, []byte("\n"))
	var result [][]byte
	
	lineIdx := 0
	for _, fragment := range file.TextFragments {
		// Copy lines before this fragment
		for lineIdx < int(fragment.OldPosition-1) && lineIdx < len(lines) {
			result = append(result, lines[lineIdx])
			lineIdx++
		}
		
		// Apply fragment changes
		oldLineCount := 0
		for _, line := range fragment.Lines {
			switch line.Op {
			case gitdiff.OpContext:
				// Context line - keep it
				if lineIdx < len(lines) {
					result = append(result, lines[lineIdx])
					lineIdx++
				}
				oldLineCount++
				
			case gitdiff.OpDelete:
				// Delete line - skip it
				lineIdx++
				oldLineCount++
				
			case gitdiff.OpAdd:
				// Add line - insert it
				result = append(result, []byte(line.Line))
			}
		}
	}
	
	// Copy remaining lines
	for lineIdx < len(lines) {
		result = append(result, lines[lineIdx])
		lineIdx++
	}
	
	return bytes.Join(result, []byte("\n")), nil
}
