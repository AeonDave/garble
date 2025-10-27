package main

import (
	"encoding/gob"
	"fmt"
	"os"
)

type listedPackage struct {
	ImportPath string
	Export     string
	Standard   bool
}

type sharedCacheDump struct {
	ListedPackages map[string]*listedPackage
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: debug_dump_cache path")
		os.Exit(1)
	}
	path := os.Args[1]
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var cache sharedCacheDump
	if err := gob.NewDecoder(f).Decode(&cache); err != nil {
		panic(err)
	}
	fmt.Printf("Listed packages: %d\n", len(cache.ListedPackages))
	for _, pkg := range []string{"bytes", "crypto/chacha20poly1305", "crypto/cipher", "crypto/hkdf", "crypto/sha256", "encoding/binary", "fmt", "io", "os", "sync"} {
		if lp := cache.ListedPackages[pkg]; lp != nil {
			fmt.Printf("%s export=%q standard=%v\n", pkg, lp.Export, lp.Standard)
		} else {
			fmt.Printf("%s missing\n", pkg)
		}
	}
}
