//go:build garble_testing

package literals

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	obfMapEnv := os.Getenv("GARBLE_TEST_LITERALS_OBFUSCATOR_MAP")
	if obfMapEnv == "" {
		panic("literals obfuscator map required for testing build")
	}
	testPkgToObfuscatorMap = make(map[string]obfuscator)

	// Parse obfuscator mapping: pkgName1=obfIndex1,pkgName2=obfIndex2
	pairs := strings.Split(obfMapEnv, ",")
	for _, pair := range pairs {
		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) != 2 {
			panic(fmt.Sprintf("invalid obfuscator map entry: %q", pair))
		}

		pkgName := keyValue[0]
		strategyName := keyValue[1]
		obf, ok := strategyByName(strategyName)
		if !ok {
			panic(fmt.Sprintf("unknown literal obfuscator strategy %q", strategyName))
		}
		testPkgToObfuscatorMap[pkgName] = obf
	}
	TestObfuscator = obfMapEnv
}
