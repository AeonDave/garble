package literals

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	mathrand "math/rand"
	"strings"
)

type irreversibleInlineHelper struct {
	rand     *mathrand.Rand
	nameFunc NameProviderFunc
	funcName string
	used     bool
	inserted bool
}

func newIrreversibleInlineHelper(rand *mathrand.Rand, nameFunc NameProviderFunc) *irreversibleInlineHelper {
	return &irreversibleInlineHelper{
		rand:     rand,
		nameFunc: nameFunc,
		funcName: nameFunc(rand, "_garbleIrreversibleDecode"),
	}
}

func formatByteArrayLiteral(data [256]byte) string {
	var sb strings.Builder
	sb.WriteString("{")
	for i, b := range data {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("0x%02x", b))
	}
	sb.WriteString("}")
	return sb.String()
}

func (h *irreversibleInlineHelper) generateInlineCode() string {
	rotateName := h.nameFunc(h.rand, "rotl")
	loadName := h.nameFunc(h.rand, "load64")
	storeName := h.nameFunc(h.rand, "store64")
	roundName := h.nameFunc(h.rand, "round")
	sboxName := h.nameFunc(h.rand, "sbox")
	invName := h.nameFunc(h.rand, "invSbox")

	return fmt.Sprintf(`
func %s(data []byte, subkeys []uint64, originalLen int) []byte {
        if len(data) == 0 {
                return data
        }
        if len(data)%%%d != 0 || len(subkeys) == 0 {
                return data
        }
        %s := [...]byte%s
        %s := [...]byte%s
        %s := func(x uint64, r uint) uint64 {
                r &= 63
                return (x << r) | (x >> (64 - r))
        }
        %s := func(b []byte) uint64 {
                return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
                        uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
        }
        %s := func(v uint64, b []byte) {
                b[0] = byte(v)
                b[1] = byte(v >> 8)
                b[2] = byte(v >> 16)
                b[3] = byte(v >> 24)
                b[4] = byte(v >> 32)
                b[5] = byte(v >> 40)
                b[6] = byte(v >> 48)
                b[7] = byte(v >> 56)
        }
        %s := func(value, key uint64) uint64 {
                mix := value ^ key
                rot := (key & 63) | 1
                mix = %s(mix, uint(rot))
                mix ^= (key << 17) | (key >> 47)
                mix += 0x%016x
                return mix
        }
        for offset := 0; offset < len(data); offset += %d {
                left := %s(data[offset : offset+8])
                right := %s(data[offset+8 : offset+16])
                for round := len(subkeys) - 1; round >= 0; round-- {
                        key := subkeys[round]
                        mix := %s(left, key)
                        tmp := right ^ mix
                        right = left
                        left = tmp
                }
                %s(left, data[offset:offset+8])
                %s(right, data[offset+8:offset+16])
        }
        for i := range data {
                data[i] = %s[data[i]]
        }
        if originalLen <= len(data) {
                return data[:originalLen]
        }
        return data
}
`,
		h.funcName,
		irreversibleBlockSize,
		sboxName, formatByteArrayLiteral(irreversibleSBox),
		invName, formatByteArrayLiteral(irreversibleInvSBox),
		rotateName,
		loadName,
		storeName,
		roundName, rotateName, irreversibleRoundConstant,
		irreversibleBlockSize,
		loadName, loadName,
		roundName,
		storeName, storeName,
		invName,
	)
}

func insertIrreversibleInlineCode(file *ast.File, helper *irreversibleInlineHelper) {
	if helper.inserted {
		return
	}
	code := helper.generateInlineCode()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "irreversible.go", "package p\n"+code, 0)
	if err != nil {
		panic(fmt.Sprintf("failed to parse irreversible inline code: %v", err))
	}
	if len(parsed.Decls) == 0 {
		panic("irreversible inline code produced no declarations")
	}
	funcDecl, ok := parsed.Decls[0].(*ast.FuncDecl)
	if !ok {
		panic("irreversible inline code did not start with a function")
	}
	file.Decls = append(file.Decls, funcDecl)
	helper.inserted = true
}
