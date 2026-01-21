package ctrlflow

import (
	"go/constant"
	"go/types"
	mathrand "math/rand"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestApplyFlatteningNoopForSmallFunctions(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f() {}
`)
	info := applyFlattening(ssaPkg.Func("f"), mathrand.New(mathrand.NewSource(1)))
	if info != nil {
		t.Fatal("expected no flattening for small function")
	}
}

func TestApplyFlatteningCreatesEntry(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f(x int) int {
	if x > 0 {
		return 1
	}
	return 2
}
`)
	fn := ssaPkg.Func("f")
	info := applyFlattening(fn, mathrand.New(mathrand.NewSource(2)))
	if len(info) == 0 {
		t.Fatal("expected dispatcher info")
	}
	if len(fn.Blocks) == 0 || fn.Blocks[0].Comment != "ctrflow.entry" {
		t.Fatalf("expected entry block, got %+v", fn.Blocks[0])
	}
	phi, ok := fn.Blocks[0].Instrs[0].(*ssa.Phi)
	if !ok {
		t.Fatalf("expected first instr to be Phi, got %T", fn.Blocks[0].Instrs[0])
	}
	if len(phi.Edges) != len(info) {
		t.Fatalf("phi edges=%d, want %d", len(phi.Edges), len(info))
	}
}

func TestAddJunkBlocksSkipsWhenNoCandidates(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f() {}
`)
	fn := ssaPkg.Func("f")
	before := len(fn.Blocks)
	addJunkBlocks(fn, 3, mathrand.New(mathrand.NewSource(3)))
	if len(fn.Blocks) != before {
		t.Fatalf("expected no change, got %d -> %d", before, len(fn.Blocks))
	}
}

func TestAddJunkBlocksAddsBlocks(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f(x int) int {
	if x > 0 { return 1 }
	return 2
}
`)
	fn := ssaPkg.Func("f")
	before := len(fn.Blocks)
	addJunkBlocks(fn, 2, mathrand.New(mathrand.NewSource(4)))
	if len(fn.Blocks) < before+2 {
		t.Fatalf("expected junk blocks added, got %d -> %d", before, len(fn.Blocks))
	}
	found := false
	for _, b := range fn.Blocks {
		if b.Comment != "" && len(b.Comment) >= len("ctrflow.fake.") && b.Comment[:len("ctrflow.fake.")] == "ctrflow.fake." {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected fake block comment")
	}
}

func TestApplySplittingFalseWhenTooSmall(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f() {}
`)
	fn := ssaPkg.Func("f")
	if applySplitting(fn, mathrand.New(mathrand.NewSource(5))) {
		t.Fatal("expected applySplitting to return false")
	}
}

func TestApplySplittingCreatesNewBlock(t *testing.T) {
	fn := &ssa.Function{}
	block := &ssa.BasicBlock{
		Index: 0,
		Instrs: []ssa.Instruction{
			&ssa.Jump{},
			&ssa.Jump{},
			&ssa.Return{},
		},
	}
	fn.Blocks = []*ssa.BasicBlock{block}
	before := len(fn.Blocks)
	if !applySplitting(fn, mathrand.New(mathrand.NewSource(6))) {
		t.Fatal("expected applySplitting to return true")
	}
	if len(fn.Blocks) != before+1 {
		t.Fatalf("expected new block, got %d -> %d", before, len(fn.Blocks))
	}
}

func TestRandomAlwaysFalseCond(t *testing.T) {
	v1, op, v2 := randomAlwaysFalseCond(mathrand.New(mathrand.NewSource(7)))
	if constant.Compare(v1.Value, op, v2.Value) {
		t.Fatalf("condition unexpectedly true: %v %v %v", v1.Value, op, v2.Value)
	}
}

func TestAddTrashBlockMarkersAddsBlocks(t *testing.T) {
	ssaPkg, _ := buildSSA(t, `package p
func f(x int) int {
	if x > 0 { return 1 }
	return 2
}
`)
	fn := ssaPkg.Func("f")
	before := len(fn.Blocks)
	addTrashBlockMarkers(fn, 1, mathrand.New(mathrand.NewSource(8)))
	if len(fn.Blocks) != before+2 {
		t.Fatalf("expected 2 new blocks, got %d -> %d", before, len(fn.Blocks))
	}
}

func TestFixBlockIndexes(t *testing.T) {
	fn := &ssa.Function{}
	fn.Blocks = []*ssa.BasicBlock{{Index: 5}, {Index: 9}, {Index: 0}}
	fixBlockIndexes(fn)
	for i, b := range fn.Blocks {
		if b.Index != i {
			t.Fatalf("block index=%d, want %d", b.Index, i)
		}
	}
}

func TestMakeSsaInt(t *testing.T) {
	c := makeSsaInt(42)
	if c == nil {
		t.Fatal("expected const")
	}
	if c.Type() != types.Typ[types.Int] {
		t.Fatalf("type=%v, want int", c.Type())
	}
	if c.Value.ExactString() != "42" {
		t.Fatalf("value=%s, want 42", c.Value.ExactString())
	}
}

func TestSetTypeOnPhi(t *testing.T) {
	phi := &ssa.Phi{}
	setType(phi, types.Typ[types.Int])
	if phi.Type() != types.Typ[types.Int] {
		t.Fatalf("type=%v, want int", phi.Type())
	}
}

func TestSetBlockAndParent(t *testing.T) {
	fn := &ssa.Function{}
	block := &ssa.BasicBlock{}
	setBlockParent(block, fn)
	if block.Parent() != fn {
		t.Fatal("parent not set")
	}
	instr := &ssa.Jump{}
	setBlock(instr, block)
	if instr.Block() != block {
		t.Fatal("block not set on instruction")
	}
}

func TestSetUnexportedFieldInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	setUnexportedField(&ssa.BasicBlock{}, "missing", 1)
}
