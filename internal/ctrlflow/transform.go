package ctrlflow

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	mathrand "math/rand"
	"strconv"

	"github.com/AeonDave/garble/internal/ssa2ast"
	"golang.org/x/tools/go/ssa"
)

type blockMapping struct {
	Fake, Target *ssa.BasicBlock
}

type cfgInfo struct {
	CompareVar ssa.Value
	StoreVar   ssa.Value
}

type dispatcherInfo []cfgInfo

// applyFlattening adds a dispatcher block and uses ssa.Phi to redirect all ssa.Jump and ssa.If to the dispatcher,
// additionally shuffle all blocks
func applyFlattening(ssaFunc *ssa.Function, obfRand *mathrand.Rand) dispatcherInfo {
	if len(ssaFunc.Blocks) < 3 {
		return nil
	}

	phiInstr := &ssa.Phi{Comment: "ctrflow.phi"}
	setType(phiInstr, types.Typ[types.Int])

	entryBlock := &ssa.BasicBlock{
		Comment: "ctrflow.entry",
		Instrs:  []ssa.Instruction{phiInstr},
	}
	setBlockParent(entryBlock, ssaFunc)

	makeJumpBlock := func(from *ssa.BasicBlock) *ssa.BasicBlock {
		jumpBlock := &ssa.BasicBlock{
			Comment: "ctrflow.jump",
			Instrs:  []ssa.Instruction{&ssa.Jump{}},
			Preds:   []*ssa.BasicBlock{from},
			Succs:   []*ssa.BasicBlock{entryBlock},
		}
		setBlockParent(jumpBlock, ssaFunc)
		return jumpBlock
	}

	// map for track fake block -> real block jump
	var blocksMapping []blockMapping
	for _, block := range ssaFunc.Blocks {
		existInstr := block.Instrs[len(block.Instrs)-1]
		switch existInstr.(type) {
		case *ssa.Jump:
			targetBlock := block.Succs[0]
			fakeBlock := makeJumpBlock(block)
			blocksMapping = append(blocksMapping, blockMapping{fakeBlock, targetBlock})
			block.Succs[0] = fakeBlock
		case *ssa.If:
			tblock, fblock := block.Succs[0], block.Succs[1]
			// Use block (the If-block) as the predecessor, not the target blocks.
			// The fake blocks are successors of the If-block, not of their targets.
			fakeTblock, fakeFblock := makeJumpBlock(block), makeJumpBlock(block)

			blocksMapping = append(blocksMapping, blockMapping{fakeTblock, tblock})
			blocksMapping = append(blocksMapping, blockMapping{fakeFblock, fblock})

			block.Succs[0] = fakeTblock
			block.Succs[1] = fakeFblock
		case *ssa.Return, *ssa.Panic:
			// control flow flattening is not applicable
		default:
			panic("unreachable")
		}
	}

	phiIdxs := obfRand.Perm(len(blocksMapping))
	for i := range phiIdxs {
		phiIdxs[i]++ // 0 reserved for real entry block
	}

	var info dispatcherInfo

	var entriesBlocks []*ssa.BasicBlock
	obfuscatedBlocks := ssaFunc.Blocks
	for i, m := range blocksMapping {
		entryBlock.Preds = append(entryBlock.Preds, m.Fake)
		val := phiIdxs[i]
		cfg := cfgInfo{StoreVar: makeSsaInt(val), CompareVar: makeSsaInt(val)}
		info = append(info, cfg)

		phiInstr.Edges = append(phiInstr.Edges, cfg.StoreVar)
		obfuscatedBlocks = append(obfuscatedBlocks, m.Fake)

		cond := &ssa.BinOp{X: phiInstr, Op: token.EQL, Y: cfg.CompareVar}
		setType(cond, types.Typ[types.Bool])

		*phiInstr.Referrers() = append(*phiInstr.Referrers(), cond)

		ifInstr := &ssa.If{Cond: cond}
		*cond.Referrers() = append(*cond.Referrers(), ifInstr)

		ifBlock := &ssa.BasicBlock{
			Instrs: []ssa.Instruction{cond, ifInstr},
			Succs:  []*ssa.BasicBlock{m.Target, nil}, // false branch fulfilled in next iteration or linked to real entry block
		}
		setBlockParent(ifBlock, ssaFunc)

		setBlock(cond, ifBlock)
		setBlock(ifInstr, ifBlock)
		entriesBlocks = append(entriesBlocks, ifBlock)

		if i == 0 {
			entryBlock.Instrs = append(entryBlock.Instrs, &ssa.Jump{})
			entryBlock.Succs = []*ssa.BasicBlock{ifBlock}
			ifBlock.Preds = append(ifBlock.Preds, entryBlock)
		} else {
			// link previous block to current
			entriesBlocks[i-1].Succs[1] = ifBlock
			ifBlock.Preds = append(ifBlock.Preds, entriesBlocks[i-1])
		}
	}

	lastFakeEntry := entriesBlocks[len(entriesBlocks)-1]

	// The else-branch of the last if-chain entry must reach the original
	// function entry block (realEntryBlock). On first invocation the phi
	// value is 0 (zero-value of int) which doesn't match any dispatch case
	// (all values are >= 1), so execution falls through to the real entry.
	//
	// CRITICAL: We must use a SEPARATE fallback block rather than pointing
	// lastFakeEntry directly at realEntryBlock. If lastFakeEntry were a
	// direct predecessor of realEntryBlock, the ssa2ast converter would
	// place the zero-value phi assignment (e.g. _s2a_N = 0) inside
	// lastFakeEntry's generated code — BEFORE the if/else exit. This means
	// the phi assignment executes unconditionally, even when the if-chain
	// match fires (true branch). In multi-pass flattening, if the true
	// branch target is the previous pass's dispatcher entry, the zero
	// assignment clobbers the inner dispatch variable, causing an infinite
	// loop. By routing through a dedicated fallback block, the zero
	// assignment only runs when no dispatch value matched (the else path),
	// which is the correct semantics.
	realEntryBlock := obfuscatedBlocks[0] // ssaFunc.Blocks[0] before this pass

	fallbackBlock := &ssa.BasicBlock{
		Comment: "ctrflow.fallback",
		Instrs:  []ssa.Instruction{&ssa.Jump{}},
		Preds:   []*ssa.BasicBlock{lastFakeEntry},
		Succs:   []*ssa.BasicBlock{realEntryBlock},
	}
	setBlockParent(fallbackBlock, ssaFunc)

	lastFakeEntry.Succs[1] = fallbackBlock
	realEntryBlock.Preds = append(realEntryBlock.Preds, fallbackBlock)

	// Patch any existing Phis in realEntryBlock (from a prior flattening pass)
	// so that the edge count stays in sync with the new predecessor.
	for _, instr := range realEntryBlock.Instrs {
		phi, ok := instr.(*ssa.Phi)
		if !ok {
			break // Phis are always at the start of a block
		}
		// Use a zero-value constant matching the phi's type. For the
		// dispatch phi (type int) this is 0, which makes the inner
		// dispatcher fall through to its own real entry — correct behavior.
		phi.Edges = append(phi.Edges, ssa.NewConst(constant.MakeInt64(0), phi.Type()))
	}

	obfuscatedBlocks = append(obfuscatedBlocks, fallbackBlock)
	obfuscatedBlocks = append(obfuscatedBlocks, entriesBlocks...)
	obfRand.Shuffle(len(obfuscatedBlocks), func(i, j int) {
		obfuscatedBlocks[i], obfuscatedBlocks[j] = obfuscatedBlocks[j], obfuscatedBlocks[i]
	})
	ssaFunc.Blocks = append([]*ssa.BasicBlock{entryBlock}, obfuscatedBlocks...)
	return info
}

// addJunkBlocks adds junk jumps into random blocks. Can create chains of junk jumps.
func addJunkBlocks(ssaFunc *ssa.Function, count int, obfRand *mathrand.Rand) {
	if count == 0 {
		return
	}
	var candidates []*ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if len(block.Succs) > 0 {
			candidates = append(candidates, block)
		}
	}

	if len(candidates) == 0 {
		return
	}

	for i := range count {
		targetBlock := candidates[obfRand.Intn(len(candidates))]
		succsIdx := obfRand.Intn(len(targetBlock.Succs))
		succs := targetBlock.Succs[succsIdx]

		fakeBlock := &ssa.BasicBlock{
			Comment: "ctrflow.fake." + strconv.Itoa(i),
			Instrs:  []ssa.Instruction{&ssa.Jump{}},
			Preds:   []*ssa.BasicBlock{targetBlock},
			Succs:   []*ssa.BasicBlock{succs},
		}
		setBlockParent(fakeBlock, ssaFunc)
		targetBlock.Succs[succsIdx] = fakeBlock

		// Update the successor's Preds so that phi resolution sees the
		// correct predecessor (fakeBlock instead of targetBlock).
		// Only replace one occurrence to handle the case where targetBlock
		// appears multiple times in succs.Preds (e.g., both branches of
		// an If going to the same block).
		for pi, pred := range succs.Preds {
			if pred == targetBlock {
				succs.Preds[pi] = fakeBlock
				break
			}
		}

		ssaFunc.Blocks = append(ssaFunc.Blocks, fakeBlock)
		candidates = append(candidates, fakeBlock)
	}
}

// applySplitting splits biggest block into 2 parts of random size.
// Returns false if no block large enough for splitting is found
func applySplitting(ssaFunc *ssa.Function, obfRand *mathrand.Rand) bool {
	var targetBlock *ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if targetBlock == nil || len(block.Instrs) > len(targetBlock.Instrs) {
			targetBlock = block
		}
	}

	// Find the first non-Phi instruction index. Phi nodes must stay together
	// at the top of their block; splitting inside the phi section would
	// corrupt the phi-predecessor mapping and produce incorrect code.
	phiEnd := 0
	for _, instr := range targetBlock.Instrs {
		if _, ok := instr.(*ssa.Phi); !ok {
			break
		}
		phiEnd++
	}

	// After skipping phis we need at least 2 non-phi instructions (1 body + 1 exit)
	const minInstrCount = 1 + 1 // 1 exit instruction + 1 any instruction
	nonPhiCount := len(targetBlock.Instrs) - phiEnd
	if targetBlock == nil || nonPhiCount <= minInstrCount {
		return false
	}

	// Split within the non-phi region: [phiEnd, len-1) exclusive of the exit
	splitIdx := phiEnd + 1 + obfRand.Intn(nonPhiCount-2)

	firstPart := make([]ssa.Instruction, splitIdx+1)
	copy(firstPart, targetBlock.Instrs)
	firstPart[len(firstPart)-1] = &ssa.Jump{}

	secondPart := targetBlock.Instrs[splitIdx:]
	targetBlock.Instrs = firstPart

	newBlock := &ssa.BasicBlock{
		Comment: "ctrflow.split." + strconv.Itoa(targetBlock.Index),
		Instrs:  secondPart,
		Preds:   []*ssa.BasicBlock{targetBlock},
		Succs:   targetBlock.Succs,
	}
	setBlockParent(newBlock, ssaFunc)
	for _, instr := range newBlock.Instrs {
		setBlock(instr, newBlock)
	}

	// Fix preds for ssa.Phi working
	for _, succ := range targetBlock.Succs {
		for i, pred := range succ.Preds {
			if pred == targetBlock {
				succ.Preds[i] = newBlock
			}
		}
	}

	ssaFunc.Blocks = append(ssaFunc.Blocks, newBlock)
	targetBlock.Succs = []*ssa.BasicBlock{newBlock}
	return true
}

// randomAlwaysFalseCond generates two random int32 and a random compare operator that always returns false, examples:
// 1350205738 <= 734900678
// 1400381511 >= 1621623831
// 2062290251 < 1908004916
// 1228588894 > 1819094321
// 2094727349 == 955574490
func randomAlwaysFalseCond(obfRand *mathrand.Rand) (*ssa.Const, token.Token, *ssa.Const) {
	tokens := []token.Token{token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ}

	val1, val2 := constant.MakeInt64(int64(obfRand.Int31())), constant.MakeInt64(int64(obfRand.Int31()))

	var candidates []token.Token
	for _, t := range tokens {
		if !constant.Compare(val1, t, val2) {
			candidates = append(candidates, t)
		}
	}

	return ssa.NewConst(val1, types.Typ[types.Int]), candidates[obfRand.Intn(len(candidates))], ssa.NewConst(val2, types.Typ[types.Int])
}

// addTrashBlockMarkers adds unreachable blocks with ssa2ast.MarkerInstr to further generate trash statements
func addTrashBlockMarkers(ssaFunc *ssa.Function, count int, obfRand *mathrand.Rand) {
	var candidates []*ssa.BasicBlock
	for _, block := range ssaFunc.Blocks {
		if len(block.Succs) > 0 {
			candidates = append(candidates, block)
		}
	}

	if len(candidates) == 0 {
		return
	}

	for range count {
		targetBlock := candidates[obfRand.Intn(len(candidates))]
		succsIdx := obfRand.Intn(len(targetBlock.Succs))
		succs := targetBlock.Succs[succsIdx]

		val1, op, val2 := randomAlwaysFalseCond(obfRand)
		phiInstr := &ssa.Phi{
			Edges: []ssa.Value{val1},
		}
		setType(phiInstr, types.Typ[types.Int])

		binOpInstr := &ssa.BinOp{
			X:  phiInstr,
			Op: op,
			Y:  val2,
		}
		setType(binOpInstr, types.Typ[types.Bool])

		jmpInstr := &ssa.If{Cond: binOpInstr}
		*binOpInstr.Referrers() = append(*binOpInstr.Referrers(), jmpInstr)

		trashBlock := &ssa.BasicBlock{
			Comment: "ctrflow.trash." + strconv.Itoa(targetBlock.Index),
			Instrs: []ssa.Instruction{
				ssa2ast.MarkerInstr,
				&ssa.Jump{},
			},
		}
		setBlockParent(trashBlock, ssaFunc)

		trashBlockDispatch := &ssa.BasicBlock{
			Comment: "ctrflow.trash.cond." + strconv.Itoa(targetBlock.Index),
			Instrs: []ssa.Instruction{
				phiInstr,
				binOpInstr,
				jmpInstr,
			},
			Preds: []*ssa.BasicBlock{targetBlock},
			Succs: []*ssa.BasicBlock{trashBlock, succs},
		}
		setBlockParent(trashBlockDispatch, ssaFunc)
		targetBlock.Succs[succsIdx] = trashBlockDispatch

		// Update the successor's Preds so that phi resolution sees
		// trashBlockDispatch as the predecessor instead of targetBlock.
		for pi, pred := range succs.Preds {
			if pred == targetBlock {
				succs.Preds[pi] = trashBlockDispatch
				break
			}
		}

		trashBlock.Preds = []*ssa.BasicBlock{trashBlockDispatch, trashBlock}
		trashBlock.Succs = []*ssa.BasicBlock{trashBlock}

		ssaFunc.Blocks = append(ssaFunc.Blocks, trashBlockDispatch, trashBlock)
	}
}

func fixBlockIndexes(ssaFunc *ssa.Function) {
	for i, block := range ssaFunc.Blocks {
		block.Index = i
	}
}

// validateSSAIntegrity performs basic structural checks on the SSA function
// after control-flow transforms. It returns a non-nil error describing the
// first inconsistency found, or nil if the graph looks sound.
//
// NOTE: The flattening algorithm intentionally breaks the Succs↔Preds duality.
// After flattening, block.Succs points to new ctrflow.jump blocks, but the
// original targetBlock.Preds still lists the old predecessors. This is by
// design: the SSA→AST converter uses goto-based dispatch, and phi assignments
// are placed in predecessor blocks listed in Preds. The old predecessors
// still execute before the dispatcher reaches the target, so phi values are
// set correctly. Therefore we do NOT check Succs→Preds duality here.
//
// Checks performed:
//   - Every block in ssaFunc.Blocks has a sequential Index matching its position.
//   - No nil entries in Preds or Succs slices.
//   - For every Phi instruction, len(Edges) == len(block.Preds).
func validateSSAIntegrity(ssaFunc *ssa.Function) error {
	for i, b := range ssaFunc.Blocks {
		if b.Index != i {
			return fmt.Errorf("block %d has Index=%d (want %d)", i, b.Index, i)
		}
	}

	for i, b := range ssaFunc.Blocks {
		for si, s := range b.Succs {
			if s == nil {
				return fmt.Errorf("block %d Succs[%d] is nil", i, si)
			}
		}

		for pi, p := range b.Preds {
			if p == nil {
				return fmt.Errorf("block %d Preds[%d] is nil", i, pi)
			}
		}

		// Validate Phi edges match Preds count
		for _, instr := range b.Instrs {
			phi, ok := instr.(*ssa.Phi)
			if !ok {
				break // Phi nodes are always at the start
			}
			if len(phi.Edges) != len(b.Preds) {
				return fmt.Errorf("block %d (%s) Phi has %d edges but %d preds",
					i, b.Comment, len(phi.Edges), len(b.Preds))
			}
		}
	}
	return nil
}
