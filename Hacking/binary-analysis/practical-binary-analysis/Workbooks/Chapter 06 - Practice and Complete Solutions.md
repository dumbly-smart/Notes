# Chapter 6 Workbook — Disassembly and Analysis Fundamentals

Return to [[../Chapter 06 - Disassembly and Analysis Fundamentals]].

# Chapter Practice Set

## Recall Questions — 10
1. Define linear-sweep disassembly.
2. Define recursive traversal.
3. What is dynamic disassembly?
4. Define a basic block.
5. Define a CFG.
6. What is an IR?
7. What is an over-approximation?
8. What is an under-approximation?
9. Define reaching definitions.
10. Define liveness.

## Conceptual Questions — 10
11. Why does inline data confuse linear sweep?
12. Why does recursive traversal miss code?
13. Why does a dynamic trace handle generated code well?
14. Why does it still lack completeness?
15. Why is a prologue not proof of function start?
16. Why does decompilation invent types/names?
17. Why does an IR need exact widths and flags?
18. Why are indirect target sets often conservative?
19. Why do data-flow equations iterate to a fixed point?
20. Why does optimization change function and variable visibility?

## Application Problems — 10
21. Split a conditional branch sequence into blocks.
22. Give successors for direct call, conditional jump, direct jump, indirect jump, and return.
23. A branch target lands inside an existing block. What must change?
24. Decode fails in linear mode. Name three explicit recovery policies.
25. A switch jump target is unresolved. What evidence helps?
26. At a merge, definitions `x=1` and `x=2` reach a use. State `IN` fact.
27. `cmp eax,10; jbe`. Infer comparison interpretation.
28. A decompiler says `char *`, but code loads 4-byte elements. Correct response?
29. Trace covers 80% of blocks. What must be stated?
30. A tail call appears as `jmp`. How can it affect function recovery?

## Multi-Step Problems — 5
31. Build a recursive CFG algorithm with splitting and unresolved edges.
32. Combine static CFG and traces into confidence-labeled coverage.
33. Compute reaching definitions on a diamond and loop.
34. Recover a structure from offset/width/use evidence.
35. Validate decompiler output for a security-relevant bounds check.

## Challenging Problems — 5
36. Analyze overlapping instruction streams without forcing one answer.
37. Recover a bounded jump table safely.
38. Explain soundness/completeness tradeoffs for indirect calls.
39. Design an IR test suite for flags and partial registers.
40. Distinguish a thunk, tail call, shared epilogue, and ordinary function.

## Trick / Misconception Questions — 5
41. True or false: every byte in `.text` is an instruction.
42. True or false: recursive traversal finds all real code.
43. True or false: executed coverage proves unexecuted paths impossible.
44. True or false: decompiler C is recovered source.
45. True or false: registers have inherent signed types.

## Case-Based Questions — 3
46. An obfuscated binary jumps over bytes that decode as calls. Compare algorithms and proof.
47. A CFG has thousands of indirect edges. Design refinement.
48. A vulnerability depends on signed/unsigned comparison. Establish exact semantics.

# Complete Solutions

## Recall solutions
1. Decode sequentially from a range start, advancing by decoded length; fast/high coverage but data/boundary sensitive.
2. Seed known entries and follow control successors using a worklist; CFG-aware but target/seed limited.
3. Decode/record instructions that actually execute in one or more runs.
4. Maximal straight-line sequence with one entry and transfer-ending boundary under the analysis model.
5. Graph of blocks/nodes and possible control-transfer edges.
6. Normalized semantic operations supporting architecture-independent analysis.
7. A result containing all real possibilities plus possible false ones.
8. A result containing observed/proven subset that can miss possibilities.
9. Which assignments may reach each program point without intervening kill.
10. Whether a value may be used on a future path before redefinition.

## Conceptual solutions
11. It decodes every selected byte and has no control-flow reason to skip embedded table/padding.
12. Missing seeds, indirect targets, callbacks, exception paths, and unsupported semantics block discovery.
13. It reads bytes at execution time and observes concrete indirect targets/self-modified code.
14. Other inputs, environment, schedules, and states can execute other paths.
15. Optimizers omit prologues; data can mimic them; functions can have multiple entries/tails. Use calls, metadata, CFG, and runtime evidence.
16. Compilation discards them; decompiler infers a readable consistent model.
17. Wrong flag/width/extension semantics corrupt branch and data-flow conclusions.
18. Alias/value uncertainty forces including multiple possible values to avoid missing a real edge.
19. Loops propagate facts around cycles; repeated transfer reaches stable solution for finite monotone domains.
20. Inlining, register allocation, tail merging, dead elimination, and LTO change surface while preserving behavior.

## Application solutions
21. Leaders are entry, branch targets, and conditional fall-through; end blocks at conditional/terminal transfers.
22. Call: callee+fallthrough by policy; conditional: target+fallthrough; jump: target; indirect: resolved set/unknown; return: none intraprocedurally.
23. Split old block at target, move suffix to new block, and repair predecessor/successor edges.
24. Stop; emit one data byte and advance; skip to known boundary—each must be labeled because resynchronization can fabricate code.
25. Dominating bounds check, table base/entry width, relocations, read-only data, target range, runtime observed targets.
26. `IN[merge]` contains both definitions unless path constraints/data-flow refinement excludes one.
27. Unsigned below-or-equal (`eax <= 10` unsigned) because `jbe` consumes CF/ZF.
28. Mark decompiler type uncertain/wrong; infer 4-byte element array/scalar from repeated access and consumers.
29. Coverage metric/denominator, inputs/environment, tool model, executed version, and that 20% plus paths remain unexplored.
30. It transfers without returning and can look intra-function; use ABI, block ownership, separate callers/symbols, and stack behavior.

## Multi-step solutions
31. Validate seed/range; worklist block starts; decode until terminator/known leader/error; add direct successors; mark unresolved indirect; split interior targets; maintain function seeds separately; never erase ambiguity.
32. Store static possible edges and dynamic observed edges separately, normalize modules, seed generated/indirect targets, calculate covered static candidates, and retain unknown/unobserved rather than deleting.
33. Compute each block’s GEN/KILL; initialize; apply union predecessor IN and transfer OUT repeatedly through diamond/loop until unchanged; then list definitions reaching each use.
34. Gather all base+offset accesses, widths/extensions, writers/readers, API consumers, array strides, lifetimes, and multiple instances; propose layout with unknown padding and test runtime values.
35. Identify source length/capacity types; inspect compare operands and signed branch; prove dominance over use; check transformations/truncation; run boundary values and watch actual copy/index.

## Challenging solutions
36. Record each stream start/bytes/edges/provenance; seek incoming branches and executed traces; both can be real. Byte-visited sets must not suppress alternate starts automatically.
37. Require validated bounds and entry count; safe table range; correct signed/relative entry decoding; every target executable; add candidates with heuristic confidence and observe traces.
38. A sound call graph may include false targets; a precise under-approximation misses real ones. Refine with points-to/value sets, type/CFI constraints, relocations, and dynamic evidence while stating remaining approximation.
39. Include arithmetic overflow/carry/sign/zero, shifts, compares, `adc/sbb`, partial-register writes, zero idioms, undefined flags, memory aliasing, and differential execution against hardware/emulator.
40. Thunk is small forwarding adapter; tail call ends with jump under calling convention; shared epilogue has multiple internal predecessors restoring/returning; ordinary function has independent entry/call/return evidence. Use graph/ABI, not size alone.

## Misconception solutions
41. False: padding/data/unreachable bytes exist.
42. False: it depends on seeds and target recovery.
43. False: trace is an under-approximation.
44. False: it is synthesized equivalent pseudocode.
45. False: operations/branches/extensions establish interpretation.

## Case solutions
46. Linear sweep emits bogus calls; recursive traversal follows jump and skips bytes. Validate jump execution, xrefs treating skipped range as data, and alternate-entry possibility.
47. Partition by call site; backward-slice target expression; apply constants, relocations, types, bounds, points-to/CFI, and observed targets; keep residual unknown edge.
48. Identify operand widths/definitions/extensions, compare and exact conditional mnemonic/flags, translate both signed and unsigned edge values, and run `-1,0,bound,bound+1,UINT_MAX` equivalents.
