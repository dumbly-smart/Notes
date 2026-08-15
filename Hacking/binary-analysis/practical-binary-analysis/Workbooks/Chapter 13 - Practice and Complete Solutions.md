# Chapter 13 Workbook — Practical Symbolic Execution with Triton

Return to [[../Chapter 13 - Practical Symbolic Execution with Triton]]. Authorized toys only.

# Chapter Practice Set

## Recall Questions — 10
1. What does Triton provide?
2. What is an AST?
3. What is symbolic variable provenance?
4. Define backward slice.
5. Why maintain concrete state?
6. What is a path-constraint prefix?
7. What does branch negation generate?
8. What is a benign control target?
9. What is a code-coverage worklist?
10. What is model replay?

## Conceptual Questions — 10
11. Why preserve AST widths?
12. Why synchronize syscall effects?
13. Why does backward slicing scale analysis?
14. Why map variables to input offsets?
15. Why omit later constraints when flipping an earlier branch?
16. Why can BFS and DFS find different paths under budget?
17. Why is root cause different from symbolic sink?
18. Why is target-address knowledge separate from IP control?
19. Why use `win()` instead of a privileged shell in labs?
20. Why does a Triton model remain environment-relative?

## Application Problems — 10
21. Draw AST for `(x^0x13)+3`.
22. Slice a branch depending only on input bytes 0 and 3.
23. Flip third constraint among `C1,C2,C3,C4`.
24. Preserve first branch and flip second.
25. A read returns 5 bytes into memory. Synchronize state.
26. A symbolic byte maps to argv offset 7. What report metadata?
27. Solver candidate contains forbidden NUL. Add constraint.
28. PIE randomizes `win`. What additional fact is needed?
29. Generated case reaches no new edge. Worklist action?
30. Concrete replay diverges at syscall. Diagnose.

## Multi-Step Problems — 5
31. Build a Triton emulation loop.
32. Build backward-slice tool.
33. Build concolic coverage generator.
34. Build benign exploit-input generator for toy overflow.
35. Validate AST simplification.

## Challenging Problems — 5
36. Model self-modifying code.
37. Handle symbolic indirect jump targets.
38. Manage state explosion with loops.
39. Combine taint and symbolic execution.
40. Compare Triton emulation with full-system execution.

## Trick / Misconception Questions — 5
41. True or false: AST text alone preserves semantics.
42. True or false: backward slice proves irrelevant input can never matter.
43. True or false: negating `C2` should retain `C3,C4`.
44. True or false: solved return target proves production RCE.
45. True or false: exact source code is recovered from ASTs.

## Case-Based Questions — 3
46. Coverage tool repeatedly generates duplicate inputs. Repair.
47. Exploit generator works only with ASLR disabled. Correct claim/design.
48. Triton and hardware disagree after partial-register operation. Debug.

# Complete Solutions

## Recall solutions
1. Architecture instruction semantics, concrete/symbolic state, ASTs, taint and solver integration.
2. Typed tree of operations/operands representing symbolic expression.
3. Mapping from symbolic variable back to original input/channel/offset/event.
4. Dependency subgraph needed to compute a chosen expression/sink.
5. It drives current path, addresses, decoding, and concrete interaction while symbolic expressions track alternatives.
6. Constraints for decisions before a selected branch.
7. Solver query/input for alternate successor under preserved prefix.
8. Authorized lab function/marker demonstrating control without harmful payload.
9. Pending seeds/branches/states prioritized for new coverage.
10. Execute solver-produced bytes on exact target and compare expected path/effect.

## Conceptual solutions
11. Machine operations wrap/extract/extend; removing widths changes algebra and solutions.
12. External operations write memory/registers and return values unknown to emulator; stale state diverges.
13. It removes expressions/bytes not influencing target under modeled dependency graph, reducing solver load.
14. A model is useful only if values can be materialized at correct positions/channels.
15. They belong to old path after decision and may contradict alternate successor.
16. BFS spends budget shallow/wide; DFS dives; finite budget makes search order decisive.
17. Root cause is violated invariant enabling corruption; sink is constrained target/use; each needs its own evidence.
18. Controlling bits is not knowing a useful randomized address or satisfying CFI/alignment/bad bytes.
19. It proves scoped control safely, deterministically, and without privileged post-exploitation behavior.
20. Hooks, memory, syscalls, modules, versions, and concretizations define model.

## Application solutions
21. Root `add_8`; left child `xor_8(x_8,0x13_8)`; right `3_8`, preserving modulo width.
22. Traverse branch AST dependencies; retain transformations and symbolic variables for offsets 0/3; exclude other variables only under current model.
23. Assert `C1∧C2∧¬C3`; `C4` is omitted.
24. `C1∧¬C2`.
25. Set return register concrete 5, write five concrete bytes at destination, symbolize/tag them if input policy, leave remainder unchanged, advance according to syscall model.
26. Input channel/argv index, byte offset 7, symbolic ID/name, concrete seed byte, constraints/model value, target hash/run.
27. Add byte `!=0` constraints for affected positions (and encoding/range constraints), re-solve; do not strip NUL afterward because that changes model.
28. A legitimate runtime base/address leak or relocatable target strategy under actual environment; fixed static address alone is insufficient.
29. Deduplicate by bytes/path/coverage, mark attempted branch, inspect model mismatch, choose next pending alternative; avoid endless requeue.
30. Compare exact syscall args/result/environment with hook summary; update concrete memory/return/error and symbolic effects; replay from first divergence.

## Multi-step solutions
31. Configure architecture/modes; fetch bounded instruction; set concrete registers/memory; symbolize chosen inputs; process instruction semantics; handle external events; update PC; collect constraints/events until goal/budget.
32. Select sink symbolic expression; retrieve dependencies/AST; recursively collect parent symbolic expressions and variables; map to input offsets; export operations and confidence; verify by mutating excluded/included bytes.
33. Run seed concretely/emulated; collect branches/coverage; queue alternate constraints; preserve prefix/negate one; solve with input constraints; materialize; replay; retain novel cases; resource/dedup controls.
34. Prove toy overflow root cause/offset; symbolize input; execute to saved benign control target use; constrain target to `win()` and format bytes; solve; replay hardened/unhardened variants; report primitive/mitigation differences.
35. Ask solver for counterexample `original != simplified`; unsat at exact widths establishes equivalence in solver logic. Add random concrete differential tests and edge values.

## Challenging solutions
36. Observe writes to code memory, update concrete bytes, invalidate decoded/semantic cache, create code versions, then fetch new bytes. Symbolic code bytes may be unsupported/explosive; bound/concretize explicitly.
37. Solve target expression under path constraints for bounded executable ranges/alignment; enumerate models with blocking clauses/resource cap; seed CFG/paths and retain unresolved remainder.
38. Bound/unroll, detect repeated states, summarize invariants/functions, merge compatible states, prioritize novelty/target distance, and cut solver-hard paths with documented incompleteness.
39. Use taint to choose relevant inputs/sinks and symbolic variables; symbolic analysis solves values/alternate paths; maintain separate meaning because taint union and AST dependence differ.
40. Triton client controls environment and can slice/solve precisely but must emulate syscalls/instructions; full-system execution gives realistic OS/device state with higher complexity. Concolic trace bridges them.

## Misconception solutions
41. False: operation IDs, widths, signed relations, provenance matter beyond rendering.
42. False: only irrelevant to selected expression under executed/model dependencies.
43. False: later constraints belong to old branch outcome.
44. False: address knowledge, mitigations, reliability, environment and objective remain.
45. False: ASTs represent machine semantics, not lost historical source.

## Case solutions
46. Canonicalize input/model, block previous models, preserve correct prefix only, validate branch orientation, deduplicate worklist and track attempted alternatives; inspect concretized bytes not actually symbolic.
47. Claim only control in non-ASLR lab. For real protections require legitimate base knowledge/leak and PIE-aware offsets; test clean randomized runs. Do not disable ASLR in final impact assessment.
48. Verify architecture mode and semantics: 32-bit write zeroes upper 32 bits on x86-64, 8/16-bit writes preserve others; check high-byte regs, width/extract/extend ASTs, concrete sync, and differential minimal test.
