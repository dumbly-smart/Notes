# Chapter 12 Workbook — Symbolic Execution Principles

Return to [[../Chapter 12 - Symbolic Execution Principles]].

# Chapter Practice Set

## Recall Questions — 10
1. Define symbolic value.
2. Define symbolic state.
3. Define path constraint.
4. Define concrete execution.
5. Define concolic execution.
6. What does `sat` mean?
7. What does `unsat` mean?
8. What does `unknown` mean?
9. Define bitvector.
10. Define path explosion.

## Conceptual Questions — 10
11. Why does symbolic branching fork states?
12. Why is reachability a satisfiability question?
13. Why is validity checked by negation?
14. Why use bitvectors rather than integers for machine code?
15. Why do signed/unsigned relations differ on same bits?
16. Why are symbolic pointers difficult?
17. Why do loops explode paths/states?
18. Why summarize libraries/syscalls?
19. Why does concretization lose completeness?
20. Why replay every model?

## Application Problems — 10
21. Derive success constraint for `y=x+3; y==10`.
22. Solve 8-bit `x+250=10`.
23. Interpret signed/unsigned `0xff` as 8-bit.
24. Prove formula valid using solver query.
25. Form query to reach third branch after `C1,C2,C3`.
26. Form query to flip second branch while preserving prefix.
27. Bound 20 independent branches: maximum paths?
28. A solver returns `unknown`. What claim allowed?
29. Symbolic length indexes memory. Name constraints needed.
30. Generated input fails replay. List first checks.

## Multi-Step Problems — 5
31. Symbolically execute a two-branch function.
32. Design bounded target-reach analysis.
33. Build a concolic coverage loop.
34. Model an opaque predicate over 8-bit values.
35. Compare integer and bitvector solutions for overflow equation.

## Challenging Problems — 5
36. Merge states safely at reconvergence.
37. Handle symbolic memory address conservatively.
38. Simplify expressions without changing widths.
39. Model environment-dependent file read.
40. Prioritize paths toward a target under budget.

## Trick / Misconception Questions — 5
41. True or false: `sat` proves deployed reachability.
42. True or false: `unknown` means impossible.
43. True or false: mathematical integers model unsigned wrap automatically.
44. True or false: concolic execution explores every path.
45. True or false: a solver model is a finished exploit.

## Case-Based Questions — 3
46. Solver says branch unreachable but fuzzer reaches it. Debug.
47. Crypto check stalls solver. Redesign analysis.
48. Threads make path result nondeterministic. Scope claim.

# Complete Solutions

## Recall solutions
1. Expression representing one or many concrete values through symbolic variables.
2. Program counter, concrete/symbolic registers/memory, path condition, and modeled environment.
3. Conjunction of predicates required by decisions along a path.
4. Execution using one specific value/state per input.
5. Concrete run with parallel symbolic expressions and alternative-branch solving.
6. A model exists satisfying encoded constraints.
7. No model exists under encoded logic/assumptions.
8. Solver did not establish sat or unsat; make neither conclusion.
9. Fixed-width modular value matching machine integer operations.
10. Exponential/unbounded growth of possible execution paths/states.

## Conceptual solutions
11. Each feasible taken/not-taken condition represents different state set and path constraint.
12. Target is reachable in model iff initial assumptions plus path/goal have a satisfying input/state.
13. `F` valid means no counterexample; ask whether `¬F` is unsatisfiable.
14. They encode exact widths, wrap, extract/extend, bit operations and machine comparisons.
15. Top bit changes signed interpretation; relations use different flag/logical meanings.
16. It may alias many locations, multiplying states/constraints; memory model must choose ranges/objects.
17. Each iteration can fork and unbounded iterations produce infinitely many paths absent bounds/invariants.
18. Full implementation is costly/path-heavy; summaries encode relevant effects and reduce states.
19. Fixing symbolic value selects one case and discards alternatives unless revisited.
20. Model can omit environment/instructions or target wrong version; concrete execution validates candidate reality.

## Application solutions
21. `X+3=10`, so mathematical/unbounded solution `X=7`; add width semantics if machine integer.
22. Mod 256, `x=16` because `16+250=266≡10`.
23. Unsigned 255; signed two’s-complement -1.
24. Assert `¬F` with assumptions; `unsat` proves `F` valid in model.
25. `C1 ∧ C2 ∧ C3 ∧ goal_at_third_successor` according to actual branch orientations.
26. `C1 ∧ ¬C2`; omit later `C3` from old path.
27. Up to `2^20=1,048,576`, before infeasibility/correlation reductions.
28. Only “undetermined”; try another tactic/solver/bound or concrete evidence.
29. Valid object/range, `index<size`, address arithmetic width/no wrap, initialized bytes, alias/environment constraints.
30. Exact hash/input encoding, path prefix, widths/signedness, syscall/library model, ASLR/environment, unsupported semantics/concretization.

## Multi-step solutions
31. Replace input with `X`; execute assignments as expressions; at first branch fork `PC∧C1`/`PC∧¬C1`; update states; repeat second branch; solve each leaf; replay representatives.
32. Choose start/goal; symbolize minimal bytes; model required memory/syscalls; cap input/loops/time; CFG distance search; query goal; record unsupported assumptions; replay.
33. Run seed; collect ordered constraints/coverage; choose unseen alternative; preserve earlier prefix and negate chosen branch; solve/model input; concrete run; retain new coverage; queue until budget/no progress.
34. Encode exact 8-bit expression and negation; solver unsat proves opaque under assumptions; also reason algebraically and exhaustively test 256 values as independent check.
35. Solve once with Int and once BitVec; show modulo wrap differences and signed/unsigned comparisons. Machine behavior follows bitvector width.

## Challenging solutions
36. At same PC, use guarded expressions/ITE or merge memory/register values under path predicates only when compatible; disjoin path constraints; control expression growth and preserve side effects.
37. Bound pointer to known objects/ranges, fork candidate aliases or use array theory, reject unmapped targets, cap set; otherwise concretize with explicit incompleteness.
38. Apply width-aware identities, constant fold modulo `2^n`, preserve sign/zero extensions and extraction order; differential solver equivalence check (`old != new` unsat).
39. Symbolize returned bytes/count within bounds, encode errors/short reads relevant to goal, or hook with controlled fixture. State filesystem model explicitly.
40. Use static CFG distance, coverage novelty, constraint complexity, input relevance/slicing, loop limits, and solver timeouts; retain fairness to avoid permanent starvation.

## Misconception solutions
41. False: it proves model satisfiable; replay/environment needed.
42. False: undetermined.
43. False: use fixed-width bitvectors.
44. False: path explosion/bounds remain.
45. False: root cause, primitive, mitigations, objective/reliability separate.

## Case solutions
46. Confirm same binary/input; inspect missing instruction/syscall, width/signedness, overconstraint, concretized pointer, self-modification, environment and thread schedule; import concrete trace and locate first model divergence.
47. Concretize/hook well-tested crypto, symbolize compared digest/result or use input-format knowledge, backward slice to pre-crypto conditions, fuzz/mutate around structure. State that bypassed crypto internals are assumed.
48. Treat schedule/environment as part of model; reproduce one controlled schedule, enumerate/symbolize bounded interleavings if feasible, and claim reachability only under specified schedule rather than universal behavior.
