# Chapter 10 Workbook — Dynamic Taint Analysis Principles

Return to [[../Chapter 10 - Dynamic Taint Analysis Principles]].

# Chapter Practice Set

## Recall Questions — 10
1. Define DTA.
2. Define taint source.
3. Define taint sink.
4. Define propagation policy.
5. Define taint granularity.
6. Define taint color.
7. Define overtaint.
8. Define undertaint.
9. Define implicit flow.
10. Define shadow memory.

## Conceptual Questions — 10
11. Why is DTA path-specific?
12. Why is a tainted sink not automatically vulnerable?
13. Why should `xor r,r` clear old taint?
14. Why does simple union propagation overtaint?
15. Why do multiple colors help?
16. Why is bit-level taint expensive?
17. Why are control dependencies hard?
18. Why does missing one instruction semantic matter?
19. Why does DTA need library/syscall models?
20. Why can validation leave a length tainted but safe?

## Application Problems — 10
21. Define integrity policy for network bytes reaching return target.
22. Define confidentiality policy for secret file to socket.
23. Propagate tags through `mov`, `add`, and zero idiom.
24. Compare byte and word taint for one changed byte.
25. A branch on secret writes constants. Identify missed flow.
26. Claimed length is tainted and bounds-checked. Interpret alert.
27. Heartbleed-style response leaks adjacent marker. Choose source/sink.
28. Sanitizer hashes input to a boolean. Should taint clear?
29. Two input channels influence one address. What color result?
30. A sink executes only on an untested path. What can DTA conclude?

## Multi-Step Problems — 5
31. Design a control-hijack DTA detector.
32. Design a data-exfiltration detector.
33. Design shadow-memory organization.
34. Diagnose overtaint in a parser.
35. Diagnose undertaint in a state machine.

## Challenging Problems — 5
36. Track taint through lookup tables.
37. Bound program-counter taint with post-dominators.
38. Model sanitization without false trust.
39. Compare DTA with backward slicing and symbolic execution.
40. Evaluate DTA soundness under threads/self-modification.

## Trick / Misconception Questions — 5
41. True or false: untainted sink proves safety.
42. True or false: tainted branch proves exploitability.
43. True or false: all arithmetic should union tags.
44. True or false: one taint bit preserves provenance.
45. True or false: explicit-flow tracking catches every information flow.

## Case-Based Questions — 3
46. A secret-derived encrypted buffer is sent to an approved server. Interpret.
47. Input controls an array index after validation. Build policy-aware conclusion.
48. DTA misses a demonstrated control transfer. Debug systematically.

# Complete Solutions

## Recall solutions
1. Runtime tracking of policy labels through executed data/information flows.
2. Event/data where labels are introduced with provenance.
3. Security-relevant use where labels are inspected.
4. Semantics deciding destination tags from operand/control tags.
5. Unit labeled: bit, byte, word, object, etc.
6. Identity/provenance label distinguishing sources/classes.
7. Labels spread beyond true semantic dependence, causing noise.
8. True influence loses/fails to receive label, causing misses.
9. Information transfer through control choice rather than explicit data copy.
10. Metadata address space mapping application registers/memory to tags.

## Conceptual solutions
11. Instrumentation follows concrete execution; unexecuted branches are not propagated/checked.
12. Influence can be intended and validated; security invariant/context determines danger.
13. Result is constant zero independent of previous value; operand identity matters.
14. Identities/masks/cancellations can remove semantic dependence even when operands were tagged.
15. They identify which source/bytes contributed and support policy by origin.
16. More metadata and fine-grained propagation/composition per operation.
17. A predicate can influence large/nested regions; determining dependence end and avoiding label explosion is difficult.
18. One lost/mispropagated tag breaks downstream provenance and creates false results.
19. External/native code changes buffers/returns and high-level routines have semantics expensive/impossible to infer instruction-by-instruction.
20. Taint denotes origin/control, while a dominating correct range check can establish allowed use.

## Application solutions
21. Source actual bytes returned by recv/read; propagate; sink every executed indirect call/jump/return target; report source colors, site, concrete target, run.
22. Color actual bytes read from selected secret identities; propagate; inspect actual bytes passed to untrusted output descriptors/destinations.
23. `mov`: copy source tags; `add`: usually union both operand tags; `xor r,r`: empty result tag because zero.
24. Byte taint labels only influenced byte(s); word policy smears label across whole machine word, cheaper but less precise.
25. Implicit control flow: secret predicate selects untainted constants. Add PC/control taint if property requires it.
26. It proves untrusted origin reaches length, not violation. Verify the check dominates use and capacity assumptions; classify safe controlled value if correct.
27. Mark synthetic secret/adjacent memory as source and outbound network bytes as sink for confidentiality; alternatively taint claimed length plus add explicit bounds model.
28. Depends on property. Boolean still depends on input; retain provenance for influence. “Sanitized” may change trust policy only after proving semantic guarantee.
29. Union/set of both colors, unless policy deliberately records coarser combined label.
30. Nothing about that path; only absence/presence on executed runs.

## Multi-step solutions
31. Select untrusted channels; tag actual returned bytes; precise register/memory propagation; inspect target expression tags before indirect transfers; log provenance/concrete state; test safe/overflow toy; document implicit/coverage limits.
32. Track file identity through open/dup/close; tag actual read/mmap bytes; identify socket/untrusted output; inspect actual sent ranges/iovecs; handle fd reuse/processes; allowlist authorized flows.
33. Choose byte labels, sparse page hierarchy/direct mapping tradeoff, register shadow, color-set representation, thread safety, bounds, lazy allocation, and benchmark lookup/memory.
34. Trace first unexpected label backward; inspect union identities, coarse granularity, PC taint lifetime, library summaries, and aliasing; refine semantics without dropping real influence.
35. Compare real input-to-sink trace; find first tag loss; inspect unsupported instruction, implicit branch, syscall/library summary, partial register/memory width, thread state, or concretization.

## Challenging solutions
36. Index tag may influence which table value is selected even if table bytes untainted. Explicit address-dependence policy can taint loaded result by address tag; increases overtaint and must be documented.
37. Taint PC when branch condition tagged; propagate to assignments until immediate post-dominator where branch paths reconverge, while treating exceptions/loops carefully. It approximates control region, not perfect information flow.
38. Define exact property guaranteed (range/grammar/authentication), require check dominance and no later transformation invalidation, perhaps attach refined label rather than clear provenance, and test bypass/edge cases.
39. DTA cheaply tracks executed provenance; backward slice narrows definitions for target; symbolic execution represents value/path alternatives and can create inputs. Combine with distinct claims.
40. Races reorder flows and shared shadow updates; self-modification invalidates instrumentation semantics. Need synchronized tags, code invalidation/versioning, per-thread state, and explicit schedule/code coverage limitations.

## Misconception solutions
41. False: policy/path/implementation can miss flow.
42. False: intended validated control exists; primitive/impact separate.
43. False: zero/cancellation/masks need semantic rules.
44. False: it says tainted/not, not which source.
45. False: implicit flows are missed.

## Case solutions
46. Under explicit policy, secret influences output; encryption may be intended confidentiality protection and destination approved. Report provenance, authorization/context, ciphertext policy, and avoid “exfiltration” claim.
47. Taint shows input influence. Prove index range against element count, signedness, check dominance, later truncation, and actual address. Safe result can remain tainted.
48. Reproduce exact run; confirm source event/actual length; trace expected tags stepwise; inspect unsupported ops, partial writes, implicit flows, library/syscall model, threads, code version, and sink hook timing.
