# Chapter 8 Workbook — Customizing Disassembly with Capstone

Return to [[../Chapter 08 - Customizing Disassembly with Capstone]].

# Chapter Practice Set

## Recall Questions — 10
1. What does Capstone do?
2. What must be configured before decoding?
3. What does detail mode provide?
4. Define a disassembly seed.
5. What data structure drives recursive traversal?
6. When does a conditional block end?
7. What is an unresolved edge?
8. Why scan backward from `ret` candidates?
9. What is a gadget side effect?
10. What is semantic deduplication?

## Conceptual Questions — 10
11. Why build a custom pass?
12. Why not parse operand text?
13. Why must decode failure policy be explicit?
14. Why validate targets against mappings?
15. Why split a block on an interior target?
16. Why do indirect transfers limit recursion?
17. Why are ordinary boundaries insufficient for gadget search?
18. Why does a found gadget not imply exploitation?
19. Why preserve overlapping streams?
20. Why combine trace seeds with static analysis?

## Application Problems — 10
21. Classify direct call successors.
22. Classify conditional branch successors.
23. Classify unconditional jump successors.
24. Classify return successors.
25. A target is outside executable ranges. Record what?
26. Decode succeeds but length crosses range end. Accept?
27. New target lands at second instruction of block. Repair CFG.
28. Candidate bytes decode to two instructions then `ret`, but leave a byte gap. Gadget?
29. Gadget contains `mov [rax],rbx`. What constraint matters?
30. Trace observes a new indirect target. How integrate?

## Multi-Step Problems — 5
31. Design typed Capstone wrapper.
32. Implement recursive traversal with functions separate from blocks.
33. Implement bounded gadget scan.
34. Add jump-table recovery.
35. Export deterministic DOT/JSON.

## Challenging Problems — 5
36. Handle overlapping instruction streams.
37. Resolve a register-indirect jump using backward slicing.
38. Deduplicate gadgets by semantics while retaining occurrences.
39. Design hostile decoder/CFG fuzz tests.
40. Compare custom pass with a full RE platform.

## Trick / Misconception Questions — 5
41. True or false: Capstone identifies functions.
42. True or false: every decoded direct target is valid.
43. True or false: visited bytes can never be decoded from another start.
44. True or false: gadget scanner should start only at function instructions.
45. True or false: `pop rdi; ret` changes only `rdi`.

## Case-Based Questions — 3
46. Obfuscation adds bogus conditional edges. Build confidence policy.
47. Scanner finds millions of gadgets in data. Diagnose.
48. Static CFG misses runtime-generated code. Extend architecture.

# Complete Solutions

## Recall solutions
1. It decodes supplied bytes/address under configured ISA/mode into instruction objects.
2. Architecture, mode/bitness/endianness as relevant, syntax, and detail option.
3. Typed operands, groups, register reads/writes, and architecture detail used for flow/effects.
4. Validated candidate instruction-entry address from metadata, calls, exports, traces, etc.
5. A worklist/queue plus block/leader/visited-start maps.
6. At conditional transfer; add taken target and fall-through.
7. A possible control successor whose concrete/static target set is not recovered.
8. x86 has no unique backward decode; try starts and validate forward ending exactly at terminator.
9. Any changed register/flags/memory/stack/fault requirement beyond intended operation.
10. Grouping sequences with equivalent normalized effects while preserving addresses as occurrences.

## Conceptual solutions
11. Encode target/domain knowledge, specialized output, obfuscation policy, scanners, and research analyses absent from generic tool.
12. Text syntax varies and loses operand structure; typed metadata avoids fragile string parsing.
13. Stop, data-byte recovery, or resync produce different false positives/coverage; users must know which occurred.
14. Corrupt/immediate data can point anywhere; following blindly causes OOB reads and bogus CFG.
15. Basic-block single-entry property is violated; predecessors must target a new leader block.
16. Target is computed from runtime/data state and may require value analysis or traces.
17. Gadgets can begin inside bytes of ordinary instructions because variable-length x86 permits alternate streams.
18. Address knowledge, stack control, side effects, mitigations, bad bytes, and a vulnerable primitive are separate requirements.
19. Both may be reachable under obfuscation/state; byte-level suppression converts uncertainty to false certainty.
20. Traces provide concrete generated/indirect entries; static analysis explores direct alternatives not executed. Keep provenance distinct.

## Application solutions
21. Record callee as function seed and fall-through as continuing caller edge according to interprocedural policy.
22. Taken target plus next instruction.
23. Direct target only; no fall-through.
24. No intraprocedural successor; interprocedural return relation is separate.
25. External/out-of-model edge with raw target and reason; do not decode memory blindly.
26. No. Decoder read/semantic span must fit validated file-backed range.
27. Split at target, move suffix, repair edges/leaders and any predecessor that formerly entered old start.
28. No; accepted sequence must cover exactly from proposed start through terminator with no gap/extra byte.
29. `rax` must be valid writable and write side effect acceptable; `rbx` value, flags, and stack delta also matter.
30. Add observed edge/seed with run provenance and code version; do not mark it exhaustive.

## Multi-step solutions
31. Own Capstone handle; decode one bounded instruction; copy address/size/bytes/id/typed operands/register effects/groups; classify flow; return explicit error; test every transfer family.
32. Worklist block leaders; decode/split/edges; separate function seeds from intraprocedural CFG; retain shared/tail blocks and unresolved transfers; provenance/confidence fields.
33. Enumerate executable file-backed bytes for terminators; for each bounded backward start decode forward; require exact terminal alignment/instruction count; reject unsafe categories by policy; annotate effects/deduplicate.
34. Require dominating index bound, validated table base/range/entry width/encoding, target mapping, bounded cases; add heuristic targets and verify traces/relocations.
35. Sort modules/functions/blocks/edges by stable keys, normalize addresses, escape labels, version schema, represent 64-bit losslessly, and make repeated runs byte-identical.

## Challenging solutions
36. Track instruction starts/streams rather than globally consumed bytes, maintain overlap relation, seek incoming edges and runtime observations, and present alternatives.
37. Slice definitions of target register through block/predecessors; model loads/constants/arithmetic, aliases and bounds; derive finite set or unresolved expression; validate targets/mappings/traces.
38. Normalize instruction semantic effects, stack delta, clobbers, memory preconditions, and final control; key semantics separately from list of module offsets/bytes.
39. Random/truncated ranges, targets at boundaries/outside, overlapping leaders, invalid encodings, huge worklists, self loops, jump tables, alternate starts; enforce resource limits and sanitizers.
40. Custom tool is transparent/narrow/automatable but lacks mature loaders, types, UI, decompiler, signatures. Integrate/export rather than recreating everything unless research requires it.

## Misconception solutions
41. False: decoder only; function recovery is a higher layer.
42. False: validate mapping/range and semantics.
43. False: overlapping streams exist.
44. False: alternate-boundary gadgets are central.
45. False: it changes `rsp`, consumes memory, may affect alignment/fault, then `ret` consumes target.

## Case solutions
46. Mark statically possible edges, prove opaque predicates with bounded solver/data-flow only when sound, record executed edges, and never delete an edge solely because tests did not take it.
47. Scanner likely used non-executable/file data or failed exact-end validation. Restrict ranges, require valid forward sequence ending at terminator, cap length, and annotate data overlap.
48. Add dynamic code-range/version model and trace import backend; seed observed executions, store runtime bytes/module mapping, disassemble versions, and keep static file CFG distinct.
