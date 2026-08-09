# Chapter 9 Workbook — Binary Instrumentation

Return to [[../Chapter 09 - Binary Instrumentation]].

# Chapter Practice Set

## Recall Questions — 10
1. Define instrumentation.
2. Name three granularities.
3. Describe `int3` instrumentation.
4. Describe trampoline instrumentation.
5. Define DBI.
6. What is a code cache?
7. Define static instruction count.
8. Define dynamic instruction count.
9. What is a packer?
10. Define write-to-execute transition.

## Conceptual Questions — 10
11. Why choose the coarsest sufficient granularity?
12. Why are traps expensive?
13. Why is trampoline relocation difficult?
14. Why does DBI execute translated copies?
15. Why use thread-local counters?
16. Why normalize runtime addresses?
17. Why does write→execute suggest unpacking?
18. Why is it not proof of malicious packing?
19. Why is a memory dump not automatically executable?
20. Why can instrumentation alter behavior?

## Application Problems — 10
21. Count instructions with one callback per block.
22. Count branch taken/not-taken.
23. Attribute events in stripped PIE.
24. Aggregate per-thread counts.
25. Merge overlapping written intervals.
26. A jump enters a written interval. What record?
27. Same address executes changed bytes. What action?
28. Logs dominate runtime. Optimize.
29. A JIT triggers unpacker alerts. Refine.
30. Dumped region lacks imports. Next step?

## Multi-Step Problems — 5
31. Design a Pin-style profiler.
32. Design automatic unpacking detector.
33. Compare trap, trampoline, and DBI for coverage.
34. Validate instrumentation transparency.
35. Build backend-independent event schema.

## Challenging Problems — 5
36. Handle self-modifying code-cache invalidation.
37. Preserve thread/signal correctness in static breakpoint scheme.
38. Detect original entry when unpacker uses many generated stages.
39. Reconstruct a runnable image from memory.
40. Quantify overhead and bias.

## Trick / Misconception Questions — 5
41. True or false: block callback count equals instruction count.
42. True or false: global `++counter` is thread-safe.
43. True or false: write→execute always means malware.
44. True or false: raw runtime address is stable evidence under ASLR.
45. True or false: dumped memory bytes preserve original file layout.

## Case-Based Questions — 3
46. Profile a multithreaded stripped PIE reproducibly.
47. Unpack a benign UPX-like toy with several layers.
48. Anti-instrumentation timing check changes path. Establish trustworthy result.

# Complete Solutions

## Recall solutions
1. Adding analysis behavior at selected program events without changing intended semantics beyond observer effects.
2. Image, routine, trace, basic block, instruction, syscall, memory access.
3. Replace byte with `0xCC`; trap handler analyzes, executes/restores displaced instruction, reinstalls, resumes.
4. Patch branch to analysis code, preserve state, execute relocated original instructions, jump continuation.
5. Runtime translation/instrumentation framework that mediates execution.
6. Memory holding translated/instrumented target blocks.
7. Number of instructions encoded in a code region once.
8. Sum of instructions actually executed including repetitions.
9. Program that transforms/stores another executable representation and reconstructs it at runtime.
10. Control fetch/transfer into bytes previously written during execution.

## Conceptual solutions
11. Fewer callbacks reduce overhead while answering same question; e.g., add block size once.
12. Each causes exception/control transfer/context handling and possibly process/tool switches.
13. Displaced relative operands/branches, instruction boundaries, flags/registers, and reach change at new address.
14. Framework can insert analysis and link blocks while controlling semantics/caching.
15. Avoid races and hot contention; aggregate at safe points.
16. ASLR/modules load at changing addresses; module hash+offset is reproducible.
17. Packed code is commonly reconstructed by writes then executed.
18. JITs, loaders, trampolines, and legitimate self-modification do the same.
19. Headers, imports, relocations, sections, file offsets, and zero-fill layout may be absent/different.
20. Timing, scheduling, signals, layout, cache, and explicit detection are affected.

## Application solutions
21. At block entry add its static instruction count to dynamic counter; each execution repeats addition.
22. Instrument conditional branch at execution and observed target/taken predicate; maintain per-site two counters.
23. Record image hash/path/load base and module offset; use symbols only if present and preserve raw site.
24. Allocate TLS counter structure, update without shared lock, merge atomically/under lock at thread end/finalization.
25. Use interval set: insert sorted range and union any touching/overlapping intervals, with overflow-safe ends.
26. Time/thread/source transfer site/destination, mapping, written interval provenance, code bytes/version, and stage classification.
27. Invalidate decoded/cached metadata, create new code version, and associate later events with it.
28. Buffer binary events per thread, aggregate blocks, sample/filter, batch writes, avoid symbol/text formatting on hot path.
29. Classify known JIT modules/APIs, mapping origin, repeated code-cache behavior, signatures, and expected process role; report policy evidence not “malware.”
30. Reconstruct loader structures/IAT/relocations or analyze memory directly; identify resolved target addresses and module mappings.

## Multi-step solutions
31. Initialize framework/symbols; stable image/function/block IDs; instrument block counts and control/syscalls; TLS counters; buffered output; deterministic final aggregation; test known loops/threads.
32. Track memory writes/ranges and mappings; observe control targets/fetch; detect first execution of written bytes; version regions; identify stages/original logic using sustained execution/import behavior; dump with mapping metadata.
33. Trap: simple one-byte but very slow/complex signals. Trampoline: persistent fast but hard relocation/layout. DBI: flexible broad coverage, runtime dependency/overhead/detection. Choose by goal.
34. Compare uninstrumented/instrumented outputs/syscalls/exit across inputs, stress threads/signals/timing, use lower-intrusion corroboration, measure overhead, and document irreducible observer effect.
35. Schema includes sequence/time, PID/TID, image hash/offset, code version, event kind, branch target, syscall/memory metadata, backend provenance; keep backend-specific fields optional.

## Challenging solutions
36. Detect writes to cached source ranges, invalidate affected translated blocks atomically, prevent stale execution, synchronize threads, and version bytes. Framework mechanisms should be used where available.
37. Distinguish tool traps from target signals, serialize patch-step-repatch safely or use per-thread strategies, handle threads executing same site, restore original bytes on detach, deliver real signals.
38. Track successive written-executed generations and transitions; look for stabilized broad application behavior/import use, but report candidate OEP with evidence. Multi-stage packing has no universal single heuristic.
39. Capture mappings/permissions/bytes, choose layout, recreate PE/ELF headers/segments, rebuild imports from resolved slots/calls, preserve/repair relocations and entry, then validate parser and isolated execution.
40. Measure wall/CPU/instructions/events across baseline/tool-only/policy, multiple runs and inputs; fit overhead components, report variance and paths lost/changed due timing.

## Misconception solutions
41. False: callback executions times block static size gives instructions.
42. False: it races unless atomic/synchronized; even atomic contends.
43. False: it is a heuristic event.
44. False: normalize to module identity/offset.
45. False: memory layout and runtime resolution differ.

## Case solutions
46. Hash/modules, TLS counters, module-offset sites, deterministic aggregation by IDs, synchronize output, run clean trials, compare expected workload and report scheduling variance.
47. Record every write/execute stage and code version, dump each mapping with transition metadata, identify final stable logic, reconstruct or analyze memory, and validate against toy’s known behavior.
48. Detect timing check statically/dynamically, compare hardware/lower-intrusion traces, patch only a copy as causal experiment, model both paths, and report that DBI path alone is observer-biased.
