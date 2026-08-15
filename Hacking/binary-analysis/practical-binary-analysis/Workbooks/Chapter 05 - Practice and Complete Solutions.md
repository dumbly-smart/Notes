# Chapter 5 Workbook — Basic Binary Analysis in Linux

Return to [[../Chapter 05 - Basic Binary Analysis in Linux]].

# Chapter Practice Set

## Recall Questions — 10
1. What question does `file` answer first?
2. What does `ldd` report?
3. What does `xxd -s` control?
4. Which `readelf` option lists program headers?
5. Which `nm` option selects dynamic symbols?
6. What does `strings -t x` add?
7. What boundary does `strace` observe?
8. What does `ltrace` commonly observe?
9. Which `objdump` option disassembles?
10. Where is the first pointer argument at an AMD64 System V call?

## Conceptual Questions — 10
11. Why identify a binary before choosing a decoder?
12. Why is static dependency inspection safer for unknown files?
13. Why must file offsets and VAs be labeled separately?
14. Why is a string a lead rather than proof?
15. Why is an import a capability rather than behavior proof?
16. Why can `ltrace` miss a library-like operation?
17. Why is one `strace` incomplete?
18. Why inspect relocation-aware object disassembly?
19. Why break at a buffer consumer rather than process start?
20. Why should tool output be question-driven?

## Application Problems — 10
21. Write a nonexecuting initial triage sequence for an unknown ELF.
22. A UTF-16LE message is absent from default `strings`; what next?
23. Trace shows `read(3,buf,4096)=12`. Which bytes became defined?
24. At `write(fd,buf,n)`, which AMD64 registers should be inspected?
25. `nm` is empty but `readelf -Ws` shows imports. Explain.
26. A URL has no code xrefs. State the confidence conclusion.
27. A call to `strcmp` compares two runtime-built buffers. Design GDB observation.
28. Runtime entry differs under PIE. Normalize it.
29. `ltrace` shows no `memcpy`, but bytes are copied. Give three explanations.
30. A trace opens the same path twice with different flags. What additional evidence is needed?

## Multi-Step Problems — 5
31. Triage a stripped dynamically linked ELF from hash to focused breakpoint.
32. Recover a dynamically decrypted string and its construction path.
33. Correlate a failed file open syscall to the responsible source-equivalent function.
34. Compare behavior across two argument cases using controlled traces.
35. Build a reproducible evidence bundle for another analyst.

## Challenging Problems — 5
36. A sample detects tracing and changes behavior. Design lower-intrusion corroboration.
37. A statically linked binary has no helpful imports. Prioritize analysis.
38. A process forks/execs helpers. Preserve causal timeline.
39. A string exists compressed in a custom section. Design recovery.
40. Tool outputs disagree on architecture/format. Resolve safely.

## Trick / Misconception Questions — 5
41. True or false: `file` output is ground truth.
42. True or false: `ldd` is always safe on malware.
43. True or false: no string means the value never exists.
44. True or false: no observed syscall means the binary cannot perform it.
45. True or false: GDB argument registers always contain C `main` arguments at ELF entry.

## Case-Based Questions — 3
46. A service reads a config and later connects externally only when one flag is set. Design the investigation.
47. A stripped program prints a secret assembled one byte at a time. Recover and prove it.
48. An analyst claims malware because `strings` shows commands and IPs. Review the claim.

# Complete Solutions

## Recall solutions
1. File/container identity, architecture, bitness, endianness, linking/stripping clues. Verify important fields independently.
2. Current-environment shared-library resolution; it is not merely a static `NEEDED` list.
3. Starting file offset for the dump; do not confuse it with VA.
4. `-l`/`-lW`.
5. `-D`.
6. Hex file offset for each discovered string.
7. User process/kernel syscall boundary.
8. Calls through dynamically linked library interfaces it can interpose/trace.
9. `-d` (with `-D` having a different all-content convention in some usage); choose explicit target sections/ranges.
10. `rdi`; then `rsi,rdx,rcx,r8,r9`.

## Conceptual solutions
11. Architecture/mode/endianness determine instruction and format interpretation; wrong choice can still emit plausible nonsense.
12. It avoids executing target-controlled startup behavior. Parse dynamic metadata first inside a hardened parser/isolated workflow.
13. They name different coordinate systems; patches and runtime breakpoints fail when arithmetic crosses them blindly.
14. It may be dead, decoy, output, encoded input, or data. Require reachable xref and behavior.
15. Linking says code may reference an API; paths, indirect resolution, and dead code determine actual use.
16. Static linking, inlining, hidden/internal calls, direct syscalls, unsupported hooks, or unexecuted path.
17. It is one input/environment/schedule and observes only OS crossings, not private computation.
18. Object call/data fields may be placeholders; relocation annotations explain intended targets/calculation.
19. Consumer arguments expose the completed value at a semantic boundary, reducing noise and locating relevant slice.
20. Dumps without questions encourage confirmation bias; a question defines which observation and test settle a hypothesis.

## Application solutions
21. `sha256sum`, `file`, bounded `xxd`, `readelf -hSWlrd`, `nm -D`, `strings`—without launching. Perform in isolated copy and record output.
22. Use encoding-aware extraction (`strings -el` where appropriate), hex search, resource/section parsers, or runtime memory observation.
23. Exactly `[buf,buf+12)` on successful return; requested 4096 does not mean written 4096.
24. `rdi=fd`, `rsi=buf`, `rdx=n`; after return inspect `rax` actual result and channel identity.
25. Static table is stripped/absent while dynamic symbols remain. Tools/options query different tables.
26. It is present data with no discovered static consumer; classify as unreferenced/unknown, then consider indirect/runtime access.
27. Break at `strcmp`; inspect bounded strings at `rdi/rsi` for controlled cases; capture caller; watch/backward-trace buffer writers.
28. Derive module load bias from mappings and ELF segments; represent runtime address as module hash + static offset.
29. Compiler inlined/vectorized loop, static/private implementation, or another routine/direct instructions performed copy.
30. Caller/call stack, returned fd, subsequent reads/writes, path origin, flags semantics, and controlled input/config changes.

## Multi-step solutions
31. Hash/file → ELF headers/segments/dynamic/symbols/strings → imports/error xrefs → static CFG from entry/target → isolated argument matrix/strace → breakpoint at decisive API → inspect arguments and update model.
32. Locate consumer; break before consumption; dump bytes; hardware-watch selected buffer or trace writes backward; identify constants/input/transforms; repeat changed inputs; document static/runtime addresses and exact output.
33. Record syscall path/error; use debugger catch syscall or API breakpoint with stack; normalize caller address; inspect filename producer; find callers/control predicate; alter only path/config and verify.
34. Keep environment identical, trace full events separately, normalize PIDs/addresses, diff semantic syscalls and output, then locate first divergent branch/data input.
35. Include hash, environment/tool versions, commands, full raw logs, filtered views, annotated addresses with bases, input corpus, hypotheses/tests, and unknowns.

## Challenging solutions
36. Emphasize static metadata/code, VM snapshots, syscall/audit/ETW-like external monitoring, hardware tracing/emulation, and timing controls; compare multiple methods and document observer effects.
37. Start at entry/syscalls, strings/constants, input parsers and error outputs; identify bundled libraries by signatures cautiously; use dynamic coverage and slice from security-relevant syscalls.
38. Use `strace -f`/process-aware debugger, record PID/TID and exec image hashes, normalize timestamps, build parent-child/file-descriptor lineage, preserve complete logs before filtering.
39. Identify entropy/magic and decompression-like loop/import; trace read/write from section to buffer; capture after transform; reconstruct algorithm and validate on multiple samples.
40. Inspect raw magic/header class/machine/endianness with two format parsers; check truncation/polyglot possibilities; never execute until ambiguity is explained.

## Misconception solutions
41. False; it is fast signature-based classification and can be fooled/malformed.
42. False; prefer static metadata and isolation for hostile targets.
43. False; values may be encoded, constructed, wide, compressed, or received dynamically.
44. False; coverage is incomplete and direct/internal behavior may occur under other states.
45. False; raw entry uses the process-start ABI/stack, while runtime later calls `main`.

## Case solutions
46. Identify config read/parse, trace both flag cases, diff first divergent branch, follow flag data to connect arguments, confirm network syscall/destination in simulator, and document default/error paths.
47. Find output call and final buffer; break/watch writes; reconstruct loop/table/input; express exact byte sequence and termination; test changed conditions and compare final output.
48. Downgrade to suspicious embedded artifacts. Prove xrefs/reachability, runtime construction/use, destinations and protocol in isolation. Commands may be help text, test data, or decoys; IPs may be unused.
