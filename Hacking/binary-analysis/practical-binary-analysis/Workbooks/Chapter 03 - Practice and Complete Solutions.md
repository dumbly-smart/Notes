---
tags: [binary-analysis, workbook, pe, chapter-3, solutions]
---

# Chapter 3 Workbook — The PE Format

Return to [[../Chapter 03 - The PE Format]]. Treat every RVA, size, and count as untrusted.

# Chapter Practice Set

## Recall Questions — 10

1. What bytes begin a conventional PE image?
2. Which DOS-header field locates the PE signature?
3. What is the PE signature?
4. What does the COFF `Machine` field identify?
5. Why is the “optional” header normally required for an executable image?
6. Which field distinguishes PE32 and PE32+?
7. Define RVA.
8. What is the preferred image base?
9. What does a data-directory entry contain?
10. What runtime table receives resolved imported addresses?

## Conceptual Questions — 10

11. Why is scanning blindly for `PE\0\0` unsafe?
12. Why must `e_lfanew` be range-checked before use?
13. Explain RVA versus VA versus file offset.
14. Why can `VirtualSize` differ from `SizeOfRawData`?
15. Why are section/file alignment distinct?
16. Why are PE timestamps weak provenance evidence?
17. How do imports differ from exports?
18. Why does ASLR require base relocations when preferred placement is unavailable?
19. Why can section names mislead a reverse engineer?
20. Compare PE import resolution with ELF dynamic linking at a conceptual level.

## Application Problems — 10

21. Image base is `0x140000000`; convert RVA `0x12340` to preferred VA.
22. A section has `VirtualAddress=0x2000`, `PointerToRawData=0x600`, raw size `0x800`. Map RVA `0x2340`.
23. For the same section, can RVA `0x2a00` be read from the file? Show reasoning.
24. `e_lfanew=0x180`, file size `0x190`. What must happen?
25. Optional-header magic says PE32+, but a parser uses PE32 offsets. Predict the failure class.
26. A section has virtual size `0x900`, raw size `0x600`. Classify its final `0x300` memory bytes.
27. An imported API appears in the IAT but has no observed calls. State the justified conclusion.
28. A runtime address changes each launch but its RVA stays fixed. Explain.
29. A `.text` section includes long repeated padding bytes. How should a disassembler treat them?
30. A data-directory RVA points outside every mapped section. What should a robust parser do?

## Multi-Step Problems — 5

31. Design a safe parser from DOS header through section table.
32. Build an import-analysis workflow from directory entry to runtime call site.
33. Map a runtime faulting VA back to module RVA and file offset under ASLR.
34. Determine whether a suspicious section tail is padding, zero-fill, data, or code.
35. Compare two PE builds and determine whether a function moved or changed.

## Challenging Problems — 5

36. A PE’s raw sections overlap in the file but virtual ranges do not. What must an analyzer report/test?
37. A data directory lies in headers rather than a conventional section. Why must parsers use ranges instead of names?
38. Explain how a 32-bit integer overflow in `NumberOfSections * sizeof(header)` becomes a parser vulnerability.
39. A packed PE has a tiny import table and transfers to newly written executable memory. Design a reconstruction strategy.
40. Explain why `RVA → file offset` may fail even when the RVA is valid in memory.

## Trick / Misconception Questions — 5

41. True or false: `MZ` alone proves a valid PE.
42. True or false: “optional header” means it can be omitted from normal executables.
43. True or false: preferred image base is always the runtime base.
44. True or false: every virtual byte has a raw file byte.
45. True or false: `.idata` is the only possible place imports can be described.

## Case-Based Questions — 3

46. A Windows sample uses TLS callbacks before its apparent entry. Explain how this changes triage.
47. A parser accepts a truncated section table and later crashes. Diagnose and design regression tests.
48. A call through the IAT is mislabeled because the import name is tampered with. Build a multi-source verification plan.

# Complete Solutions

## Recall solutions

1. **Tests:** identification. Conventional start is `MZ`; it is only the DOS header magic, not complete PE validation.
2. `e_lfanew`, interpreted from a validated DOS header, gives the file offset to the PE signature.
3. `PE\0\0` (bytes `50 45 00 00`). It must occur exactly where validated `e_lfanew` points.
4. It identifies the target machine architecture; decoder choice must follow it rather than host architecture.
5. It holds image-entry/layout/subsystem/directory information required to load an image. The COFF name is historical.
6. The optional-header `Magic`; it selects PE32 versus PE32+ layout and widths.
7. An RVA is a relative virtual address measured from the loaded image base.
8. The link-time preferred base at which the image would like to be mapped; ASLR/conflicts can change actual base.
9. Normally an RVA and size for a structured directory such as imports, exports, relocations, TLS, or resources.
10. The Import Address Table (IAT)/thunk slots receive resolved function addresses.

## Conceptual solutions

11. Payload bytes may contain the signature; only `e_lfanew` establishes the intended header relationship. Scanning can select a decoy and parse arbitrary data.
12. A large/truncated offset causes out-of-bounds reads. Require enough remaining bytes for signature, COFF header, declared optional header, and section table.
13. RVA is image-relative; VA is actual base + RVA; file offset locates stored bytes through a containing section/header mapping. They are not interchangeable.
14. Disk alignment/padding and memory zero-fill differ. Raw may be rounded up; virtual may require extra zeroed storage.
15. Disk I/O/layout uses file alignment; virtual mappings use section/page alignment. Their constraints and units serve different consumers.
16. Toolchains, packers, and attackers can alter timestamps; corroborate with signatures, build metadata, behavior, and external provenance.
17. Imports declare external dependencies the loader resolves; exports advertise symbols other modules can request. Both use directories/tables but reverse direction.
18. Absolute image addresses encoded for the preferred base must be adjusted by load delta. Without relocation information, safe rebasing may be impossible.
19. Names are short producer-controlled labels; packers rename them, content spans purposes, and flags/references/mappings provide stronger evidence.
20. Both resolve external named/ordinal entities into callable addresses. PE uses import descriptors/thunks/IAT; ELF uses dynamic symbols/relocations and GOT/PLT conventions. Algorithms and structures differ.

## Application solutions

21. `0x140000000 + 0x12340 = 0x140012340`. At runtime replace preferred with actual base.
22. Delta `0x2340-0x2000=0x340`; file offset `0x600+0x340=0x940`, within raw size.
23. Delta is `0xa00`, greater than raw `0x800`; it has no raw byte through that section even if virtual size maps it. Do not read `0x1000` by arithmetic alone.
24. Reject as truncated: only `0x10` bytes remain, insufficient for signature and headers. Never seek/read optimistically.
25. Fields are read at wrong widths/offsets, producing corrupt bases, sizes, and directories; this can lead to OOB access or misanalysis.
26. The virtual-only tail is normally zero-filled memory, assuming virtual size really covers it and loader accepts metadata.
27. The image declares a dependency/address slot. It may be unused on tested paths or referenced dynamically; import alone does not prove execution.
28. ASLR changes actual image base; RVA is relative to the image layout and remains stable for identical bytes/build.
29. Mark as candidate padding/data unless a reachable edge begins there. Linear decoding of padding is not evidence of code.
30. Reject or mark the directory malformed/unsupported; validate RVA and complete size before dereferencing. Never clamp silently.

## Multi-step solutions

31. Validate file length and `MZ`; safely read/range-check `e_lfanew`; verify signature; decode COFF header; validate optional-header declared size and magic-specific minimum; validate directory count against header size; calculate section-table range with division; then validate each raw/virtual range and alignment.
32. Locate import directory by RVA/size; map safely; iterate bounded descriptors to terminator within range; map name/thunk tables; distinguish ordinal/name; find IAT slot xrefs; at runtime compare slot value to loaded module export and observe call.
33. Identify module/mapping and actual base; compute `RVA=VA-base`; select containing section and ensure delta lies in raw size; compute `PointerToRawData + delta`. If RVA is virtual-only, there is no file offset.
34. Compare delta against raw/virtual sizes, characteristics, relocation/xrefs, entropy/pattern, reachable branches, and runtime execution/write events. Preserve “unknown padding/data” if evidence is insufficient.
35. Normalize by RVA, then match functions using bytes, CFG shape, calls, constants, strings, and semantics. Address movement alone is layout change; semantic/CFG differences indicate code change.

## Challenging solutions

36. Retain overlap as malformed/ambiguous; avoid assigning one raw byte uniquely. Determine actual Windows loader acceptance and mapping in an isolated VM, record precedence, and prevent analyzer range alias bugs.
37. Directory entries give RVA/size and may legally refer to header-mapped regions; conventional section names are not authoritative. Implement a general RVA resolver covering validated headers and sections.
38. Multiplication can wrap, allocate too little, then loop declared count out of bounds. Require `count <= remaining/header_size` before allocation/iteration and impose format limits; fuzz boundary values under sanitizers.
39. Isolate execution; trace writes and permission/control transfers; capture memory at original-entry transition; reconstruct section layout, imports/IAT, relocations, and entry, or analyze dump in memory-aware tooling. Tiny imports are a clue, not proof.
40. RVA may fall in virtual zero-fill, an unbacked gap, or runtime-created memory; raw size can be smaller than virtual size. File conversion requires a containing file-backed interval.

## Misconception solutions

41. False. Validate `e_lfanew`, PE signature, header sizes, machine/magic, directories, and section ranges.
42. False. It is normally mandatory for executable images; “optional” comes from COFF object terminology.
43. False. ASLR/conflicts can relocate; actual VA uses actual runtime base.
44. False. Virtual zero-fill and runtime allocations have no stored byte.
45. False. Names are conventional; directory RVA is authoritative and structures may be elsewhere/packed.

## Case solutions

46. TLS callbacks can execute before the nominal entry point, performing unpacking, anti-debugging, or initialization. Parse TLS directory/callback array, seed them in static CFG, set early debugger/DBI events, and compare state before callback and entry.
47. Root cause is incomplete table-range validation. Require declared count to fit remaining bytes and optional-header-derived table start. Test zero/exact/one-short counts, huge multiplication-wrap count, truncated individual headers, overlapping raw ranges, and malformed strings under ASan.
48. Treat name as untrusted metadata. Identify actual resolved module/address at runtime; map address to a verified loaded module/export; inspect call arguments/effects and code signature; compare clean vendor image/import data. Label mismatch rather than trusting either source alone.
