---
tags: [binary-analysis, workbook, elf, chapter-2, solutions]
---

# Chapter 2 Workbook — The ELF Format

Return to [[../Chapter 02 - The ELF Format]]. Use half-open ranges and show every address/offset step.

# Chapter Practice Set

## Recall Questions — 10

1. What are the first four ELF bytes?
2. Which `e_ident` properties control how later fields are decoded?
3. What does `e_entry` contain?
4. What do `e_phoff` and `e_shoff` contain?
5. What does `e_shstrndx` select?
6. Name the section-header fields for file offset, virtual address, and size.
7. Why does `.bss` commonly use `SHT_NOBITS`?
8. What is the purpose of `.dynsym/.dynstr`?
9. Which table controls runtime mappings?
10. Define `p_filesz` and `p_memsz`.

## Conceptual Questions — 10

11. Why must class and byte order be known before parsing the header?
12. Why are sections and segments not interchangeable?
13. Why can a runnable ELF lack useful section headers?
14. Why is `sh_name` an offset rather than a direct string?
15. Explain why section names are weaker evidence than flags, types, mappings, and references.
16. Explain lazy binding using PLT/GOT/loader roles.
17. Compare `.rel.*` and `.rela.*` conceptually.
18. Why can `p_memsz` be larger than `p_filesz`?
19. Why must `p_offset` and `p_vaddr` satisfy alignment congruence?
20. Why is an `ET_DYN` file not necessarily “just a shared library”?

## Application Problems — 10

21. A `PT_LOAD` has `p_offset=0x1000`, `p_vaddr=0x401000`, `p_filesz=0x900`, `p_memsz=0xb00`. Map VA `0x401640` to file offset.
22. For the same segment, determine whether VA `0x401a20` has stored file bytes.
23. Validate a program-header table at offset `0x40`, entry size `0x38`, count `13`, file size `0x400`.
24. `sh_name=0x27`. Describe every validation before returning its string.
25. A section named `.text` is writable and non-executable in its containing segment. What can you conclude?
26. `readelf -S` shows `.bss` size `0x400` and file offset overlapping the next section. Why might reading 0x400 bytes there be wrong?
27. A PIE’s static entry is `0x1080`, runtime image placement is `0x555555554000`. Give the candidate runtime entry and state the assumption.
28. A relocation uses symbol index 4 and addend `-4`. What must you inspect before calculating a result?
29. Full RELRO and `BIND_NOW` are enabled. How does first-call resolution differ from ordinary lazy binding?
30. You want to inject code into appended bytes. Which headers/relationships determine whether those bytes enter memory?

## Multi-Step Problems — 5

31. Design a robust 64-bit little-endian ELF header parser from magic through table validation.
32. Given an ELF, construct a reproducible map from each executable segment to sections and file byte ranges.
33. Trace a dynamically linked call from a call site through its relocation and eventual target.
34. Determine whether an address belongs to file-backed data, zero-fill memory, or no load segment.
35. Compare two PIE runs and normalize runtime addresses to image-relative offsets correctly.

## Challenging Problems — 5

36. A hostile ELF has overlapping `PT_LOAD` entries with different permissions. Explain analysis and runtime questions.
37. Section headers claim one code location while program headers map different bytes executable. Establish an evidence hierarchy.
38. Derive an overflow-safe validation for an arbitrary table and explain why `offset + count*size <= file_size` is unsafe when used naïvely.
39. A binary has no `.plt` section name but performs dynamic calls. Explain how to recover the mechanism.
40. Explain why converting VAs to file offsets by subtracting a single global image base can fail.

## Trick / Misconception Questions — 5

41. True or false: `e_entry` is a file offset.
42. True or false: every allocated section corresponds to exactly one segment.
43. True or false: `.bss` occupies its full size in the file.
44. True or false: full RELRO means the whole process is read-only.
45. True or false: an executable section contains only valid reachable instructions.

## Case-Based Questions — 3

46. A stripped sample has corrupted section names but executes normally. Build a static-analysis plan.
47. A security tool crashes on an ELF with a huge section count. Diagnose the likely parser class and specify a safe fix/test suite.
48. An analyst patches bytes at `VA - 0x400000`, but behavior does not change. Explain possible mapping errors and a correct procedure.

# Complete Solutions

## Recall solutions

### 1. Magic
**Tests:** identification. The bytes are `0x7f 45 4c 46` (`0x7f` + `ELF`). Verify before interpreting structure; a filename extension is not evidence.

### 2. Early decoding properties
Class selects 32/64-bit layout and data encoding selects endianness; version/ABI fields add interpretation constraints. Parsing multibyte offsets before these is circular and unsafe.

### 3. `e_entry`
It is the image virtual address/relative virtual value where loader control begins, interpreted according to file type/load placement. It is not a raw file offset or automatically `main`.

### 4. Table offsets
They are file offsets from the beginning of the ELF to the program-header and section-header tables. Validate them against actual file size.

### 5. `e_shstrndx`
It selects the section-header entry for the section-name string table. It does not select the static/dynamic symbol-name table.

### 6. Section location fields
`sh_offset` is file offset, `sh_addr` is memory virtual address if allocated, and `sh_size` is logical size. Their meaning is qualified by type, especially `SHT_NOBITS`.

### 7. `.bss`/`NOBITS`
Zero-initialized objects require memory capacity but no stored zero payload. The loader supplies zeros, reducing file size.

### 8. Dynamic tables
`.dynsym` stores selected runtime-visible symbols and `.dynstr` their strings plus related dynamic strings. They support loader symbol resolution and cannot always be stripped.

### 9. Runtime mapping table
The program-header table, especially `PT_LOAD`, defines load mappings. Section headers mainly serve linkers and analysis tools.

### 10. File versus memory size
`p_filesz` is stored bytes taken from the file; `p_memsz` is memory extent. For valid loadable segments, memory size is at least file size, with any excess normally zero-filled.

## Conceptual solutions

### 11. Class/endianness first
They select field widths and byte interpretation. Reading `e_phoff` with the wrong layout/order yields a fabricated offset and unsafe access. Correct parsers branch to a validated layout after `e_ident`.

### 12. Sections versus segments
Sections group semantic/linker content; segments group ranges to map with permissions. Several sections may share one segment, padding can lie between them, and a section can be absent while runtime mapping remains valid.

### 13. Execution without sections
The kernel follows program headers and entry metadata. Once linking is complete, section names/table can often be removed. Dynamic loader requirements are reachable through program/dynamic metadata, not necessarily section headers.

### 14. `sh_name`
Storing offsets avoids repeated fixed string fields and supports variable names. Parser selects `.shstrtab`, verifies the offset is inside it, then finds a terminating NUL within bounds.

### 15. Weak names
Names are arbitrary strings under producer/sample control. Flags/types/mappings constrain loader/tool treatment, while xrefs and execution show use. A region called `.text` can contain data or be unmapped.

### 16. Lazy binding
Caller reaches a PLT-like stub; an unresolved GOT-like slot routes to the loader resolver with relocation identity; loader finds symbol, updates the slot, and transfers. Later calls use cached address. Exact implementation varies, so verify actual relocation/stubs.

### 17. REL versus RELA
Both specify relocation target/type/symbol. REL obtains addend from the location being relocated; RELA stores an explicit addend in the entry. Architecture ABI determines which and the exact formula.

### 18. Extra memory
Zero-initialized storage and alignment can require memory beyond file bytes. Loader maps file-backed prefix and supplies zeros to the remaining memory extent.

### 19. Alignment congruence
Page mapping preserves the same within-page displacement for file offset and VA. Congruence enables mapping aligned file pages at aligned virtual pages without shifting content.

### 20. `ET_DYN`
PIE executables commonly use `ET_DYN` so the whole image can relocate. Inspect interpreter, entry, dynamic tags, usage, and launch behavior rather than classifying solely by `e_type`.

## Application solutions

### 21. Address mapping
Confirm delta `0x401640-0x401000=0x640`, which is below `p_filesz=0x900`. Add to offset: `0x1000+0x640=0x1640`. Common error: subtracting a global base unrelated to the containing segment.

### 22. Zero-fill status
Delta is `0xa20`. It exceeds file size `0x900` but is below memory size `0xb00`, so it is mapped zero-fill memory with no stored corresponding file byte.

### 23. Table validation
Available bytes from offset are `0x400-0x40=0x3c0`. Required count capacity is `13*0x38=0x2d8`, which fits. Also verify `0x38` matches/at least expected entry layout and every entry’s fields. Use division form `13 <= 0x3c0/0x38` to avoid multiplication overflow.

### 24. Name validation
Validate `e_shstrndx` is a real section index; its section type/range is file-backed and within file; `0x27 < string_table_size`; scan only remaining bytes for NUL; reject/label malformed if absent. Do not call unbounded C-string APIs first.

### 25. Misleading `.text`
Only the name suggests conventional code. If runtime mapping is non-executable, ordinary instruction fetch there should fail unless permissions later change. Investigate type/flags, mapping, xrefs, and `mprotect`; do not label it executable code from the name.

### 26. `SHT_NOBITS`
Its size describes memory, not bytes beginning at `sh_offset`. The offset can be a conceptual placement and overlap later stored data. Reading size bytes would consume unrelated content.

### 27. PIE entry
Candidate `0x555555554000 + 0x1080 = 0x555555555080`, assuming `0x1080` is image-relative to that load bias. Verify load-segment VAs/mapping offsets; “base” must be defined correctly.

### 28. Relocation inputs
Inspect relocation type/ABI formula, target place, symbol table linked by the relocation section/dynamic tag, symbol value/binding, width, and how addend is interpreted. Symbol index/addend alone are insufficient.

### 29. Eager binding
Relevant dynamic function relocations are resolved during startup and GOT-like slots become protected under full RELRO. The first call does not take the ordinary lazy resolver path. Initialization cost shifts earlier.

### 30. Appended injection
Program headers decide mapping. A new/extended `PT_LOAD` must cover file offset and VMA with proper sizes, flags, and alignment; section header is useful for tools but insufficient. Then execution must be redirected and payload relocatability/ABI handled.

## Multi-step solutions

### 31. Robust parser
Read bounded `e_ident`; verify magic/version/class/data/machine support; select exact header structure; decode fields; verify header/entry sizes; validate table offsets are within file; use `count <= (file_size-offset)/entry_size`; handle extended numbering if supported; parse entries with type-specific invariants. Fail closed with contextual errors.

### 32. Segment/section map
Parse validated `PT_LOAD`s; record file and memory half-open ranges/flags. Parse valid sections independently. For each allocated section, intersect its memory/file range with segments and reproduce `readelf -l` mapping. Mark contradictions/zero-fill rather than forcing one-to-one ownership.

### 33. Dynamic call trace
Identify call/PLT-like target; inspect relocation referencing symbol index; resolve name through linked dynamic symbol/string tables; inspect GOT-like slot; determine lazy/eager flags; at runtime record module base, slot before/after first call, loader event, and final library address. This connects file metadata to behavior.

### 34. Classify address
Find all `PT_LOAD`s containing VA without overflow. If none: unmapped by image. If delta `< p_filesz`: file-backed at `p_offset+delta`. If `p_filesz <= delta < p_memsz`: zero-fill. Overlaps require documenting loader precedence/OS behavior rather than choosing arbitrarily.

### 35. Normalize PIE runs
For each run read mappings with file offsets; match executable hash/path; derive load bias using a known `PT_LOAD` relationship; calculate `static = runtime-load_bias`; verify with entry/symbol. Compare offsets/edges, not raw addresses. Mapping start alone can be wrong if its file offset/VMA is nonzero.

## Challenging solutions

### 36. Overlapping loads
Static parser must retain both and flag overlap/permission disagreement. Runtime question is kernel mapping order, page rounding, merged permissions, and acceptance rules on that OS. Test only in isolation. Security tools should not assume unique ownership and must avoid using ambiguous mapping to certify W^X.

### 37. Conflicting metadata
For runtime reachability, validated program headers and observed mappings/execution outrank section names. For semantic organization, relocations/symbols/xrefs add evidence. Preserve corruption as a finding; use section data only where ranges validate and corroborate.

### 38. Overflow-safe table check
First require `offset <= file_size`; set `remaining=file_size-offset`; require supported `entry_size>0`; require `count <= remaining/entry_size`. Naïve multiplication/addition can wrap to a small value and pass. Fuzz near `UINT_MAX`, zero entry size, exact boundary, and one-byte truncation.

### 39. Dynamic calls without `.plt` name
Names may be stripped/changed and modern linkers vary. Start from dynamic tags and relocation records, identify slots and imported symbols, then disassemble call stubs/references by address and observe runtime resolution. Section label is not required.

### 40. One-base subtraction failure
ELF load segments can have different file offsets/VAs, page rounding, holes, and zero-fill. A global subtraction assumes uniform mapping. Select containing segment and apply its `p_offset + (VA-p_vaddr)` only for file-backed range.

## Misconception solutions

### 41. `e_entry` file offset — false
It is a virtual/image address. Translate only through the containing file-backed load segment.

### 42. One section per segment — false
Segments commonly group several sections and padding. Runtime and linker views have different units.

### 43. `.bss` stored fully — false
It normally describes zero-filled memory with `SHT_NOBITS`; file payload need not contain its zeros.

### 44. Full RELRO makes process read-only — false
It protects selected relocation/GOT-related regions after resolution. Ordinary writable data, heap, and stack remain writable according to mappings.

### 45. Executable section is all reachable code — false
It may contain padding, inline data, unreachable code, or alternate streams. Executable permission permits fetch; it does not prove semantics/reachability.

## Case solutions

### 46. Corrupted section names
Validate ELF/program headers; map executable `PT_LOAD` bytes; use entry, dynamic table, relocations, init arrays, imports, and recursive traversal; supplement with isolated traces and observed indirect targets. Treat section headers as untrusted optional hints. Execution works because loader-critical program metadata remains coherent.

### 47. Huge count crash
Likely unchecked table allocation/multiplication or out-of-bounds iteration. Replace with offset/remaining/division validation, impose resource limits, reject unsupported entry sizes, and use bounded ownership. Tests: zero, exact maximum, count causing multiplication wrap, offset EOF±1, truncated last entry, fuzz corpus under ASan/UBSan.

### 48. Wrong patch offset
The analyst assumed one image base, patched zero-fill/unmapped bytes, ignored segment file offset, patched another copy, or hit PIE runtime rather than static VA. Confirm hash, find containing `PT_LOAD`, verify VA lies below `p_vaddr+p_filesz`, compute segment formula, patch a copy, hex/disassemble exact bytes, and validate at runtime with module offset.
