---
tags: [binary-analysis, workbook, libbfd, loader, chapter-4, solutions]
---

# Chapter 4 Workbook — Building a Binary Loader with libbfd

Return to [[../Chapter 04 - Building a Binary Loader with libbfd]].

# Chapter Practice Set

## Recall Questions — 10

1. What kind of “loader” does this chapter build?
2. What problem does libbfd solve?
3. Name the three normalized classes used in the chapter design.
4. Which whole-file properties belong in `Binary`?
5. Which properties belong in `Section`?
6. Which properties belong in `Symbol`?
7. What must happen before BFD object queries are trusted?
8. Why are static and dynamic symbol loading separate cases?
9. What is VMA?
10. What is transactional construction?

## Conceptual Questions — 10

11. Why normalize formats instead of letting the disassembler call libbfd everywhere?
12. Why is an analysis loader different from the OS loader?
13. Why is an `unknown` enum value important?
14. Why should target addresses use explicit wide integer types?
15. Why must strings/bytes be copied out of library-owned storage?
16. Why is absence of `.symtab` not a load failure?
17. Why can a code-flagged section still contain data?
18. Why is RAII useful in this loader?
19. Why do cross-tool comparisons not prove correctness?
20. Why must malformed inputs be part of normal tests?

## Application Problems — 10

21. Write an overflow-safe test that address `x` lies in `[base,base+size)`.
22. A section size is zero. What should containment return?
23. `bfd_openr` succeeds but format check fails. What state should the caller receive?
24. Static symbols are absent and dynamic symbols contain imports. How should result be represented?
25. A `SHT_NOBITS`-like section has size but no file content. How should normalized model represent it?
26. A BFD name pointer is stored directly and handle is closed. Diagnose.
27. A 32-bit target loads on a 64-bit host. Which width controls decoding?
28. A section reports 8 GiB but tool has a 1 GiB resource limit. What should happen?
29. Two sections overlap in VMA. How should address lookup behave?
30. `SEC_CODE` is set. What is the strongest safe classification?

## Multi-Step Problems — 5

31. Design the entire load transaction and cleanup paths.
32. Design static/dynamic symbol fallback without duplicate confusion.
33. Design section-content loading with bounds, ownership, and zero-fill semantics.
34. Create a differential test matrix covering formats, symbols, architectures, and linking.
35. Design a stable JSON output consumed by a disassembler.

## Challenging Problems — 5

36. The library accepts a malformed file that your later code crashes on. Explain responsibility boundaries.
37. A symbol value appears section-relative in one API path and absolute in another. How do you prevent double rebasing?
38. Design lookup semantics when symbols share an address or one symbol lies inside another function.
39. Explain how exception safety can fail when loading a vector of sections.
40. Compare libbfd, direct parsing, a modern library, and subprocess tool output for a production analyzer.

## Trick / Misconception Questions — 5

41. True or false: libbfd makes all malformed files safe.
42. True or false: no symbols means the loader should reject the binary.
43. True or false: host pointer width equals target address width.
44. True or false: a section name is safe to retain as a raw pointer.
45. True or false: every `SEC_CODE` byte can be sent to recursive traversal as an entry.

## Case-Based Questions — 3

46. A loader works on one ELF but produces wrong entry/sections for PIE and PE. Design diagnosis.
47. A security scan service is exhausted by huge symbol/section counts. Design defensive limits without hiding valid large files.
48. A later CFG tool reports an address outside every section although runtime executes it. Explain model gaps and extensions.

# Complete Solutions

## Recall solutions

1. An analysis loader that normalizes binary metadata/bytes; it does not create a process.
2. libbfd abstracts multiple object/executable formats and access to architecture, sections, symbols, and contents.
3. `Binary`, `Section`, and `Symbol`.
4. Filename/identity, type/flavour, architecture, bitness, entry, section/symbol collections.
5. Name, VMA, size, owned bytes or storage kind, flags/classification.
6. Owned name, address/value, type and optionally binding/provenance.
7. Initialize/open, then verify recognized `bfd_object` format and check every error.
8. Stripping can remove static symbols while runtime dynamic symbols remain; APIs/storage requirements differ.
9. Virtual memory address associated with a section/entity in image space.
10. Build a private result and publish it only after required invariants succeed; failures expose no half-valid object.

## Conceptual solutions

11. A normalized boundary prevents format/library coupling throughout later algorithms and makes testing/ownership consistent.
12. It reads and represents a file; OS loading maps segments, creates process state, relocates, and starts execution.
13. It preserves uncertainty/unsupported cases rather than silently inventing a known classification.
14. Host ABI varies and target may differ; explicit `uint64_t`-like values prevent truncation and clarify serialization.
15. Closing/reusing the BFD handle invalidates internal buffers; copying establishes lifetime owned by normalized model.
16. Stripped binaries are normal and executable; missing optional metadata must be represented as absence.
17. Executable/code flags permit or suggest code but padding, inline data, jump tables, and unreachable bytes exist.
18. It closes handles/frees buffers on every return/exception, reducing leaks and partial cleanup bugs.
19. Both tools may share library/assumptions, and agreement on friendly inputs says little about malformed cases.
20. Binary parsers are exposed to attacker-controlled offsets/counts/strings; hostile cases test the actual trust boundary.

## Application solutions

21. `x >= base && x - base < size`; subtraction occurs only after lower-bound proof and avoids `base+size` overflow.
22. False for every `x`; a half-open empty interval contains nothing.
23. A complete failure/error object with contextual BFD error; RAII closes handle and no partial `Binary` escapes.
24. Empty static collection plus normalized dynamic/import symbols with provenance, optionally deduplicated by defined policy.
25. Store address/size/class and a zero-fill/no-file-bytes storage kind; do not fabricate a huge zero vector unless analysis explicitly needs it.
26. Dangling pointer/use-after-free. Copy into `std::string` before handle close.
27. Target metadata determines decoder mode/address semantics; host width only governs the analyzer implementation.
28. Reject with an explicit resource-limit result before allocation. Resource policy is distinct from format validity.
29. Return all matches or an ambiguity error; silently choosing first hides malformed/overlapping layouts.
30. “Candidate code-containing range,” not proof every byte is an instruction or entry.

## Multi-step solutions

31. Initialize once; open under RAII; verify format; build local `Binary`; load/validate properties; attempt optional symbols; load required sections into owned buffers; validate invariants; return moved result. Every failure carries context and automatic cleanup.
32. Query sizes safely, load static and dynamic separately, normalize provenance/binding/value, merge using a documented key (address/name/type) without dropping aliases, and treat absence as normal.
33. Validate representable size/resource limit; identify whether stored content exists; allocate vector transactionally; request exact bytes; reject short/error; retain flags/address/name; represent zero-fill separately.
34. Fixtures: relocatable/executable/shared, ELF/PE, 32/64, little/big if supported, static/dynamic/PIE, debug/stripped, zero-fill/empty, malformed/truncated/huge. Compare with independent tools and golden invariants.
35. Include schema version, file hash, target arch/bits/type/entry, ranges with storage/perms/VA/bytes reference, symbols with provenance. Serialize 64-bit addresses losslessly (hex strings plus defined numeric policy).

## Challenging solutions

36. Library acceptance means only its own parser contract passed. Your layer still validates resource, ownership, range, and semantic assumptions. Add postconditions and regression input; report upstream issue if library contract is violated.
37. Define one canonical address space and conversion functions. Record whether each API returns absolute VMA, section-relative value, or undefined/common symbol; assert with known fixtures and never add section VMA twice.
38. Preserve aliases at same address. “Nearest symbol” must state rule and does not prove containment; function ranges need independent boundary evidence. Return candidate set/confidence.
39. Raw pointers allocated before vector insertion can leak if later construction throws; shallow copies can double-free. Use value types/`vector<byte>`/smart handles and construct temporary section fully before moving it.
40. libbfd offers broad mature support but complex API/version coupling; direct parsing gives control but large security burden; modern typed library improves ergonomics within feature limits; subprocess output prototypes quickly but is slow/fragile/version-text dependent. Production can combine with clear trust boundaries.

## Misconception solutions

41. False. It reduces work; callers still face errors, resource abuse, and semantic assumptions.
42. False. Symbols are optional for execution and analysis can proceed from sections/entry/dynamic metadata.
43. False. Cross-analysis is common; explicitly model target width.
44. False. Copy before owner closes; also validate bounded termination.
45. False. Range is a decoding domain; recursive entries require seeds/edges.

## Case solutions

46. Verify flavour/machine/bits rather than hard-coded ELF64; inspect PIE entry as image-relative VMA and PE RVA model; compare normalized output with format-native tools; add format-specific fixtures and explicit unsupported errors.
47. Validate count/range before allocation, use configurable byte/entry/time limits, stream where possible, and return `resource_limit` distinct from `malformed`. Test legitimate large corpora and adversarial near-limit inputs.
48. Model may contain only sections/file bytes while runtime code comes from anonymous JIT/unpacking, zero-fill later written, or modules loaded after start. Extend with program segments/runtime mappings and dynamic code-version ranges; do not force it into original sections.
