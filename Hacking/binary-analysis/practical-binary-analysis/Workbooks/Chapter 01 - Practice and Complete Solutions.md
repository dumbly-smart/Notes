---
tags: [binary-analysis, workbook, chapter-1, solutions]
---

# Chapter 1 Workbook — Anatomy of a Binary

Return to [[../Chapter 01 - Anatomy of a Binary]]. Questions come first; do not open the solutions until you have written an answer and the evidence you would use.

# Chapter Practice Set

## Recall Questions — 10

1. Name the four principal C build stages in order.
2. What artifact does `gcc -E` produce conceptually?
3. What is a translation unit?
4. What does an assembler produce?
5. What problem does a relocation solve?
6. What is a symbol?
7. Which symbol table commonly disappears during stripping?
8. What does disassembly produce?
9. What is the executable entry point?
10. Which component maps shared libraries for a normal dynamically linked process?

## Conceptual Questions — 10

11. Why does including a header not copy a shared-library implementation into the program?
12. Why can optimized code contain no recognizable form of a source variable?
13. Why can an object file contain calls before final addresses exist?
14. Why do stripped binaries remain executable?
15. Why can `.dynsym` remain after `.symtab` is removed?
16. Why is decompiled C not the original source?
17. Explain the difference between static linking and runtime loading.
18. Explain the difference between a direct address and a symbolic name.
19. Why can the executable entry point differ from `main`?
20. Why is one valid x86 decoding not proof of the intended instruction stream?

## Application Problems — 10

21. Give the command sequence that preserves preprocessing, assembly, object, and executable forms of `demo.c`.
22. A macro changes a buffer size only in release builds. Which artifact should you inspect first, and why?
23. An `-O2` listing returns constant `42` although source computes several expressions. Name the likely transformation and a verification method.
24. `objdump -dr demo.o` annotates a call with a relocation for `puts`. Explain what the displayed placeholder and annotation mean.
25. `nm app` reports “no symbols,” but `nm -D app` lists `malloc`. Explain.
26. You break at `_start` and cannot find `argc` in the normal `main` argument registers. What should you investigate?
27. A binary imports `connect` but no observed run makes a network syscall. State the strongest justified conclusion.
28. A function seen at `-O0` has no standalone call target at `-O2`, but its arithmetic appears inside two callers. What happened?
29. A debugger runtime address differs from the disassembler address by a constant during one run. What relationship should you test?
30. A compiler warning appears during `gcc -c` but not preprocessing. Which stage owns the relevant reasoning?

## Multi-Step Problems — 5

31. Design an experiment showing the difference between preprocessing, compilation, assembly, and linking using one call to a function in another source file.
32. Starting from a `printf` call in source, trace every major representation until the real libc routine executes.
33. You receive stripped and unstripped builds of the same program. Design a method to transfer useful names without assuming identical addresses.
34. Recover whether an unexplained constant came from a macro, compiler optimization, linker layout, or runtime initialization.
35. Explain how to distinguish dead-code elimination from an unexecuted dynamic path.

## Challenging Problems — 5

36. A function has no symbol and no direct callers but its address appears in a read-only table. Build an evidence chain for or against it being a callback.
37. Two valid disassemblies overlap in the same byte range. Describe how static and dynamic evidence should be combined without erasing ambiguity.
38. A relocatable object uses a PC-relative relocation. Explain the conceptual calculation and why the final value depends on both target and relocation place.
39. A statically linked stripped binary has thousands of functions and almost no imports. Design a prioritization strategy.
40. Explain which information is fundamentally lost by compilation and which can often be reconstructed as an equivalent abstraction.

## Trick / Misconception Questions — 5

41. True or false: `#include <stdio.h>` inserts the compiled body of `printf`. Correct the statement.
42. True or false: a stripped binary has no function boundaries. Correct the statement.
43. True or false: every instruction in an object file has its final runtime address. Correct the statement.
44. True or false: `main` is the first instruction the kernel executes in a C program. Correct the statement.
45. True or false: if `strings` finds a password-looking value, the program must accept it. Correct the statement.

## Case-Based Questions — 3

46. A vendor supplies a stripped PIE that behaves differently on two machines. Create a staged investigation separating compile-time, link-time, dependency, loader, and runtime-environment causes.
47. An incident analyst sees a dynamically constructed command in memory but no plaintext command in the file. Explain how the build/runtime model guides recovery.
48. A reverse engineer names a function `decrypt_config` solely because it calls an imported crypto API. Critique the claim and design a proof plan.

# Complete Solutions

## Recall solutions

### 1. Build-stage order

**Tests:** representation pipeline. **Concept:** preprocessing → compilation → assembly → linking. **Approach:** name both transformation and output. Preprocessing creates expanded source; compilation creates target assembly/IR-selected code; assembly creates a relocatable object; linking creates a final executable/shared image. A common error is calling all four “compilation,” which hides where symbols and addresses become known.

### 2. `gcc -E`

**Tests:** preprocessor output. It emits preprocessed C: macros expanded, selected conditional blocks retained, comments/directives handled, and header declarations incorporated. It is not assembly and does not contain linked library machine code.

### 3. Translation unit

**Tests:** compilation boundary. A translation unit is the complete preprocessed source consumed by one compiler invocation. Separate `.c` files normally become separate translation units and only meet during linking.

### 4. Assembler output

**Tests:** assembly stage. The assembler encodes instructions/data into a relocatable object containing sections, symbols, and relocations. It need not know final virtual addresses.

### 5. Relocation

**Tests:** unresolved address relationships. A relocation tells a later linker/loader which stored field must be adjusted, by what relocation rule, and often which symbol/addend participates. It is not merely an “unknown address”; its type defines the calculation.

### 6. Symbol

**Tests:** metadata vocabulary. A symbol is a named entity/address relationship such as a function or object, with attributes such as binding/type. It aids linking and analysis; the CPU executes addresses and bytes.

### 7. Stripped table

**Tests:** static versus dynamic symbols. `.symtab` with `.strtab` commonly disappears. Required dynamic entries in `.dynsym/.dynstr` remain when runtime linking needs them.

### 8. Disassembly output

**Tests:** reverse representation. Disassembly maps candidate machine-code bytes and boundaries to instruction representations. It does not automatically prove reachability, functions, source variables, or intent.

### 9. Entry point

**Tests:** executable startup. It is the virtual address to which loading transfers initial control. It commonly identifies `_start`/runtime startup, not `main`.

### 10. Shared-library mapper

**Tests:** kernel versus dynamic loader. The kernel recognizes the requested ELF interpreter and maps enough to start it; the dynamic loader maps dependencies and performs dynamic relocation/resolution. Saying only “kernel” misses the user-space loader’s role.

## Conceptual solutions

### 11. Header versus implementation

**Relevant concept:** declarations and linking. The preprocessor includes declarations/types/macros. The compiler uses the declaration to generate an ABI-correct external call. The implementation comes from an object/static archive or runtime shared library. To verify, inspect preprocessed output and unresolved object symbols.

### 12. Missing source variable

**Relevant concept:** optimization. A variable is a source abstraction, not a required storage location. Constant propagation, register allocation, common-subexpression elimination, and dead-store removal can eliminate it. Verify using multiple optimization builds and the instruction data flow. Do not conclude the source variable never existed.

### 13. Calls before addresses

The assembler can encode a placeholder and relocation tied to a symbol. When the linker chooses layout, it computes the correct field. This separation enables independent compilation.

### 14. Why stripping does not stop execution

Direct control transfers and data references are already encoded/relocated; required dynamic metadata remains. Human-readable local names are unnecessary to the processor. Stripping changes analysis convenience, not core semantics.

### 15. Dynamic symbols survive

The runtime loader may still need imported/exported names and relocation associations. Full static/debug names are optional after linking. Confusing these tables leads to the false claim that “stripped means no names whatsoever.”

### 16. Decompiled C is not original

Compilation removes comments, formatting, many names/types, and may merge/reorder/eliminate constructs. Multiple sources can compile to equivalent code. A decompiler synthesizes one high-level representation consistent with its model; verify critical semantics in instructions.

### 17. Link versus load

Linking constructs an executable image: combines objects, resolves symbols, applies static relocations, creates dynamic metadata, and lays out content. Loading maps segments into a process and performs environment-dependent runtime resolution/initialization. They occur at different times and with different inputs.

### 18. Address versus symbol

An address is a numeric location in a particular layout/runtime context. A symbol is metadata naming an entity whose value may later become an address. ASLR can change runtime address while symbol-relative offset/identity stays meaningful.

### 19. Entry versus `main`

Language runtime work must initialize process state, libraries, constructors, TLS, and termination handling. Therefore the file entry begins startup code, which later calls `main` using the ABI.

### 20. Valid decoding ambiguity

x86 instructions are variable length and dense; starting at a different byte can produce another valid sequence. Use control-flow predecessors, relocations, symbols, data references, alignment patterns, and executed traces. A mnemonic list alone is insufficient.

## Application solutions

### 21. Preserve all stages

Run `gcc -E demo.c -o demo.i`, `gcc -S -masm=intel demo.i -o demo.s`, `gcc -c demo.s -o demo.o`, and `gcc demo.o -o demo`. Inspect each. In a real build preserve identical flags/defines; changing them invalidates comparison.

### 22. Release-only macro

Inspect release-configured preprocessed output first because it reveals which macro value/conditional branch actually reached compilation. Then compare assembly to see consequences. Inspecting only source ignores build definitions.

### 23. Constant result

Likely constant folding/propagation plus dead-code elimination. Compile with optimization reports/IR or compare `-O0/-O2`; change an input from compile-time constant to runtime/volatile carefully and observe. Do not infer compiler bug from concise output.

### 24. Object call relocation

The displayed immediate/displacement is not final. The annotation names relocation type/symbol; linker uses final symbol value, addend, and relocation place to write the correct field. Read the relocation rather than treating zero as a call to address zero.

### 25. `nm` disagreement

Default `nm` sought the static table, removed by stripping. `nm -D` reads dynamic symbols required for runtime linking, so `malloc` remains. Both outputs are consistent.

### 26. `_start` arguments

Investigate the ABI’s initial process stack and startup code. At raw entry, `argc/argv/envp/auxv` are arranged by the loader contract; normal `main` registers appear only when runtime startup calls `main`.

### 27. Imported `connect`

Strongest conclusion: the image declares a dynamic relationship/capability involving `connect`. It may execute only under another input, be dead, or be wrapped. No observed syscall under tested cases is an under-approximation, not proof of no networking.

### 28. Missing standalone function

Inlining most likely copied/optimized behavior into callers. Confirm matching semantics and absence of calls/symbol body. It could also be cloned/specialized, so preserve uncertainty until comparing compiler output or multiple sites.

### 29. Runtime/static difference

Test `runtime = module_base + static_offset` under PIE/ASLR. Derive module base from mappings and correct load-segment/file offset, not blindly the first executable page.

### 30. Warning stage

Compilation owns language type/semantic reasoning after preprocessing. `gcc -c` drives preprocessing too unless given preprocessed input, so reproduce with `demo.i` to isolate it. The assembler only understands assembly syntax/encodings.

## Multi-step solutions

### 31. Four-stage experiment

Create `main.c` calling `helper` declared in `helper.h`, and `helper.c` defining it. Preprocess each separately; compile to `.s`; assemble to `.o`; inspect `main.o`’s undefined symbol/relocation; link both objects; disassemble final call; run. Remove `helper.o` to produce a link error. This isolates every stage and shows independent compilation.

### 32. `printf` journey

Header supplies declaration; compiler places arguments per ABI and emits an external call; assembler encodes call placeholder/relocation; linker builds PLT/dynamic symbol/relocation relationship; kernel and interpreter map image; loader maps libc and resolves eagerly/lazily; PLT/GOT path reaches libc. Exact stubs vary, so inspect the actual build.

### 33. Transfer names safely

Hash/confirm builds are related; normalize functions using bytes, CFG shape, callers/callees, strings/constants, and relocation references; account for shifted addresses and optimization. Assign confidence and verify candidates dynamically. Blind address copying fails under PIE, changed link order, or code differences.

### 34. Origin of a constant

Search preprocessed source for macro/literal; compare compiler assembly/IR for synthesized arithmetic constants; inspect relocations/symbol/layout for address-derived constants; break before first runtime use and watch the storage writer for initialization. The earliest representation containing the constant locates its likely origin.

### 35. Dead versus unexecuted

Dead-code elimination means instructions are absent from the binary; inspect static code and alternative builds. An unexecuted path exists statically but lacks coverage for tested inputs. Expand inputs or solve branch constraints. One trace cannot establish compile-time elimination.

## Challenging solutions

### 36. Callback candidate

Validate table as file-backed pointer data/relocations; find code that indexes/loads it; follow value to an indirect call; verify ABI-consistent arguments; trigger a case and observe target. Counterevidence includes table used as data, address outside code, or no reachable consumer. Name it `possible_callback_X` until confirmed.

### 37. Overlapping streams

Preserve both static candidates with provenance. Analyze incoming edges and data references. Execute authorized inputs and record which starts run; self-modification/obfuscation may make both real under different paths. Dynamic observation confirms a stream for a run but does not eliminate the other globally.

### 38. PC-relative relocation

Recognize a place-relative form conceptually as `S + A - P`, where `S` is target symbol value, `A` addend, and `P` relocation place. Moving target or call site changes displacement. Use the ABI’s exact relocation definition and width/range; the generic expression is not universal.

### 39. Static stripped prioritization

Start at entry and syscalls; identify library routines by signatures conservatively; mine strings/constants; build call graph; prioritize external-input parsers, privilege/data boundaries, and high fan-in/out routines; use dynamic coverage to label observed paths. Separate application code from bundled runtime before deep reading.

### 40. Lost versus recoverable

Often lost: original names, comments, formatting, exact source types, macro boundaries, dead code, and one-to-one statements. Often recoverable: equivalent control/data flow, constants, calls, data layouts, algorithms, protocol behavior, and side effects. Recover behavioral equivalence, not historical source certainty.

## Misconception solutions

### 41. Header copies implementation — false

It normally inserts declarations/macros/source text from the header. Compiled library code is linked/resolved separately. Header-only/inlined implementations are an edge case, so inspect actual preprocessed content.

### 42. Stripping removes function boundaries — false

It removes much explicit metadata. Boundaries may still be inferred from calls, unwind info, exports, prologues, CFG, and runtime entries, but certainty can decrease.

### 43. Object instructions have final addresses — false

Relocatable sections and unresolved references are placed later. Section-relative offsets exist, but final image/runtime addresses depend on linking/loading.

### 44. Kernel executes `main` first — false

The loader transfers to the ELF entry. Runtime startup eventually invokes `main` after initialization.

### 45. Found string must be accepted password — false

It could be dead, output, test data, decoy, or transformed input. Prove reachable xrefs, comparison semantics, length/encoding, and runtime branch outcome.

## Case solutions

### 46. Different-machine behavior

**Recognition:** differences can enter at build or runtime. Confirm hashes first; if different, compare compiler flags/preprocessed artifacts/link dependencies. If identical, compare interpreter and resolved library versions, environment/config/locale/CPU features, mappings, syscalls, and input. Reproduce in matched containers. Do not blame ASLR for semantic differences without evidence.

### 47. Runtime-only command

Static strings may be encoded fragments or absent due to construction. Follow allocation/writes and data dependencies to the command-consuming sink; break immediately before it and dump bounded memory; watch writers/backward-slice to inputs/constants; repeat cases. The file-to-process model explains why runtime memory can contain bytes never stored contiguously on disk.

### 48. `decrypt_config` claim

An import proves capability, not purpose. Find the exact call, identify algorithm/context parameters, trace input origin and output consumer, observe data transformation with controlled synthetic config, and compare before/after entropy/format carefully. A more defensible temporary name is `calls_crypto_api_at_X` until behavior proves decryption and configuration role.
