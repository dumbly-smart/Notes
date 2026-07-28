---
aliases:
  - Reverse Engineering and Binary Exploitation Curriculum
  - RE and Pwn Roadmap
tags:
  - ctf
  - reverse-engineering
  - binary-exploitation
  - curriculum
status: active
---

# Reverse Engineering & Binary Exploitation — Complete CTF Curriculum

> [!important] North star
> The goal is independent problem-solving: given an unfamiliar CTF binary, rapidly map its behavior, identify the vulnerability or hidden logic, build a reliable solution, and explain why it works. Finishing content is not mastery; consistently solving unseen challenges is.

## Scope and ethics

Use these techniques only on CTFs, wargames, your own programs, or systems where you have explicit permission. The curriculum deliberately uses local, reproducible targets. Keep challenge services isolated from personal and production systems.

## End-state

By the end, I should be able to:

- read optimized x86-64 assembly almost as naturally as C;
- recover types, data structures, algorithms, and state machines from stripped binaries;
- use Ghidra and a debugger as complementary reasoning tools rather than crutches;
- recognize and exploit stack, format-string, integer, logic, race, and heap vulnerabilities;
- defeat NX, PIE, ASLR, stack canaries, RELRO, stripped symbols, seccomp, and common allocator hardening in CTF settings;
- construct ret2libc, ROP, SROP, stack-pivot, ret2dlresolve, and heap exploitation chains;
- reverse common C++, Rust, Go, Windows, ARM, and obfuscated binaries;
- automate repetitive analysis and exploitation with Python, pwntools, GDB scripting, emulation, and symbolic execution;
- debug unreliable exploits systematically;
- solve medium challenges consistently and make credible progress on hard finals during live competitions;
- produce concise write-ups that state evidence, assumptions, primitives, constraints, and the final chain.

## How to use this curriculum

This is a **48-week reference route**, not a deadline. Use gates, not calendar time, to advance. If a gate is failed, diagnose the weakest prerequisite, drill it, and retry with a fresh binary.

Recommended load:

- **Standard:** 12–15 focused hours/week for 48 weeks.
- **Intensive:** 20–25 hours/week for roughly 28–32 weeks.
- **Part-time:** 7–9 hours/week; keep the order and let the route take longer.

Weekly allocation:

| Activity | Share | Purpose |
|---|---:|---|
| Unseen challenge solving | 40% | Build transfer and independence |
| Deliberate labs | 25% | Isolate one technique at a time |
| Theory and reading | 15% | Build the mental model |
| Tooling/automation | 10% | Remove repetitive work |
| Review and write-ups | 10% | Convert experience into reusable knowledge |

For every challenge:

1. Work alone for 60–90 minutes before taking hints.
2. Record observations separately from hypotheses.
3. Ask for the smallest useful hint, never the entire solution.
4. After solving, reproduce from a clean start.
5. Write the root cause, primitives, constraints, mitigations, chain, and failure modes.
6. Re-solve it 2–7 days later without the write-up.

## Phase 0 — Environment and baseline (Week 1)

### Learn

- Linux process basics, shell navigation, permissions, pipes, redirection, and SSH.
- Hexadecimal, binary, signed integers, two's complement, bitwise operations, and endianness.
- Minimal Git workflow for exploit and note history.
- The difference between static analysis, dynamic analysis, emulation, and instrumentation.

### Build the lab

- A disposable Linux VM or container for challenge binaries.
- Compiler toolchain: GCC/Clang, `make`, Python, and virtual environments.
- Inspection: `file`, `strings`, `xxd`, `readelf`, `objdump`, `nm`, `ldd`, `strace`, and `ltrace`.
- Reversing: Ghidra plus one lightweight disassembler/decompiler if desired.
- Debugging: GDB with one enhancement layer such as pwndbg, GEF, or PEDA.
- Exploitation: pwntools, ROPgadget or ropper, `checksec`, and patchelf.
- Later tools installed only when needed: angr, Z3, QEMU user-mode, Wine, Frida, and a Windows debugger.

### Baseline test

Without notes:

- convert values between decimal, hex, and little-endian byte sequences;
- compile a C program with and without symbols, PIE, canaries, and optimization;
- locate `main`, set a breakpoint, inspect registers and memory, and explain one call;
- complete one very easy crackme and one very easy stack-overflow challenge.

Keep the result. It is the comparison point for Week 48.

### Gate

Explain the path `source → compiler → assembler → object → linker → ELF → loader → process` and demonstrate every step on a tiny program.

---

## Phase 1 — C, memory, assembly, and ABI foundations (Weeks 2–6)

### Week 2 — C as the language of vulnerabilities

- Integers, casts, signed/unsigned behavior, arrays, pointers, pointer arithmetic.
- Strings and byte buffers; `strlen` versus allocation size.
- Structs, unions, enums, function pointers, and callbacks.
- Stack versus static storage versus heap lifetime.
- Undefined behavior and why source-level intuition can fail.

Labs:

- Implement and debug small versions of `strlen`, `memcpy`, and a dynamic array.
- Write one intentionally vulnerable program for each: out-of-bounds access, use-after-free, integer truncation, and format string.
- Inspect each at `-O0` and `-O2`.

### Week 3 — x86-64 assembly essentials

- Registers and partial-register behavior.
- Data movement, arithmetic, flags, comparisons, branches, loops, and `lea`.
- Memory operands and effective addresses.
- Stack operations, calls, returns, prologues, and epilogues.
- Intel and AT&T syntax; read both, choose one for notes.

Labs:

- Hand-trace short functions and predict final register/stack state.
- Translate 15 small C functions to assembly concepts and back to pseudocode.
- Write several leaf functions in assembly and call them from C.

### Week 4 — System V AMD64 ABI and compiler patterns

- Argument/return registers, caller/callee-saved registers, stack alignment, red zone.
- Struct returns, variadic calls, floating-point arguments, and syscall ABI.
- Common patterns for loops, switches, arrays, structs, and recursion.
- Optimizations: inlining, tail calls, strength reduction, dead-code elimination, vectorization.

Labs:

- Recover function signatures from stripped examples.
- Identify a jump table, tail call, inlined function, and stack canary sequence.
- Compare GCC and Clang output at `-O0`, `-O1`, `-O2`, and `-Os`.

### Week 5 — ELF, linking, loading, and process memory

- ELF headers, sections versus segments, symbols, relocations, and dynamic tags.
- PLT/GOT, lazy binding, shared libraries, interpreter, and constructors.
- Virtual address space, mappings, permissions, stack, heap, libraries, and VDSO.
- PIE, ASLR, NX, canaries, RELRO, and `_FORTIFY_SOURCE`.

Labs:

- Annotate an ELF from header to runtime mappings.
- Resolve one imported function manually through PLT/GOT.
- Patch an immediate or conditional branch in a toy binary and verify the effect.
- Predict `checksec`, then compile and confirm each mitigation combination.

### Week 6 — Debugger fluency

- Breakpoints, watchpoints, stepping by source/instruction, and conditional stops.
- Register, stack, memory, disassembly, and mapping inspection.
- Core files, signals, `catch syscall`, attaching, and following forks.
- GDB Python basics and reproducible command files.

Labs:

- Debug a crash from core file to root cause.
- Find a buffer offset using a cyclic pattern.
- Track a value from input to comparison with watchpoints.
- Write a small GDB command that labels or logs useful state.

### Gate 1 — Foundations

On three unseen stripped binaries:

- explain calling convention and stack frames;
- recover the purpose of at least five functions;
- map ELF metadata to runtime behavior;
- diagnose a controlled crash without guessing.

Pass condition: at least 80% correct, with evidence from disassembly/debugging.

---

## Phase 2 — Core reverse engineering (Weeks 7–13)

### Week 7 — A disciplined static workflow

- Triage: format, architecture, mitigations, imports, strings, sections, symbols.
- Function discovery, cross-references, control-flow graphs, call graphs.
- Rename, retype, comment, and progressively improve the decompiler.
- Recognize library code and avoid wasting time on irrelevant paths.

Deliverable: a one-page triage template used on every future binary.

### Week 8 — Dynamic analysis and hypothesis testing

- Input tracing, break-on-use, branch validation, and state snapshots.
- `strace` versus `ltrace` versus debugger observations.
- Patching to test a hypothesis—not as a substitute for understanding.
- Differential analysis: compare inputs, executions, or binary versions.

Labs: solve crackmes using static-only, dynamic-only, and combined approaches; compare time and blind spots.

### Week 9 — Data structures and type recovery

- Infer structs from offsets, stride, allocation size, and call usage.
- Linked lists, trees, hash tables, vectors, tagged unions, bitfields.
- Global state, object lifetimes, aliasing, and ownership clues.
- Recover function prototypes and propagate types.

Deliverable: reconstruct compilable C definitions for structures in two stripped programs.

### Week 10 — Algorithms and encodings

- Recognize checksums, hashes, base encodings, XOR loops, PRNGs, lookup tables.
- Separate cryptographic-looking code from actual cryptography.
- Work backward from success/failure sinks.
- Extract transformations into a Python solver.

Labs: license checks, custom encodings, table-driven validation, and a constraint-heavy key check.

### Week 11 — C++ reversing

- Name mangling, methods, `this`, constructors/destructors.
- Vtables, virtual dispatch, inheritance, RTTI, exceptions, templates, and STL patterns.
- Heap object layout and dynamic casts.

Labs: reconstruct a class hierarchy and solve a C++ crackme without relying on symbols.

### Week 12 — Go and Rust recognition

- Runtime-heavy binaries, strings/slices, interfaces/traits, panic paths.
- Go goroutines/channels and Rust enums/ownership artifacts at a practical level.
- Finding user logic amid runtime noise.

Labs: solve one small Go and one Rust challenge; document reliable recognition patterns.

### Week 13 — Obfuscation fundamentals

- Stripping, indirect calls, opaque predicates, control-flow flattening.
- Anti-debugging, timing checks, self-modifying code, and simple packing.
- Manual deobfuscation, binary patching, and dynamic dumping.
- Know when to emulate, instrument, or simplify instead of reading everything.

### Gate 2 — Reversing

Solve five unseen challenges:

- one optimized stripped C binary;
- one C++ binary;
- one Go or Rust binary;
- one algorithmic/keygen binary;
- one lightly packed or obfuscated binary.

For each, submit recovered behavior, decisive evidence, solver/key, and uncertainty notes. No full walkthroughs before completion.

---

## Phase 3 — Core stack exploitation (Weeks 14–20)

### Week 14 — Exploitation as primitives

- Root cause versus exploit primitive.
- Control of instruction pointer, read, write, leak, allocation, and free.
- Bad bytes, input constraints, crash reproducibility, and exploit reliability.
- Use core files and cyclic patterns; calculate, do not eyeball.

### Week 15 — Stack buffer overflows

- Stack layout, saved return address, off-by-one, partial overwrite.
- Shellcode concept and NX implications.
- Local/remote differences and clean pwntools tubes.

Labs: ret2win, argument control, partial RIP overwrite, and one constrained-input overflow.

### Week 16 — Shellcode and syscalls

- Linux x86-64 syscall ABI, position-independent code, null-free constraints.
- Stagers, read-execute chains, and debugging shellcode.
- Use assembler helpers but understand every instruction.

Labs: write small `write`, file-read, and process-spawn payloads in an isolated CTF target.

### Week 17 — ROP fundamentals

- Gadgets, side effects, calling convention, alignment, and chain simulation.
- ret2libc, libc leaks, resolving bases, and returning safely.
- Finding gadgets manually before automating.

Labs: NX bypass, two-stage leak-and-return, and remote ret2libc.

### Week 18 — Format-string exploitation

- Variadic argument handling and format parsing.
- Stack leaks, arbitrary reads, `%n` writes, positional arguments, and padding.
- GOT overwrite where RELRO permits; alternate targets where it does not.

Labs: leak-only, write-only, and combined format-string challenges.

### Week 19 — Mitigation-driven strategy

- Canary leaks/bypass in CTF designs.
- PIE/ASLR base recovery.
- Partial versus full RELRO.
- Choosing a strategy from available primitives and mitigations.
- Recognize when brute force is and is not justified.

### Week 20 — Advanced ROP

- Stack pivots, ret2csu-style sequences, SROP, ret2dlresolve.
- ORW chains under syscall restrictions.
- Gadget scarcity and register-preservation planning.

### Gate 3 — Stack pwn

Solve six unseen Linux x86-64 targets including:

- two-stage ret2libc with PIE;
- format-string leak plus write;
- canary-protected overflow;
- stack pivot;
- syscall/ROP challenge;
- one challenge with an unfamiliar constraint.

Pass condition: exploits work repeatedly from a clean environment and against the intended remote service where provided.

---

## Phase 4 — Heap exploitation (Weeks 21–28)

> [!warning]
> Allocator exploitation is version-specific. Always identify the exact libc/allocator build and understand its invariants before applying a named technique.

### Week 21 — Allocator mental model

- `brk`/`mmap`, chunks, metadata, alignment, arenas, bins, and consolidation.
- Trace `malloc`, `free`, `calloc`, and `realloc`.
- Build heap diagrams after every operation.

### Week 22 — Heap bug classes

- Heap overflow, use-after-free, double free, invalid free, uninitialized data.
- Dangling pointers, aliasing, object replacement, and size confusion.
- Convert a bug into a leak or controlled allocation.

### Week 23 — Tcache and freelist manipulation

- Tcache behavior, freelist poisoning, safe-linking concept.
- Bypasses depend on the target version and available leaks.
- Allocation choreography: force the program to return a chunk where needed.

### Week 24 — Fastbins, unsorted bins, and libc leaks

- Fastbin behavior and constraints.
- Unsorted-bin metadata as a leak source.
- Consolidation and overlap creation.

### Week 25 — Overlaps and metadata corruption

- Off-by-null/off-by-one effects.
- Size-field corruption and overlapping chunks.
- Reason from allocator checks rather than memorizing “houses.”

### Week 26 — Exploit targets in modern binaries

- Hooks in historical libc versus modern alternatives.
- Function pointers, vtables, exit handlers, FILE structures, stack targets, and ROP transition.
- Select targets based on reachable write and target hardening.

### Week 27 — FILE-oriented and advanced heap concepts

- `_IO_FILE` structure concept and stream-oriented attack surface.
- Large-bin concepts and advanced allocator state manipulation.
- Study named techniques as case studies tied to specific versions.

### Week 28 — Heap exploit engineering

- Automate heap diagrams and menu interactions.
- Assert expected leaks and allocator state.
- Debug nondeterminism and local/remote libc mismatch.
- Use the supplied loader/libc safely with patchelf or a matching environment.

### Gate 4 — Heap pwn

For at least five unseen challenges spanning two or more allocator versions:

- identify the precise bug;
- diagram the relevant heap state;
- state the required primitive;
- explain allocator checks and the bypass;
- produce a reliable exploit.

At least one must require a leak, one an overlap, one UAF/tcache manipulation, and one modern post-hook control target.

---

## Phase 5 — Advanced targets and program analysis (Weeks 29–35)

### Week 29 — Integer and logic exploitation

- Overflow, underflow, truncation, sign conversion, bad bounds, and size calculations.
- Logic flaws that create memory primitives.
- Race/TOCTOU concepts in local CTF programs.

### Week 30 — Seccomp and sandboxed pwn

- Read BPF/seccomp policies.
- ORW and alternate syscall strategies.
- File descriptor assumptions, syscall constraints, and staged chains.

### Week 31 — Symbolic execution and constraint solving

- Symbolic values, path predicates, state explosion, and environment modeling.
- Z3 for direct constraints; angr for selective program exploration.
- Constrain inputs and hook irrelevant code.
- Know when manual reasoning is faster.

Labs: solve the same key-check manually, with Z3, and with angr; compare.

### Week 32 — Emulation and instrumentation

- QEMU user-mode for foreign architectures.
- Unicorn-style emulation concepts, hooks, and memory models.
- Frida or equivalent dynamic instrumentation.
- Write tiny targeted harnesses rather than emulating an entire OS.

### Week 33 — ARM/AArch64 introduction

- Registers, calling convention, load/store model, branches, stack frames.
- AArch64 ROP differences and alignment.
- Cross-compile, emulate, debug, reverse, and exploit small targets.

### Week 34 — Windows reversing and pwn foundations

- PE sections, imports/exports, relocations, SEH concept, Windows x64 calling convention.
- Basic WinAPI recognition and debugger workflow.
- Windows mitigations at an orientation level.

### Week 35 — Custom VMs and bytecode

- Identify dispatch loops, opcode decoding, VM state, handlers, and bytecode.
- Build a disassembler/interpreter.
- Lift validation logic into a solver.

### Gate 5 — Breadth

Complete:

- one seccomp-constrained pwn;
- one symbolic-solving challenge;
- one ARM/AArch64 reverse or pwn;
- one Windows PE reverse;
- one custom-VM challenge.

The goal is a transferable workflow, not equal mastery on every platform.

---

## Phase 6 — Expert workflow and competition performance (Weeks 36–42)

### Week 36 — Automated triage

Create a script that reports:

- architecture, format, interpreter, and mitigations;
- imports, exports, interesting strings, sections, and dynamic dependencies;
- suspected libc/loader pairing;
- useful first-pass debugger commands.

Automation must show evidence, not silently decide exploitability.

### Week 37 — Exploit architecture

Standardize pwntools projects:

- explicit local, remote, GDB, and supplied-libc modes;
- deterministic parsing with timeouts;
- helpers for leaks, packing, addresses, and menu actions;
- logged stages and assertions;
- separation of offsets from runtime bases.

### Week 38 — Reliability engineering

- Eliminate racey reads, sleeps, brittle prompts, accidental buffering assumptions.
- Handle ASLR, network fragmentation, stack alignment, and one-gadget constraints.
- Run an exploit dozens of times and categorize every failure.

### Week 39 — Patch diffing and variant analysis

- Compare vulnerable/fixed binaries structurally and behaviorally.
- Use function matching, changed constants, and control-flow differences.
- Infer the vulnerability from a small patch.

### Week 40 — Speed reversing

- Timed triage drills.
- Rapidly classify challenge archetype and likely decisive functions.
- Abandon unproductive paths using a written hypothesis budget.

### Week 41 — Team CTF operation

- Produce useful partial notes: facts, hypotheses, blockers, artifacts.
- Hand off a challenge cleanly.
- Maintain exploit scripts and dependencies under version control.
- Communicate without duplicating teammates' work.

### Week 42 — Full mock CTF

Run a 24–48-hour personal or team simulation:

- choose a balanced set of old legal CTF challenges;
- do not read write-ups during the event;
- track time, hints, dead ends, solves, and exploit reliability;
- conduct a blunt postmortem.

### Gate 6 — Competition readiness

In timed conditions, solve:

- two medium reverse challenges;
- two medium pwn challenges;
- make documented, technically meaningful progress on a hard challenge.

No technique checklist guarantees “expert.” This gate measures the real outcome: performance on unseen problems.

---

## Phase 7 — Specialization and capstone (Weeks 43–48)

### Weeks 43–44 — Choose a specialty

Choose one primary and one secondary:

- advanced glibc heap exploitation;
- obfuscation/devirtualization;
- kernel pwn foundations;
- browser engine exploitation foundations;
- Windows internals/exploitation;
- embedded/firmware and unusual architectures;
- automated binary analysis;
- vulnerability research and patch diffing.

Keep advanced work in legal labs. Kernel/browser tracks require much deeper operating-system or runtime study and are beginnings, not two-week mastery claims.

### Weeks 45–46 — Reproduce, then vary

- Reproduce two public CTF solutions in the specialty.
- Do not copy scripts blindly: explain each transition and invariant.
- Change the environment or binary so the original exploit breaks.
- Adapt it and document why.

### Week 47 — Capstone

Pick an unfamiliar hard challenge or build a paired target:

- reverse the format and behavior;
- identify or intentionally introduce a nontrivial flaw;
- create a full exploit/solver;
- make it reliable;
- document mitigations and at least one alternate approach;
- package the environment so it can be reproduced.

### Week 48 — Final assessment

Repeat the Week 1 baseline, then complete a fresh mini-set under time pressure.

Write a skills audit:

- what is automatic now;
- what still requires references;
- recurring failure patterns;
- solve rates by category and difficulty;
- next 12-week specialization plan.

---

## Practice ladder

Use legal CTF/wargame material and progress by demonstrated difficulty:

1. **Foundations:** small self-compiled programs, compiler explorer experiments, beginner reversing and stack-overflow levels.
2. **Guided practice:** pwn.college-style modules, ROP Emporium-style focused tasks, beginner challenge archives.
3. **Mixed challenge sets:** picoCTF and archived beginner/intermediate CTF tasks.
4. **Intermediate depth:** Exploit Education-style labs, harder archived CTF pwn/rev, allocator-specific practice.
5. **Competition depth:** recent archived challenges attempted blind, then write-up comparison.

Do not farm only familiar patterns. Maintain a mix:

- 50% at the edge of current ability;
- 30% consolidation/speed;
- 20% deliberately too hard, for research and exposure.

## Core references by purpose

Prefer primary specifications and tool manuals for exact behavior:

- Intel or AMD architecture manuals for x86-64 semantics.
- System V AMD64 ABI for calling convention and ELF ABI details.
- GDB, binutils, Ghidra, pwntools, and glibc source/documentation.
- *Practical Binary Analysis* for executable analysis and tool-building.
- *Computer Systems: A Programmer's Perspective* for machine-level foundations.
- *The Shellcoder's Handbook* for historical concepts—verify modern applicability.
- How2Heap as version-tagged allocator technique examples, never as recipes without understanding.
- CTF challenge write-ups only after a serious independent attempt.

Record the exact tool, libc, kernel, and architecture version whenever behavior depends on them.

## The canonical challenge workflow

### 1. Triage

```text
file → checksec → run safely → imports/strings → ELF metadata → debugger
```

Questions:

- What format, architecture, ABI, loader, and libraries?
- What mitigations exist?
- What input channels and constraints exist?
- What functions touch attacker-controlled data?

### 2. Model

- Rename functions and variables.
- Recover types and important data structures.
- Draw control flow, object lifetime, or heap state.
- Separate observed facts from inferred behavior.

### 3. Find and prove the root cause

- Trigger the smallest deterministic failure.
- Trace input to the corrupting or decisive operation.
- State the violated invariant precisely.

### 4. Inventory primitives

- What can be leaked, read, written, allocated, freed, or redirected?
- How controlled is each primitive?
- What restrictions, bad bytes, and operation counts apply?

### 5. Choose the chain

```text
bug → primitive → information leak → address calculation
→ stronger primitive/control target → code execution or flag read
```

The chain should account for every enabled mitigation.

### 6. Engineer reliability

- Assert expected prompts and leak ranges.
- Log bases and key addresses.
- Avoid unexplained constants and sleeps.
- Test local, matching-library, and remote modes.
- Re-run from a clean state many times.

### 7. Distill

- What clue should have been noticed earlier?
- Which dead end consumed time and why?
- What reusable pattern belongs in notes or tooling?
- Can the solve be reproduced without looking?

## Note template for every challenge

```markdown
# Challenge name

## Metadata
- Event/category/difficulty:
- Architecture/format/libc:
- Mitigations:
- Files and hashes:

## Initial triage

## Observed facts

## Hypotheses

## Program model

## Root cause

## Available primitives and constraints

## Exploit/solver chain

## Reliability notes

## Dead ends

## Lessons and reusable patterns

## Re-solve date
```

## Progress scoreboard

Track outcomes, not hours alone:

| Metric | Current | Target |
|---|---:|---:|
| Unseen reverse solves | 0 | 50+ |
| Unseen pwn solves | 0 | 50+ |
| Medium challenges solved without hints | 0 | 25+ |
| Heap challenges across allocator versions | 0 | 12+ |
| Other-architecture/VM/Windows challenges | 0 | 10+ |
| Clean write-ups | 0 | 30+ |
| Reliable remote exploits (20/20 runs) | 0 | 15+ |
| Timed mock CTFs | 0 | 3+ |

Also track:

- median time to first useful hypothesis;
- median time to root cause;
- hints used and when;
- failure rate of completed exploits;
- recurring knowledge gaps.

## Anti-patterns

- Watching solutions feels productive but does not train discovery.
- Copying exploit templates without tracing every value creates brittle intuition.
- Memorizing named heap attacks without allocator invariants fails across versions.
- Trusting decompiler output as source code hides calling-convention and type errors.
- Trying every tool before forming a question creates noise.
- Spending hours on one hypothesis without seeking disconfirming evidence is not persistence.
- Solving only challenges in a favorite category creates fake confidence.
- A shell once is not a finished exploit; reliability and explanation are part of the solve.

## Review cadence

- **Daily:** 10 minutes of assembly/hex recall and one small prediction.
- **Weekly:** one blind challenge, one write-up, and one re-solve.
- **Every 4 weeks:** timed mixed set and gap analysis.
- **Every phase:** take the gate on unseen material.
- **Quarterly:** delete or revise stale assumptions, especially version-specific heap notes.

## Immediate starting sequence

- [ ] Complete the Week 1 baseline and record the result.
- [ ] Create the isolated lab and verify the toolchain.
- [ ] Work through [[02 - Source Code to Running Program]].
- [ ] Continue with [[03 - Executable Formats - ELF and PE]].
- [ ] Practice loading and inspection in [[04 - Binary Loading and Linux Analysis]].
- [ ] Drill [[05 - x86-64 Assembly for Binary Analysis]].
- [ ] Apply [[06 - Static Disassembly Strategies]].
- [ ] Attempt Gate 1 on fresh binaries.

> [!success] Definition of success
> “God-level” is not knowing every trick. It is having such strong fundamentals and such a disciplined experimental method that unfamiliar binaries become tractable, failed ideas produce information, and new techniques can be learned quickly from first principles.
