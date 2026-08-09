---
tags: [binary-analysis, instrumentation, pin, unpacking, chapter-notes]
chapter: 9
---

# Chapter 9 — Binary Instrumentation

## Chapter overview

Instrumentation adds analysis callbacks at selected execution points. The chapter compares static instrumentation with dynamic binary instrumentation (DBI), develops a Pin profiler, and detects unpacked code by following writes followed by control transfer.

```text
target instructions
 → instrumentation policy decides where
 → analysis callbacks observe/update tool state
 → target executes with translated/rewritten code
```

## 9.1 APIs and placement

Instrumentation granularity includes image, routine, trace, basic block, instruction, syscall, and memory access. Insert the least expensive callback that answers the question.

Example: to count executed instructions, increment once per basic block by its static instruction count rather than callback on every instruction. This changes instrumentation frequency without changing the final count.

## 9.2 Static binary instrumentation

### `int3` approach

Replace an instruction byte with breakpoint opcode `0xCC`. On trap, a handler/tool identifies the site, performs analysis, emulates or temporarily restores/steps the displaced instruction, reinstalls the trap, and resumes.

Benefits: one-byte patch and flexible analysis. Costs: traps/context switches are expensive; threads and signals complicate correctness; self-checking code sees changes.

### Trampoline approach

Replace enough original bytes with a branch to a code cave/new region. Execute analysis and relocated original semantics, then return. Faster at runtime but relocation and layout are harder. See [[Chapter 07 - ELF Code Injection]].

## 9.3 DBI architecture

A DBI system commonly:

1. gains control before target execution;
2. decodes target blocks/traces;
3. creates translated code in a cache;
4. inserts analysis calls according to the tool;
5. links cached blocks and executes them;
6. handles syscalls, signals, threads, code changes, and cache invalidation.

The target often executes translated copies, not its original bytes directly. Correctness requires transparent register/flags state, control-flow behavior, exceptions, and memory ordering within documented limits.

## 9.4 Pin profiler

### Data model

Per image/function/basic block, store stable identifiers and counters. Global counters updated by multiple threads must use thread-local accumulation or synchronization.

Metrics:

- executed instructions;
- basic blocks/traces;
- direct/indirect calls and branches;
- taken/not-taken branches;
- syscalls;
- per-function dynamic counts.

### Static versus dynamic counts

A basic block containing five instructions contributes five each time it executes. A loop block executed 1,000 times contributes 5,000 dynamic instructions. Static code size is still five instructions.

### Function attribution

Symbols provide convenient ranges but stripped functions and tail calls complicate attribution. Image offsets are more stable than raw runtime addresses under ASLR:

```text
offset = runtime_address - runtime_image_base
```

## 9.5 Automatic unpacking

Packers store transformed code and execute a stub that reconstructs original code in memory.

Core heuristic:

```text
memory byte written during execution
       +
later instruction fetch/control transfer into written region
       =
candidate unpacked/generated code transition
```

### Tracking design

1. record memory-write ranges, merging overlaps;
2. on control transfers, test destination against written ranges;
3. avoid flagging ordinary stack/heap JIT-like behavior without context;
4. record the transition and mappings;
5. dump relevant mapped ranges;
6. reconstruct a usable file or analyze memory directly.

A raw memory dump may lack valid file headers, imports, relocations, or original section layout. “Dump succeeded” does not mean “reconstructed executable is runnable.”

### False positives/negatives

False positives: JIT compilers, runtime trampolines, legitimate self-modifying code, loaders. False negatives: writes outside tracked granularity, kernel/device modification, code copied before instrumentation, direct fall-through into written bytes, unsupported control events.

## Performance model

```text
total overhead ≈ translation cost + callback frequency × callback cost
                 + synchronization + output cost
```

Buffer events per thread and write in batches. Logging every instruction to a locked text file can change timing and make the tool unusable.

## Common mistakes

- Instrumenting every instruction when block-level suffices.
- Using unsynchronized global counters.
- Confusing static block size with dynamic execution count.
- Reporting ASLR-dependent addresses without module offsets.
- Treating write-then-execute as proof of malicious packing.
- Expecting a memory dump to be a valid on-disk ELF.

## Practice questions

1. Compare `int3`, trampoline, and DBI instrumentation.
2. How can block instrumentation count instructions correctly?
3. Why use thread-local counters?
4. Design a packed-code transition detector that handles overlapping writes.
5. List metadata needed to interpret an address after the run.
6. Explain how instrumentation can change observed behavior.

## Solutions

1. `int3` uses traps and minimal patches; trampolines statically redirect and relocate; DBI translates at runtime with rich APIs. They trade performance, persistence, complexity, and transparency.
2. Insert one increment by the block’s instruction count at block entry; multiply implicitly through repeated executions.
3. They avoid hot global contention and data races; aggregate safely at thread end/finalization.
4. Maintain an interval set of written addresses; merge ranges; check every actual transfer/fetch destination; label mappings and transition time.
5. Image name/hash, runtime base, static offset, mapping permissions, thread/time, symbol if available, and load/unload events.
6. Timing, memory layout, signal behavior, thread scheduling, and anti-analysis checks can differ; validate with lower-intrusion evidence.

## Mastery checklist

- [ ] Select instrumentation granularity by question and cost.
- [ ] Explain trap, trampoline, and code-cache approaches.
- [ ] Design a thread-correct profiler.
- [ ] Detect and critically evaluate write-to-execute transitions.
