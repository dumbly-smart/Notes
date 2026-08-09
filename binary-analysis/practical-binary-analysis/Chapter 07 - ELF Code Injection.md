---
tags: [binary-analysis, elf, patching, injection, authorized-lab, chapter-notes]
chapter: 7
---

# Chapter 7 — Simple Code Injection Techniques for ELF

## Chapter overview

The chapter turns analysis into controlled modification: patch an instruction, interpose library behavior, inject a section, and redirect execution. These techniques teach ELF invariants and are also useful for instrumentation and defensive experiments.

> [!warning] Scope
> Modify only a copy of an authorized lab binary. Record original and patched hashes. Persistent injection into third-party binaries without permission is out of scope.

```text
hypothesis → locate bytes → choose redirection → preserve ABI/layout
 → patch copy → re-disassemble → execute tests → compare behavior
```

## 7.1 Hex editing and the off-by-one example

An off-by-one occurs when a loop or bounds decision permits one element beyond the intended range. The book observes and fixes such a bug by changing machine code.

### Safe patch workflow

1. identify the faulty condition in source-equivalent logic;
2. locate the exact instruction and bytes;
3. determine instruction length and branch semantics;
4. translate virtual address through the correct load segment;
5. patch a copy with size-compatible encoding;
6. disassemble the patched region from a trusted boundary;
7. run boundary cases and compare side effects.

Example conceptual repair:

```asm
jle loop       ; permits i == bound
```

to:

```asm
jl loop        ; signed i < bound
```

This is correct only if the operands are signed and equality is the sole error. `jb` would be needed for unsigned below. A one-byte opcode change can alter control flow without moving surrounding code, but verify encoding.

## 7.2 `LD_PRELOAD` interposition

The dynamic loader can prefer symbols from a preloaded shared object.

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

void *malloc(size_t n) {
    static void *(*real_malloc)(size_t);
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    fprintf(stderr, "malloc(%zu)\n", n);
    return real_malloc(n);
}
```

Build/use in an authorized lab:

```bash
gcc -shared -fPIC -ldl hook.c -o hook.so
LD_PRELOAD=./hook.so ./lab
```

### Why wrappers are subtle

- initialization may recursively call the hooked routine;
- logging functions can allocate;
- threads require synchronization;
- ABI/signature/errno must be preserved;
- direct/internal/static calls may bypass interposition;
- secure-execution contexts restrict loader environment variables.

The book’s heap-overflow detector idea wraps allocation and related operations, records sizes, and checks whether writes exceed known objects. Interposing only `malloc` cannot observe arbitrary writes; detection needs wrappers around copy routines or instrumentation.

## 7.3 Injecting an ELF section

Adding bytes to the file is not sufficient. To execute them, the bytes must be mapped into memory with compatible permissions and addresses. Section headers serve tools; program headers control loading.

High-level injection:

1. choose a safe insertion location or append payload;
2. create/update section-name storage and section header if desired;
3. ensure a `PT_LOAD` maps the bytes, or add/extend a segment safely;
4. satisfy offset/VMA alignment congruence;
5. update counts/offsets affected by moved tables;
6. handle relocations or use position-independent payload;
7. redirect execution and provide a return path.

> [!deep-dive] Why section-only injection may not run
> The kernel does not normally map a new section merely because it appears in the section-header table. If no loadable segment covers its file range, the bytes are invisible to the running process.

## 7.4 Calling injected code

### Entry-point modification

Change `e_entry` to injected code. The payload must preserve startup assumptions and eventually transfer to the original entry. It executes before runtime initialization, so many library services may be unavailable.

### Constructor/destructor hijacking

Change or add function pointers in initialization/finalization arrays. Constructors run before `main` after enough runtime setup; destructors run on normal teardown. Verify array relocations and termination paths.

### GOT redirection

Change a resolved/imported function pointer relationship so a call reaches the hook. Full RELRO makes the GOT read-only after relocation at runtime; file-time rewriting and relocation behavior remain separate questions.

### PLT rewriting

Redirect a stub while respecting instruction size, PC-relative reach, and lazy-binding structure. Linker implementations vary.

### Direct/indirect call redirection

Patch direct relative displacement or pointer tables. For x86 `call rel32`:

```text
displacement = target - address_after_call
```

The signed 32-bit displacement limits reach. If out of range, use a nearby trampoline.

## Trampoline reasoning

```text
original site
 → jump trampoline
      → save required state
      → execute instrumentation/payload
      → reproduce displaced instructions
      → jump original continuation
```

Relocating displaced instructions is hard when they use RIP-relative addressing or relative branches. Re-encode their meaning for the trampoline’s new location.

## Validation checklist

- original and patched SHA-256 recorded;
- exact changed offsets/bytes documented;
- ELF parser accepts headers;
- program-header mappings cover injected bytes;
- no accidental W+X segment unless explicitly justified in lab;
- disassembly boundaries valid;
- stack alignment, registers, flags, and calling convention preserved;
- original behavior regression-tested;
- hook executes once/at intended times;
- ASLR/PIE tested across clean runs.

## Common mistakes

- Mapping a VMA directly to file offset.
- Adding a section but no load mapping.
- Overwriting more/less bytes than the replacement instruction.
- Forgetting signed relative-displacement range.
- Moving RIP-relative instructions without fixing references.
- Assuming interposition catches static/internal calls.
- Testing only the new behavior, not unchanged paths.

## Practice questions

1. Why can `jle → jl` be wrong even for an off-by-one?
2. Explain why a newly listed executable section might never enter memory.
3. What state must a trampoline preserve?
4. Compute `rel32` from a call at `0x401000` (length 5) to `0x402000`.
5. Compare entry-point, constructor, GOT, and direct-call redirection.
6. Why can a `malloc` interposer recurse before initialization finishes?

## Solutions

1. The comparison may be unsigned, equality may be valid, or the actual bound may differ. Recover types/invariant first.
2. Runtime loading follows program headers; no covering `PT_LOAD` means section bytes are not mapped.
3. Any live registers/flags, stack alignment, displaced instruction semantics, ABI-preserved registers, and a correct continuation.
4. Address after call is `0x401005`; displacement is `0x402000 - 0x401005 = 0xffb`, encoded little-endian as a signed 32-bit value.
5. Entry runs earliest; constructors run around runtime startup; GOT/PLT target imports; direct calls patch one site. Each has different scope, prerequisites, and hardening interaction.
6. Resolving/logging can allocate internally and invoke the wrapper again. Use recursion guards and allocation-free bootstrap techniques.

## Mastery checklist

- [ ] Patch a branch in a toy copy and prove the invariant changed.
- [ ] Write a non-recursive minimal interposer.
- [ ] Explain section versus mapped segment for injection.
- [ ] Calculate and validate a relative redirection.
- [ ] Design a trampoline that handles RIP-relative displaced code.

## Extended chapter synthesis

**Key process:** hypothesize → patch only a copy → map VA through correct segment → preserve encoding/ABI/layout → re-disassemble → run identical regression matrix → document bytes and hashes.

**Key formulas:** `rel_displacement = target - address_after_instruction`; ELF mapping uses the containing `PT_LOAD`.

**Common confusion:** adding a section is not the same as mapping a segment; changing behavior is not proof the patch preserved all other paths.

Full 48-question set with worked solutions: [[Workbooks/Chapter 07 - Practice and Complete Solutions]].
