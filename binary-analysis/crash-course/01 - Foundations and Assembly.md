---
tags: [ctf, assembly, elf, gdb]
day: 1
---

# Day 1 — Foundations, Assembly, ELF, and GDB

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Read ordinary x86-64 functions, explain how an ELF becomes a process, and inspect execution confidently in GDB.

## Lesson

Read [[08 - Core Theory Handbook#1. From C to machine code]], [[08 - Core Theory Handbook#2. x86-64 assembly and the ABI]], and [[08 - Core Theory Handbook#3. ELF, dynamic linking, and mitigations]] before beginning the labs.

## Schedule

### Block 1 — C and memory (90 min)

- [ ] Review integers, signedness, casts, pointers, arrays, and pointer arithmetic.
- [ ] Draw stack, heap, globals, code, and shared libraries.
- [ ] Explain lifetime differences between local, static, and allocated objects.
- [ ] Write tiny examples of out-of-bounds access, use-after-free, integer truncation, and format-string misuse.

### Block 2 — x86-64 essentials (2 hr)

- [ ] Registers: general purpose, `rip`, `rsp`, `rbp`, flags, partial registers.
- [ ] Instructions: `mov`, `lea`, arithmetic, bitwise, `cmp`, `test`, jumps, `call`, `ret`.
- [ ] Addressing: `[base + index*scale + displacement]`.
- [ ] Little-endian representation and two’s complement.
- [ ] System V AMD64 arguments: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; return in `rax`.
- [ ] Caller/callee-saved registers and 16-byte stack alignment.

Hand-trace at least 20 short snippets. Before running them, predict registers, flags, branch direction, and return value.

### Block 3 — Compilation and ELF (90 min)

Compile the same small program at `-O0` and `-O2`, with and without PIE and symbols.

- [ ] Trace `source → assembly → object → linked ELF → loaded process`.
- [ ] Distinguish sections from segments.
- [ ] Locate entry point, program headers, `.text`, `.data`, `.bss`, symbols, imports, PLT, and GOT.
- [ ] Explain NX, PIE, ASLR, canary, and RELRO in one sentence each.
- [ ] Predict `checksec` output before checking.

Use existing notes:

- [[02 - Source Code to Running Program]]
- [[03 - Executable Formats - ELF and PE]]
- [[04 - Binary Loading and Linux Analysis]]
- [[05 - x86-64 Assembly for Binary Analysis]]

### Block 4 — GDB fluency (2 hr)

- [ ] Start, break, run, continue, step instruction, and finish.
- [ ] Inspect registers, stack, mappings, instructions, and arbitrary memory.
- [ ] Set a conditional breakpoint and a watchpoint.
- [ ] Find `main` in a stripped PIE binary.
- [ ] Follow a value from input to comparison.
- [ ] trigger a crash and identify the faulting instruction and corrupted value.

### Block 5 — Blind lab (2 hr)

Take an unseen, easy Linux x86-64 binary:

1. Triage it without Ghidra.
2. Find its input and success path.
3. Recover the validation logic.
4. Verify in GDB.
5. Write a short solver or valid input.

## Deliverables

- [ ] Annotated stack frame for one function.
- [ ] ELF-to-process diagram.
- [ ] Twenty assembly traces.
- [ ] GDB command log.
- [ ] One solved beginner crackme and write-up.

## Gate

Without notes, explain an unseen function’s arguments, locals, branches, and return value; then set a breakpoint at it in a stripped PIE and prove the explanation dynamically.

**Result:** [ ] Pass [ ] Repair needed

Next: [[02 - Reverse Engineering Workflow]]
