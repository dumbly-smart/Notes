---
tags: [binary-analysis, x86, tools, appendix-notes]
---

# Appendices — x86, ELF Injection, Tools, and Reading

## Appendix A — x86 assembly crash course

### Program layout

Assembly source contains instructions, directives, labels, and comments. Only encoded instructions/data become runtime bytes; directives tell the assembler/linker how to construct them.

Intel syntax is `operation destination, source`; AT&T generally reverses operands and decorates registers/immediates. Always identify syntax before tracing data.

### Machine state

```text
general registers: rax rbx rcx rdx rsi rdi rbp rsp r8-r15
rip: next instruction
rflags: ZF CF SF OF and others
memory: virtual address space
```

Partial registers matter: writing `eax` clears the upper half of `rax`; writing `ax`/`al` does not.

### Instruction encoding

x86 instructions are variable length and may include prefixes, opcode, ModR/M, SIB, displacement, and immediate. Not every field appears. RIP-relative addressing enables position-independent data/code references.

### Data movement and arithmetic

```asm
mov rax, rbx            ; copy value
lea rax, [rdi+rsi*4+8]  ; compute expression/address, no dereference
add eax, ecx
sub rsp, 0x20
movzx eax, byte ptr [rdi] ; zero extension
movsx eax, byte ptr [rdi] ; sign extension
```

### Control flow and flags

`cmp a,b` computes flag effects like `a-b` without storing result. `test x,x` checks zero/sign. Signed branches (`jl/jle/jg/jge`) interpret SF/OF/ZF; unsigned (`jb/jbe/ja/jae`) use CF/ZF.

### Calls and stack

`call` pushes return address and transfers control; `ret` pops target. Under System V AMD64, integer/pointer args normally use `rdi,rsi,rdx,rcx,r8,r9`; result uses `rax`; callee-saved registers are `rbx,rbp,r12-r15`; stack alignment must satisfy the ABI.

### Assembly reading algorithm

1. mark inputs by ABI;
2. split basic blocks;
3. track definitions and memory widths;
4. interpret branch signedness;
5. name stable stack/global locations;
6. identify loops/calls and their invariants;
7. express behavior as typed pseudocode;
8. validate with controlled runtime values.

## Appendix B — PT_NOTE overwriting

The book implements injection by repurposing a `PT_NOTE` program header. Conceptually it changes a nonessential note segment into a loadable segment covering appended injected bytes, adds matching section metadata, and redirects execution.

Critical invariants:

- chosen note content is genuinely nonessential for the lab;
- new `p_offset/p_vaddr` do not overlap mappings incorrectly;
- `p_filesz ≤ p_memsz`;
- `p_offset` and `p_vaddr` satisfy alignment congruence;
- flags are least-privilege, normally R-X for code rather than RWX;
- section-table relocation/count/name indices remain valid;
- payload is position independent or relocations are handled;
- original entry/behavior can resume.

Modern binaries may use notes for build IDs, properties, ABI metadata, or security features; blindly overwriting one is unsafe. Prefer adding a proper segment when building a robust rewriter.

## Appendix C — tool selection

| Need | Tool class/examples |
|---|---|
| identify/metadata | `file`, `readelf`, `objdump`, PE-aware parser |
| raw bytes | `xxd`, hex editor |
| symbols/dependencies | `nm`, `readelf`, loader-aware tools |
| static RE | Ghidra, Binary Ninja, IDA, rizin/Cutter |
| debugging | GDB/pwndbg, rr, WinDbg |
| syscall/library trace | `strace`, `ltrace` |
| decoding | Capstone; encoding with Keystone; IR with other frameworks |
| DBI | Pin, DynamoRIO, Frida (different abstraction/use cases) |
| fuzzing | AFL++/libFuzzer/Honggfuzz depending target/harness |
| symbolic | Z3, Triton, angr |

Tools change; verify current official documentation before installing or building. The concepts—format, ISA, ABI, coverage, model—outlast specific versions.

## Appendix D — further reading strategy

Read in layers:

1. ISA manuals and ABI for ground truth;
2. ELF/PE specifications for container semantics;
3. compiler/linker documentation for produced patterns;
4. disassembly/CFG papers for recovery limits;
5. DBI, taint, and symbolic execution papers for analysis models;
6. vulnerability research with exact versions and reproducible labs.

For every source, record date/version, threat model, assumptions, evaluated dataset, false-positive/negative definition, and whether code/artifacts reproduce.

## Appendix mastery questions

1. Why does writing `eax` affect `rax` differently from writing `ax`?
2. Which branch family should compare `size_t`, and why?
3. List five ways PT_NOTE repurposing can break a binary.
4. Why should an ISA manual outrank decompiler output?
5. Choose tools for a packed, stripped, network-facing ELF and justify sequence.

## Answers

1. x86-64 defines 32-bit writes as zero-extending into the full register; 16/8-bit writes preserve other bits.
2. Unsigned branches (`jb/jbe/ja/jae`) because `size_t` is unsigned, assuming the comparison has not been transformed.
3. Needed property note removed, overlaps, bad alignment, wrong flags, invalid counts/offsets, non-PIC payload, lost entry, or unmapped bytes.
4. The manual defines architectural semantics; a decompiler is a heuristic reconstruction with invented types/control structure.
5. Static identity/headers/imports first, isolated runtime tracing/DBI for unpacking transition, memory dump and reconstruction, then static/dynamic cross-analysis of unpacked code.
