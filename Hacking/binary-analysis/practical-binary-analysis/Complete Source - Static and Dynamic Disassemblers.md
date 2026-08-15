# Complete Source — Static and Dynamic Disassemblers

These are compiled, executed reference implementations—not pseudocode. The static tool parses bounded ELF64 program headers and recursively decodes explicit seeds with Capstone. The dynamic tool launches an authorized local target with `ptrace`, reads bytes at RIP before execution, decodes one instruction, single-steps, and records the concrete successor.

## Build

```bash
gcc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion Code/minidis.c -lcapstone -o minidis
gcc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion Code/minitrace.c -lcapstone -o minitrace
```

Both builds were verified with zero warnings against Capstone 5.0.9.

## Complete static-disassembler source

![[Code/minidis.c]]

## Static run against the stripped Chapter 2 target

```bash
./minidis ch02_stripped \
  0x1460 0x1470 0x1490 0x14b0 0x1510 \
  0x1550 0x1580 0x1610 0x1640 0x16c0 \
  0x16e0 0x16f0 0x1730 0x1760 0x17e0
```

Observed excerpts:

```text
entry=0x1310 executable_segments=1
0x1760: push     rbp
0x1790: mov      edi, dword ptr [r15 + rbx*4]
0x1794: call     r13
0x1730: mulsd    xmm1, xmm0
0x174c: divsd    xmm1, xmm0
0x16e0: mov      rax, rdi
0x16e3: add      rax, rdx
0x16e6: adc      rsi, rcx
0x16e9: mov      qword ptr [r8], rsi
0x1030: jmp      qword ptr [rip + 0x2fca]
unresolved-indirect at 0x1030
```

The unresolved edge is correct: an import trampoline is indirect, and the minimal tool refuses to invent a target. Add relocation/import resolution as the next milestone.

## Complete dynamic-disassembler source

![[Code/minitrace.c]]

## Dynamic run

```bash
./minitrace 80 ./ch02_debug
```

Observed excerpts:

```text
000002 tid=512597 pc=0x7f710af6e303 from=0x7f710af6e300 call     0x7f710af6eec0
000024 tid=512597 pc=0x7f710af6ef16 from=0x7f710af6ef13 je       0x7f710af6ef98
000027 tid=512597 pc=0x7f710af6ef2a from=0x7f710af6ef23 jmp      0x7f710af6ef47
000030 tid=512597 pc=0x7f710af6ef36 from=0x7f710af6ef4b mov      qword ptr [rcx + rax*8], rdx
```

The first budgeted instructions belong to the dynamic loader. That is expected: dynamic disassembly records what executes, not only the main executable. The next milestone is parsing `/proc/<pid>/maps` and emitting module-relative offsets.

## Validation checklist

- Reject malformed ELF metadata without an out-of-bounds read.
- Compile under ASan/UBSan during development.
- Diff static boundaries against `objdump -d` and Ghidra.
- Keep indirect edges unresolved until evidence resolves them.
- Test taken and fall-through branch inputs.
- Forward genuine target signals.
- Treat the tracer as an observer, not a sandbox.
- Add thread/clone/exec handling before multithreaded targets.

## Next milestones

1. Add ELF symbols and relocation-aware PLT naming.
2. Export basic blocks and edges as Graphviz DOT.
3. Normalize runtime addresses with memory maps and load segments.
4. Schedule all traced threads and record signal provenance.
5. Version blocks when executed bytes change.
6. Add an IR lifter and use the Chapter 13 functions as regression tests.
