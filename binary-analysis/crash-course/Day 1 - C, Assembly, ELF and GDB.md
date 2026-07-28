---
tags: [ctf, x86-64, assembly, elf, gdb]
day: 1
---

# Day 1 — C, x86-64 Assembly, ELF, and GDB

Back: [[01 - One Week RE and Pwn Crash Course]]

## Mental model: source to process

```text
C source → preprocessor → compiler → assembly → assembler
→ relocatable object → linker → ELF → kernel/loader → process
```

```bash
gcc -E demo.c -o demo.i
gcc -S -masm=intel demo.c -o demo.s
gcc -c demo.c -o demo.o
gcc demo.o -o demo
gcc -g -O0 demo.c -o demo_debug
gcc -O2 demo.c -o demo_O2
```

The object already contains machine code but may have unresolved references. The linker combines objects/libraries, lays out the executable, and records relocations and loader metadata.

## Memory essentials

- `.text`: executable instructions.
- `.rodata`: constants and string literals.
- `.data`: initialized writable globals.
- `.bss`: zero-initialized globals.
- Heap: dynamically allocated objects.
- Stack: call state and local storage.

Little-endian stores the least-significant byte first:

```text
0x1122334455667788 → 88 77 66 55 44 33 22 11
```

Watch for signed/unsigned conversion, integer wraparound, truncation, pointer lifetime, array bounds, and byte-count versus element-count mistakes.

## Registers and instructions

- `rip`: next instruction.
- `rsp`: top of stack.
- `rbp`: optional frame base.
- `rax`: usual return register.
- `rflags`: condition state.

```asm
mov rax, rbx          ; copy value
mov eax, [rbp-4]      ; load four bytes
mov [rdi+8], rax      ; store eight bytes
lea rax, [rdi+rdi*2]  ; calculate 3*rdi, no dereference
cmp edi, 10           ; set flags from edi-10
je equal
```

Writing `eax` clears the high half of `rax`. `cmp`/`test` update flags; signed (`jl`) and unsigned (`jb`) branches interpret them differently.

## System V AMD64 ABI

| Argument | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| Register | `rdi` | `rsi` | `rdx` | `rcx` | `r8` | `r9` |

Return value: `rax`. Callee-saved: `rbx`, `rbp`, `r12`–`r15`. Stack alignment matters at call boundaries.

```c
long f(long x, long y) { return x * 3 + y; }
```

```asm
f:
    lea rax, [rdi+rdi*2]
    add rax, rsi
    ret
```

## ELF

Sections organize link-time content; segments describe runtime mappings. One load segment may contain multiple sections.

```bash
readelf -hW ./demo   # header
readelf -SW ./demo   # sections
readelf -lW ./demo   # segments
readelf -sW ./demo   # symbols
readelf -rW ./demo   # relocations
```

PLT stubs and GOT entries support dynamic function resolution. The loader places the resolved runtime address into the GOT.

### Mitigations

- NX: writable data is not executable.
- ASLR: randomizes runtime mappings.
- PIE: allows the main executable base to be randomized.
- Canary: detects overwrites before saved return state.
- Full RELRO: makes the resolved GOT read-only.

## GDB workflow

```gdb
starti
break main
run
si
ni
finish
continue
info registers
x/12gx $rsp
x/10i $rip
info proc mappings
watch *(int*)ADDRESS
```

Use breakpoints to stop at code, watchpoints to stop when data changes, and mappings to relate static offsets to runtime bases.

## Labs

- [ ] Hand-trace 20 short functions.
- [ ] Compile one program at `-O0`/`-O2`, PIE/non-PIE, stripped/unstripped.
- [ ] Predict then verify its mitigations.
- [ ] Find `main` and one comparison in GDB.
- [ ] Solve one easy stripped crackme.

## Gate

Explain an unseen function’s arguments, locals, branches, and return value, then prove the explanation dynamically in a stripped PIE.

Next: [[crash-course/Day 2 - Reverse Engineering]]

