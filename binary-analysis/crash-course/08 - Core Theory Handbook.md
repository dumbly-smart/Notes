---
aliases:
  - RE and Pwn Core Theory
tags: [ctf, reverse-engineering, binary-exploitation, reference]
---

# Reverse Engineering & Binary Exploitation — Core Theory Handbook

Back: [[00 - One-Week RE and Pwn Crash Course]]

This is the teaching companion to the crash course. Read the matching chapter before doing each day’s labs. Commands and examples assume an authorized Linux x86-64 CTF lab.

# 1. From C to machine code

## Compilation pipeline

```text
source.c
  ↓ preprocessor: expands includes and macros
source.i
  ↓ compiler: translates language semantics to assembly
source.s
  ↓ assembler: encodes instructions and emits relocatable object
source.o
  ↓ linker: combines objects/libraries and resolves references
executable ELF
  ↓ kernel + dynamic loader
process memory
```

Useful experiments:

```bash
gcc -E demo.c -o demo.i
gcc -S -masm=intel demo.c -o demo.s
gcc -c demo.c -o demo.o
gcc demo.o -o demo
gcc -O2 -fno-omit-frame-pointer demo.c -o demo_O2
gcc -g -O0 demo.c -o demo_debug
```

An object file can contain machine code while still having unresolved references. The linker connects those references, lays out the executable, and records information the loader will need.

## Process memory

A running process sees a virtual address space. Typical mappings include:

```text
low addresses
  executable code and data
  heap → usually grows upward
  mapped files and shared libraries
  stack → usually grows downward
high addresses
```

- `.text`: executable instructions, normally read/execute.
- `.rodata`: constants and string literals, normally read-only.
- `.data`: initialized writable globals.
- `.bss`: zero-initialized globals; its size is represented without storing all zero bytes.
- Heap: dynamic allocations managed by an allocator such as glibc `malloc`.
- Stack: call frames, saved state, local storage, arguments that do not fit in registers.

These are conventions and loader mappings, not magical physical regions.

## Integers and bytes

An unsigned `n`-bit integer represents `0` through `2^n - 1`. A two’s-complement signed `n`-bit integer represents `-2^(n-1)` through `2^(n-1)-1`.

Little-endian stores the least significant byte first:

```text
value:       0x1122334455667788
memory low → 88 77 66 55 44 33 22 11
```

Common vulnerability boundaries:

- signed value checked as negative, then converted to a large unsigned size;
- multiplication/addition wraps before allocation;
- large integer truncates when assigned to a smaller type;
- byte count and element count are confused.

# 2. x86-64 assembly and the ABI

## Registers

The main 64-bit general-purpose registers are `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `rsp`, and `r8`–`r15`.

- `rip`: address of the next instruction.
- `rsp`: current top of the stack.
- `rbp`: often a frame base at low optimization; it can be a normal register.
- `rax`: usual integer return value.
- `rflags`: condition flags used by conditional branches.

Writing a 32-bit subregister such as `eax` clears the high 32 bits of `rax`. Writing `al` changes only its low byte.

## Intel operand model

```asm
mov rax, rbx          ; rax = rbx
mov eax, [rbp-4]      ; load 4 bytes from memory
mov [rdi+8], rax      ; store 8 bytes
lea rax, [rdi+rdi*2]  ; calculate 3*rdi; no memory read
```

Square brackets mean memory access except when `lea` is calculating the address itself.

## Arithmetic and branches

`cmp a, b` conceptually computes `a-b` and updates flags without saving the result. `test a, a` performs a bitwise AND for flags and is commonly used to check zero.

```asm
cmp edi, 10
je  equal
jl  less_signed
jb  below_unsigned
```

Signed and unsigned comparisons interpret the same bits differently. This matters when recovering types.

## Calls and stack frames

`call target` pushes the return address and transfers control. `ret` pops an address into `rip`.

System V AMD64 integer/pointer arguments:

| Argument | Register |
|---:|---|
| 1 | `rdi` |
| 2 | `rsi` |
| 3 | `rdx` |
| 4 | `rcx` |
| 5 | `r8` |
| 6 | `r9` |

Return value is normally in `rax`. Registers `rbx`, `rbp`, and `r12`–`r15` are callee-saved. The caller must assume that `rax`, `rcx`, `rdx`, `rsi`, `rdi`, and `r8`–`r11` may change.

Example:

```c
long f(long x, long y) {
    return x * 3 + y;
}
```

Possible assembly:

```asm
f:
    lea rax, [rdi+rdi*2]
    add rax, rsi
    ret
```

The absence of a stack frame does not mean the decompiler lost code; this leaf function needs no stack storage.

## Recognizing common constructs

Array access:

```asm
mov eax, [rdi+rcx*4]
```

suggests 4-byte elements at base `rdi`, index `rcx`.

Struct access:

```asm
mov eax, [rdi+0x18]
```

suggests a 4-byte field at offset `0x18` from an object pointer.

A dense `switch` often becomes a bounds check followed by an indirect jump through a jump table. An optimized loop may use pointer-end comparisons instead of a visible index.

# 3. ELF, dynamic linking, and mitigations

## Sections versus segments

Sections organize material for linking and analysis. Segments describe what the loader maps into memory. A loadable segment can contain several sections.

```bash
readelf -hW ./chall   # ELF header
readelf -SW ./chall   # sections
readelf -lW ./chall   # segments
readelf -sW ./chall   # symbols
readelf -rW ./chall   # relocations
readelf -dW ./chall   # dynamic tags
```

## PLT and GOT

Position-independent dynamically linked code cannot embed the final address of every library function. A call may go through a Procedure Linkage Table stub, which uses a Global Offset Table entry. The dynamic loader resolves and stores the runtime library address.

For exploitation reasoning, a GOT slot can be:

- a source of a real libc address if it has been resolved;
- a write target only when protections permit;
- useless for overwrite under full RELRO, though still potentially readable.

## Mitigations

- **NX:** writable data mappings are not executable. It blocks ordinary injected stack shellcode, not code reuse.
- **ASLR:** randomizes bases of stack, heap, libraries, and other mappings.
- **PIE:** lets the main executable itself load at a randomized base.
- **Stack canary:** a secret value before saved control data is checked before returning.
- **Partial RELRO:** changes some relocation behavior but normally leaves writable GOT entries.
- **Full RELRO:** resolves relocations early and makes the GOT read-only.

Mitigations do not fix the bug. They remove easy exploit paths, so the attacker needs different primitives.

# 4. Static and dynamic reversing

## The core method

1. Triage format, architecture, mitigations, imports, and strings.
2. Find input sources and success/failure sinks.
3. Map functions and data that connect them.
4. Rename and retype aggressively.
5. Write a behavioral hypothesis.
6. Design a debugger experiment that could disprove it.
7. Extract only the decisive transformation into a solver.

## Decompiler discipline

Decompiler output is reconstructed pseudocode, not source. Common errors include:

- wrong signedness;
- wrong pointer or array type;
- merged or split variables;
- inaccurate function prototypes;
- misleading loop shapes;
- hidden truncation or partial-register behavior.

When a result seems impossible, inspect the relevant instructions and calling convention.

## Working backward

Finding a success string and following its cross-reference can reveal the final branch. Work backward through the values controlling that branch. In parallel, work forward from input functions. The intersection is usually the validation core.

## Data structure recovery

Infer fields from consistent offsets:

```text
[obj+0x00] used as pointer  → probable pointer field
[obj+0x08] compared to len  → probable size field
[obj+0x10+i*4]              → probable integer array
```

Allocation size, access width, constructor behavior, and use across functions strengthen the inference.

## Dynamic tools

- `strace`: system calls, files, process behavior.
- `ltrace`: dynamic library calls when observable.
- GDB: instruction-level state and control.
- Ghidra: static structure, references, and decompilation.

Use the least invasive tool that answers the question.

Essential GDB:

```gdb
starti
break *ADDRESS
run
continue
si
ni
finish
info registers
x/10gx $rsp
x/10i $rip
info proc mappings
watch *(int*)ADDRESS
```

With PIE, raw static addresses need relocation. Debugger extensions often provide commands such as `piebase`, `vmmap`, `telescope`, and `cyclic`.

# 5. Stack corruption and shellcode

## Why an overflow controls execution

If an unchecked write into a local stack buffer continues into saved control data, it may overwrite the saved return address. On `ret`, the CPU consumes the overwritten bytes as the next `rip`.

Conceptual frame:

```text
higher addresses
saved return address
saved frame pointer
padding
local buffer
lower addresses
```

Exact order and padding depend on compiler output. Measure with disassembly and a cyclic pattern.

```python
from pwn import *
print(cyclic(300))
print(cyclic_find(0x6161616b))
```

The exploit is not “send many A characters.” It is:

```text
prove unchecked write
→ calculate offset
→ prove controlled RIP
→ choose valid target
→ satisfy target’s arguments and constraints
```

## Shellcode

Shellcode is position-independent machine code placed in attacker-controlled executable memory. On Linux x86-64, a syscall uses:

| Purpose | Register |
|---|---|
| syscall number | `rax` |
| arguments 1–3 | `rdi`, `rsi`, `rdx` |
| arguments 4–6 | `r10`, `r8`, `r9` |

`syscall` enters the kernel. NX often forces a return-oriented approach instead.

## Pwntools skeleton

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./chall", checksec=False)
context.log_level = "info"

def start():
    if args.GDB:
        return gdb.debug(exe.path, gdbscript="break main\ncontinue")
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process(exe.path)

io = start()
offset = 72                 # justify from cyclic/core evidence
payload = flat(
    b"A" * offset,
    exe.sym["win"],
)
io.sendlineafter(b"> ", payload)
io.interactive()
```

`sendlineafter` is appropriate only when that exact delimiter is reliable. When receiving a binary leak, do not accidentally strip meaningful null bytes.

# 6. ROP and ret2libc

## ROP mental model

A ROP chain is a synthetic sequence of stack values. Each `ret` loads the next gadget address; pop gadgets consume following stack entries.

```text
saved RIP = pop rdi; ret
next qword = desired first argument
next qword = target function
next qword = safe return location
```

Track `rsp` after each instruction. A gadget may pop several registers or modify memory; all side effects matter.

## Two-stage leak

When libc is randomized:

1. Call an output function on a GOT entry.
2. Return to a location that accepts another payload.
3. Parse the leaked runtime address.
4. Subtract the known symbol offset to obtain libc base.
5. Add offsets for the final function and argument.

```python
rop = ROP(exe)
rop.call(exe.plt["puts"], [exe.got["puts"]])
rop.call(exe.sym["main"])

io.sendline(flat(b"A" * offset, rop.chain()))
leak = u64(io.recvline().strip().ljust(8, b"\0"))
libc.address = leak - libc.sym["puts"]
log.info("libc base: %#x", libc.address)
assert libc.address & 0xfff == 0
```

Real output parsing must match the target’s exact behavior. A line-based parser is not universally safe.

Second stage:

```python
rop = ROP([exe, libc])
rop.call(libc.sym["system"], [next(libc.search(b"/bin/sh\0"))])
io.sendline(flat(b"A" * offset, rop.chain()))
```

On some paths, an extra `ret` is required to preserve 16-byte stack alignment before a library function.

## PIE and canaries

With PIE, gadgets and symbols in the main binary also require its runtime base. A code-pointer leak can reveal it:

```text
binary base = leaked code pointer - known static offset
```

A canary must normally be preserved. A leak can reveal it; alternate corruptions may avoid overwriting it. Brute force is justified only under specific restart/fork and entropy conditions.

# 7. Format-string vulnerabilities

## Root cause

Safe:

```c
printf("%s", user_input);
```

Vulnerable:

```c
printf(user_input);
```

The second form interprets attacker bytes as formatting instructions. Because variadic arguments have no type/count metadata available to `printf`, conversions can consume register-save-area or stack values that were never intended as arguments.

## Reads

`%p` prints pointer-sized values; positional syntax such as `%7$p` selects an argument. After discovering where controlled bytes appear, `%s` with a supplied address can dereference memory—but invalid addresses can crash.

## Writes

`%n` writes the number of characters printed so far. Width variants change write size:

- `%hhn`: one byte;
- `%hn`: two bytes;
- `%n`: usually four bytes;
- `%ln`: long-sized.

Padding is modular. For byte writes, print enough characters that the low byte of the count equals the desired value. Sort multi-writes to minimize wraparound. Pwntools can generate payloads, but first build a small manual write so the mechanism is understood.

```python
payload = fmtstr_payload(offset, {target: value}, write_size="short")
```

# 8. Heap foundations

## Allocator viewpoint

The program requests a usable size; the allocator manages a larger chunk containing metadata and aligned user space. Freed chunks may be organized into size-specific caches/bins for reuse.

Core bug classes:

- **Heap overflow:** write crosses one object into adjacent data/metadata.
- **Use-after-free:** program retains and uses a pointer after the allocation’s lifetime ended.
- **Double free:** same live allocation identity is released twice.
- **Invalid free:** supplied pointer is not a valid currently allocated chunk.

## Tcache concept

Modern glibc commonly keeps a per-thread cache of recently freed chunks by size class. A later allocation of the same class may return the most recently cached chunk.

```text
free(A) → tcache[size]: A
free(B) → tcache[size]: B → A
malloc(size) returns B
```

A UAF becomes powerful when a stale pointer aliases a replacement object. If the old code treats replacement bytes as a trusted pointer or callback, type confusion may yield read, write, or control.

Freelist pointers in modern glibc may be encoded (“safe-linking”), and double-free checks vary by version. Never copy a technique without matching the target libc and checking its invariants.

## Heap debugging questions

After every operation:

1. Which exact chunk was returned/freed?
2. What is its real chunk size?
3. Which bin/cache contains it?
4. Which program pointers still reference it?
5. What metadata or user fields changed?
6. What allocator check will run next?

A named “house” is a historical technique, not a substitute for this state model.

# 9. Advanced constraints

## Seccomp

Seccomp filters restrict which syscalls a process may invoke. If a direct process-spawn syscall is blocked but file operations are allowed, a CTF chain may:

```text
open permitted target → read contents → write to output
```

This is commonly called ORW. Exact syscall availability, file descriptor values, architecture, and filter rules must be verified.

## Stack pivots

A pivot changes `rsp` to a larger attacker-controlled region when the original overflow has too little space. Gadgets involving `leave; ret`, `xchg` with `rsp`, or controlled stack restoration may serve, depending on the binary.

## SROP

Sigreturn-oriented programming uses a crafted signal frame so the kernel restores many registers at once. It requires a route to the appropriate syscall and precise architecture-specific frame layout.

## Symbolic solving

Direct Z3 is ideal when validation logic can be expressed as constraints:

```python
from z3 import *

x = [BitVec(f"x{i}", 8) for i in range(4)]
s = Solver()
for c in x:
    s.add(c >= 0x20, c <= 0x7e)
s.add(x[0] ^ x[1] == 0x12)
s.add(x[2] + x[3] == 0x90)

if s.check() == sat:
    m = s.model()
    print(bytes(m[c].as_long() for c in x))
```

Symbolic execution additionally models program paths, but unconstrained input and library/environment behavior can cause state explosion. Restrict input length, hook irrelevant functions, and target specific success/failure addresses.

# 10. Reliability and debugging

## Reliability checklist

- Derive randomized addresses from leaks; do not paste runtime values.
- Assert page-aligned bases and plausible mapping ranges.
- Synchronize on exact protocol states.
- Preserve raw bytes in leaks.
- Record binary, loader, libc, and architecture versions.
- Remove sleeps used to hide parsing bugs.
- Log stage boundaries and calculated addresses.
- Test from new processes with ASLR enabled.

## Failure diagnosis

| Symptom | Investigate |
|---|---|
| Crash at `ret` or SIMD instruction | stack alignment, corrupt chain |
| Jump into unmapped address | bad leak parsing/base calculation |
| Works only in GDB | environment/layout/timing assumptions |
| Hangs waiting for output | wrong delimiter or target waiting for input |
| Works locally, not remotely | libc/loader mismatch, protocol difference |
| Intermittent heap failure | incorrect state assumption or nondeterministic layout |

Debug at the first state divergence, not at the final crash. Compare a successful and failing run at the boundary between exploit stages.

# 11. What one week can and cannot do

This handbook supplies the core models for beginner-to-intermediate Linux x86-64 CTF work. Deep modern heap exploitation, kernel/browser exploitation, Windows internals, advanced devirtualization, and unfamiliar architectures each require dedicated study after the crash course.

Mastery grows from unseen challenges, accurate postmortems, and re-solving—not from reading this note once.

