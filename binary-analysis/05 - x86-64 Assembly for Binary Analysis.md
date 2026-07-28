# x86-64 Assembly for Binary Analysis

## Purpose

This is not a course in writing large assembly programs. Its purpose is to make disassembled x86-64 code readable enough that we can recover:

- data movement and transformations;
- function inputs, outputs, and local state;
- conditions, loops, calls, and returns;
- memory layout and pointer use;
- compiler-generated patterns;
- suspicious or security-relevant behavior.

The central question is always:

> What machine state does this instruction read, and what machine state can it change?

---

## 1. The machine-state model

At any instant, a thread's relevant architectural state includes:

```text
┌────────────────────────────────────────────┐
│ General-purpose registers                 │
│ rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp…   │
├────────────────────────────────────────────┤
│ Instruction pointer: rip                   │
├────────────────────────────────────────────┤
│ Status flags: ZF, CF, SF, OF…              │
├────────────────────────────────────────────┤
│ Virtual memory                            │
│ code, globals, heap, stack, mappings…      │
└────────────────────────────────────────────┘
```

An instruction changes this state. Analysis consists largely of tracking those changes while preserving uncertainty where the value is not known.

For example:

```asm
mov eax, 5
add eax, 3
```

State transition:

```text
before          after mov       after add
eax = unknown → eax = 5       → eax = 8
```

---

## 2. Instructions, directives, labels, and bytes

Assembly listings can contain four different kinds of items:

| Kind | Example | Meaning |
|---|---|---|
| Instruction | `mov eax, 0` | Operation executed by the CPU |
| Directive | `.section .text` | Instruction to the assembler |
| Label | `main:` | Symbolic name for an address |
| Comment | `# initialize result` | Human annotation |

Directives and labels help construct an object file, but the CPU does not execute them.

Machine instructions are encoded as bytes. x86 instructions are variable length—between 1 and 15 bytes—and may contain:

```text
prefixes | opcode | ModR/M | SIB | displacement | immediate
```

Not every instruction contains every field. This variable-length encoding is one reason disassembly can become desynchronized when decoding starts at the wrong byte.

---

## 3. Intel syntax

These notes use Intel syntax:

```asm
mov destination, source
sub rsp, 0x20
```

AT&T syntax reverses the operands and decorates registers and constants:

```asm
mov $0x6, %edi       # AT&T
mov edi, 0x6         # Intel
```

When reading an unfamiliar listing, verify the syntax before interpreting data flow.

### Operand categories

An instruction can operate on:

- a **register**: `rax`;
- an **immediate constant**: `0x20`;
- a **memory location**: `[rbp-8]`.

Examples:

```asm
mov rax, rbx          ; register → register
mov eax, 42           ; immediate → register
mov eax, [rbp-4]      ; memory → register
mov [rbp-4], eax      ; register → memory
```

Normal x86 instructions generally do not allow both explicit operands to be arbitrary memory locations. A value is commonly loaded into a register first.

---

## 4. Registers and subregisters

### General-purpose registers

| 64-bit | Low 32 bits | Low 16 bits | Low 8 bits |
|---|---|---|---|
| `rax` | `eax` | `ax` | `al` |
| `rbx` | `ebx` | `bx` | `bl` |
| `rcx` | `ecx` | `cx` | `cl` |
| `rdx` | `edx` | `dx` | `dl` |
| `rsi` | `esi` | `si` | `sil` |
| `rdi` | `edi` | `di` | `dil` |
| `rbp` | `ebp` | `bp` | `bpl` |
| `rsp` | `esp` | `sp` | `spl` |
| `r8`–`r15` | `r8d`–`r15d` | `r8w`–`r15w` | `r8b`–`r15b` |

Important rule:

```asm
mov eax, 1
```

Writing a 32-bit general-purpose register clears the upper 32 bits of its 64-bit parent:

```text
rax = 0x????????????????  →  rax = 0x0000000000000001
```

Writing `ax`, `al`, or another 8/16-bit subregister does **not** clear all remaining parent bits.

### Special registers

- `rip` — address of the next instruction;
- `rsp` — current top of the stack;
- `rbp` — often a frame pointer, though optimized code may use it as a general register;
- `rflags` — status and control flags.

Register names suggest historical roles, not guaranteed current meaning. For example, `rcx` is traditionally a count register, but compiled code can use it for many purposes.

---

## 5. Sizes and extension

Common size names:

| Name | Bits | Bytes |
|---|---:|---:|
| byte | 8 | 1 |
| word | 16 | 2 |
| doubleword / `DWORD` | 32 | 4 |
| quadword / `QWORD` | 64 | 8 |

Memory operands may need an explicit size:

```asm
mov BYTE PTR [rbp-1], 0
mov DWORD PTR [rbp-8], 7
mov QWORD PTR [rbp-16], rax
```

### Zero and sign extension

```asm
movzx eax, BYTE PTR [rdi]   ; unsigned byte → zero-extended 32-bit value
movsx eax, BYTE PTR [rdi]   ; signed byte → sign-extended 32-bit value
movsxd rax, eax             ; signed 32-bit → signed 64-bit
```

This often reveals signedness. However, infer types from a pattern of evidence rather than a single instruction.

---

## 6. Memory addressing

The general x86 memory-address form is:

```text
[base + index × scale + displacement]
```

where `scale` is 1, 2, 4, or 8.

Examples:

```asm
mov eax, [rbp-4]              ; local stack slot
mov rax, [rdi]                ; dereference pointer in rdi
mov eax, [rdi+rcx*4]          ; int_array[rcx]
mov rax, [rbx+rsi*8+0x10]     ; base + indexed field
lea rax, [rip+0x2f31]         ; address relative to next instruction
```

Square brackets mean memory access:

```asm
mov rax, rbx      ; copy the value in rbx
mov rax, [rbx]    ; load 8 bytes from memory at address rbx
```

Confusing these produces completely wrong analysis.

### RIP-relative addressing

Position-independent x86-64 code commonly refers to globals and constants relative to `rip`:

```asm
lea rdi, [rip+0xe9d]
```

The effective address is calculated relative to the address of the following instruction. Disassemblers often annotate the final target.

### `lea` is arithmetic, not dereferencing

`lea` means “load effective address”:

```asm
lea rax, [rdi+rdi*4]   ; rax = rdi * 5
```

No memory is read here. Compilers frequently use `lea` as a fast arithmetic instruction.

---

## 7. Endianness

x86 is little-endian: the least significant byte of a multibyte value is stored at the lowest address.

Value:

```text
0x12345678
```

Memory:

```text
address +0  +1  +2  +3
byte     78  56  34  12
```

Endianness changes byte order in memory, not the conventional way the numerical value is written in a register.

---

## 8. Arithmetic and bitwise operations

Common instructions:

```asm
add rax, rbx
sub rsp, 0x20
inc ecx
dec edx
imul eax, edi, 10
and eax, 0xff
or eax, 1
xor edx, edx
shl eax, 2
shr eax, 1
sar eax, 1
```

### Common idioms

```asm
xor eax, eax       ; eax = 0
and eax, 0xff      ; retain low byte
shl eax, 3         ; multiply unsigned bit pattern by 8
shr eax, 1         ; logical right shift, inserts zero
sar eax, 1         ; arithmetic right shift, preserves sign
```

Do not automatically translate every shift into multiplication or division. Overflow, signedness, and rounding can make the exact semantics different.

### Multiplication and division

Some forms use implicit registers. For example, unsigned `div rbx` divides the combined value in `rdx:rax` by `rbx`, producing:

```text
quotient  → rax
remainder → rdx
```

`idiv` is signed. Before division, look for instructions that prepare the high half, such as `xor edx, edx` or `cqo`.

---

## 9. Flags, comparisons, and branches

Arithmetic instructions update flags. Particularly useful flags include:

| Flag | Meaning |
|---|---|
| `ZF` | Result was zero |
| `SF` | Sign bit of result |
| `CF` | Unsigned carry or borrow |
| `OF` | Signed overflow |

`cmp a, b` computes `a - b` for flags but discards the result:

```asm
cmp edi, 10
je equal_case
```

`test a, b` computes a bitwise AND for flags and discards the result:

```asm
test rax, rax
je is_zero
```

### Signed versus unsigned conditions

After `cmp a, b`:

| Meaning | Signed jump | Unsigned jump |
|---|---|---|
| equal | `je` / `jz` | `je` / `jz` |
| not equal | `jne` / `jnz` | `jne` / `jnz` |
| greater | `jg` | `ja` |
| greater or equal | `jge` | `jae` |
| less | `jl` | `jb` |
| less or equal | `jle` | `jbe` |

The machine does not store a permanent “signed integer” type in the register. The chosen conditional jump determines how the flags are interpreted.

### Branchless conditions

Optimized code may avoid branches:

```asm
cmp edi, esi
setg al              ; al = 1 if signed edi > esi, otherwise 0

cmp edi, esi
cmovg eax, edx       ; conditionally copy without branching
```

---

## 10. The stack

On x86-64, the stack normally grows toward lower addresses:

```asm
push rax     ; rsp -= 8; [rsp] = rax
pop rbx      ; rbx = [rsp]; rsp += 8
```

Conceptual layout inside a function:

```text
higher addresses
┌──────────────────────┐
│ caller's stack data  │
├──────────────────────┤
│ return address       │ ← placed by call
├──────────────────────┤
│ saved registers      │
├──────────────────────┤
│ local variables      │
├──────────────────────┤
│ outgoing call area   │
└──────────────────────┘ ← rsp
lower addresses
```

Exact layouts depend on the ABI, compiler, optimization, and function behavior.

### Traditional prologue and epilogue

```asm
push rbp
mov rbp, rsp
sub rsp, 0x20
...
leave
ret
```

`leave` behaves roughly like:

```asm
mov rsp, rbp
pop rbp
```

Optimized functions may omit the frame pointer, use no prologue, merge epilogues, or never touch the stack.

### The red zone

Under the System V AMD64 ABI, leaf functions may use 128 bytes below `rsp` without adjusting `rsp`. This area is the **red zone**. It is not part of the Windows x64 ABI.

---

## 11. Calls and returns

```asm
call target
```

performs two essential actions:

1. pushes the address of the next instruction;
2. transfers control to `target`.

```asm
ret
```

pops a return address into `rip`.

This is why corruption of stack return addresses can hijack control flow.

Calls may be:

```asm
call 0x401180       ; direct
call rax            ; indirect through register
call [rip+0x2f10]   ; indirect through memory
```

Indirect calls make static target recovery much harder.

---

## 12. System V AMD64 calling convention

On mainstream 64-bit Linux, the first integer or pointer arguments are normally passed in:

```text
1: rdi
2: rsi
3: rdx
4: rcx
5: r8
6: r9
remaining arguments: stack
return value: rax
```

Floating-point arguments use vector registers and follow additional rules.

### Register preservation

The caller may expect **callee-saved** registers to survive:

```text
rbx, rbp, r12, r13, r14, r15
```

Other general registers are normally caller-saved. A function that modifies a callee-saved register must restore it before returning.

### Stack alignment

The ABI requires appropriate stack alignment at call boundaries. Compiler-generated adjustments that appear unnecessary may exist solely to preserve alignment.

### Variadic calls

For System V variadic functions, `al` communicates the number of vector registers used for floating-point arguments. This explains patterns such as:

```asm
xor eax, eax
call printf@plt
```

The `xor eax, eax` may be ABI preparation, not application logic.

---

## 13. Recovering high-level constructs

### `if`

C:

```c
if (x == 5)
    result = 1;
else
    result = 0;
```

Possible assembly:

```asm
cmp edi, 5
jne .else
mov eax, 1
jmp .done
.else:
xor eax, eax
.done:
```

### Loop

C:

```c
for (int i = 0; i < n; i++)
    sum += a[i];
```

Possible shape:

```asm
xor eax, eax                ; i = 0
xor edx, edx                ; sum = 0
.loop:
cmp eax, esi
jge .done
add edx, DWORD PTR [rdi+rax*4]
inc eax
jmp .loop
.done:
mov eax, edx
ret
```

### Array indexing

```asm
mov eax, DWORD PTR [rdi+rcx*4]
```

Possible interpretation:

```c
eax = ((int *)rdi)[rcx];
```

This is a hypothesis based on element width and addressing—not proof of the original C type.

### Structure field

```asm
mov eax, DWORD PTR [rdi+0x18]
```

Possible interpretation: load a 4-byte field at offset `0x18` from an object pointed to by `rdi`.

Repeated accesses at consistent offsets help reconstruct a tentative structure.

---

## 14. Optimized-code realities

Optimization can:

- inline functions;
- eliminate variables and dead code;
- fold constants;
- combine loops;
- replace division with multiplication and shifts;
- reuse one register for unrelated values at different times;
- tail-call another function;
- split one source function into several regions;
- merge identical code from different functions.

Therefore:

> Never assume one source statement equals one assembly instruction, one variable equals one stack slot, or one source function equals one contiguous block.

### Tail calls

A function ending with:

```asm
jmp another_function
```

may represent a tail call. It reuses the current return address instead of creating another stack frame.

### Inlining

Absence of a `call` does not mean the source never called a helper. Its body may have been inlined.

---

## 15. Worked analysis

Consider:

```asm
check:
    test    rdi, rdi
    je      .invalid
    movzx   eax, BYTE PTR [rdi]
    cmp     al, 0x41
    sete    al
    movzx   eax, al
    ret
.invalid:
    xor     eax, eax
    ret
```

Step-by-step:

1. `rdi` is likely the first pointer argument.
2. `test rdi,rdi` checks whether it is null.
3. A null pointer returns zero through `eax`.
4. Otherwise, one byte is loaded from the pointed-to memory.
5. That byte is compared with `0x41`, ASCII `A`.
6. `sete al` produces 1 on equality and 0 otherwise.
7. `movzx eax,al` normalizes the full return register.

Plausible pseudocode:

```c
int check(const unsigned char *p) {
    if (p == NULL)
        return 0;
    return p[0] == 'A';
}
```

Confidence boundaries:

- High confidence: null check, one-byte load, equality with `0x41`, Boolean-like return.
- Medium confidence: `rdi` is intended as a pointer rather than merely containing an address-like value.
- Low confidence: original source type and function name.

---

## 16. Practical lab

Create:

```c
#include <stddef.h>

long sum_positive(const int *a, size_t n) {
    long total = 0;
    for (size_t i = 0; i < n; i++) {
        if (a[i] > 0)
            total += a[i];
    }
    return total;
}
```

Compile at different optimization levels:

```bash
gcc -O0 -g -c lab.c -o lab-O0.o
gcc -O2 -g -c lab.c -o lab-O2.o
objdump -drwC -M intel lab-O0.o
objdump -drwC -M intel lab-O2.o
```

For both versions, identify:

1. the two input arguments;
2. the return register;
3. array-element width;
4. loop header and back edge;
5. signed comparison used for `a[i] > 0`;
6. induction variable;
7. accumulator;
8. differences caused by optimization;
9. any instruction that accesses memory;
10. claims you cannot establish from assembly alone.

---

## 17. Common traps

- Treating `lea` as a memory read.
- Forgetting Intel operand order.
- Confusing an address with the value stored at that address.
- Assuming `rbp` always points to a stack frame.
- Reading `jg` and `ja` as equivalent.
- Ignoring implicit operands of `call`, `ret`, `push`, `pop`, `mul`, or `div`.
- Forgetting that writing `eax` clears the upper half of `rax`.
- Assuming a valid instruction sequence must be real code.
- Assigning source-level types with unjustified confidence.
- Mistaking ABI setup and runtime scaffolding for application logic.

---

## Mastery check

You are ready to proceed when you can:

1. trace register and flag state through a short instruction sequence;
2. calculate a scaled-index effective address;
3. distinguish value movement from address calculation;
4. identify arguments and return values under System V AMD64;
5. reconstruct an `if`, loop, array access, and function call;
6. explain signed versus unsigned conditional jumps;
7. recognize a stack frame without assuming every function has one;
8. state what evidence supports each recovered high-level claim.

