---
tags: [reverse-engineering, ia32, compilers, virtual-machines, chapter-notes]
chapter: 2
---

# Chapter 2 — Low-Level Software

> [!workthroughs] Complete tool-backed labs: [[Walkthroughs - Chapter 02 - Fifteen Complete Analyses]]

## Chapter overview

This chapter builds the translation bridge a reverser uses constantly: high-level program structure, variables, structures, lists, and control flow become registers, stacks, heaps, data sections, instructions, flags, and calls. It then explains compiler architecture, virtual-machine bytecode/JIT execution, and processor pipelines.

The chapter exists because an instruction listing is only useful when you can infer the higher-level construct that produced it. It connects Chapter 1’s method to Chapter 3’s Windows runtime model.

### Chapter roadmap

```text
High-level program
├── modules/functions and language constructs
├── variables, structures, lists
└── conditions, loops, calls
       ↓ compiler/runtime mapping
Low-level program
├── registers, stack, heap, data sections
├── instructions and flags
└── direct/indirect control flow
       ↓ execution environments
bytecode/interpreter/JIT or hardware pipeline
```

## High-level perspectives

### Program structure and modules

High-level programs divide responsibilities into modules, classes, and functions. Binaries may preserve module boundaries through separate images, symbols, imports, exception metadata, or address ranges—but optimization/link-time code generation can inline or merge across them.

**Function:** callable unit with an interface and behavior.

**In simple words:** code that receives state/arguments, performs operations, and returns/transfers.

**Example:** a parser function receives a byte buffer and length, returns status, and fills a structure.

### Common constructs

| High-level construct | Typical low-level evidence | Important variation |
|---|---|---|
| assignment | register/memory write | optimized away or combined |
| `if/else` | comparison + conditional edge | conditional move/set/boolean arithmetic |
| loop | backward edge + induction/state | unrolled/vectorized/rotated |
| switch | compare chain or jump table | sparse tree/hash-like dispatch |
| function call | call/indirect transfer + ABI | inline/tail call |
| object method | hidden `this` pointer + field offsets | devirtualized/inlined |

### Data management

#### Variables

A source variable is a named value/lifetime, not necessarily a permanent storage slot. It can occupy a register, stack slot, global address, heap field, or no storage after optimization.

#### User-defined structures

Structures appear as repeated accesses from one base pointer:

```asm
mov eax, [ecx+4]
mov edx, [ecx+8]
cmp byte ptr [ecx+0c], 0
```

This supports fields at offsets 4, 8, and 12. Exact types require access width, sign/zero extension, consumers, writers, and multiple call sites. Padding can create unused offsets.

#### Lists

A linked list appears as node-pointer traversal. A singly linked node might load `next` at a stable offset and loop until NULL. A doubly linked list adds backward link/invariants. Do not label a pointer “next” merely because it is dereferenced repeatedly; test traversal and allocation/lifetime.

### Control flow

High-level order becomes branches, calls, returns, exceptions, and indirect dispatch. Compilers invert conditions or move code to favor fall-through, so reconstruct semantic predicates rather than mimicking listing order.

### High-level languages

**C:** relatively direct procedures/pointers/structs, but optimization remains substantial.

**C++:** constructors/destructors, `this`, name mangling, vtables, exceptions, templates and inlining add patterns.

**Java/C#:** managed metadata, bytecode/IL, garbage collection, runtime checks and JIT offer a higher-level reversing layer.

## Low-level perspectives

### Registers

IA-32 general registers include `EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP`; `EIP` controls instruction fetch and `EFLAGS` stores condition/control flags. Historical compiler conventions give registers common roles, but instructions and ABI evidence—not names—determine meaning.

### Stack

The stack supports return addresses, arguments, saved registers, locals, temporaries, exception/runtime data, and alignment.

```text
higher addresses
arguments
return address       ← pushed by call
saved frame pointer
locals/temporaries   ← stack grows toward lower addresses on IA-32
lower addresses
```

Typical frame:

```asm
push ebp
mov  ebp, esp
sub  esp, 20h
...
mov  esp, ebp
pop  ebp
ret
```

Optimizers can omit `EBP`, reserve once for several calls, reuse slots, or inline the function. A frame pattern is a clue, not a definition.

### Calling conventions

On 32-bit Windows, common conventions historically include:

| Convention | Arguments | Cleanup | Common clue |
|---|---|---|---|
| `cdecl` | stack, right-to-left | caller | `add esp,N` after call |
| `stdcall` | stack | callee | `ret N` often |
| `thiscall` | `this` often `ECX`, others stack | varies/compiler | field accesses from `ECX` |
| `fastcall` | some register args | convention-specific | `ECX/EDX` inputs |

These are patterns, not universal guarantees. Infer from multiple callers/callee stack delta and compiler/platform.

### Heap

Heap allocations support dynamic objects and variable lifetimes. Reversers trace allocation size, constructor/initialization, aliases, mutation, ownership, and free. Security analysis depends on allocation generation: the same address reused later is a different object lifetime.

### Executable data sections

Globals, constants, strings, import tables, vtables, RTTI, and pointer arrays reside in image sections. Relocations and xrefs help distinguish pointer data from integers.

## Assembly language 101

### Flags

`cmp a,b` sets flags as if `a-b`; `test a,b` sets logic-result flags without saving result.

| Flag | Intuition |
|---|---|
| ZF | result zero/equal |
| CF | unsigned carry/borrow |
| SF | result sign bit |
| OF | signed overflow |

Signed comparison consumes SF/OF/ZF; unsigned consumes CF/ZF.

```asm
cmp eax, 10
jl  signed_less
jb  unsigned_below
```

The same `0xffffffff` is signed `-1` or unsigned `4294967295`; the branch determines interpretation.

### Instruction format and addressing

IA-32 is variable-length. Memory operand often follows:

```text
base + index*scale + displacement
```

`[eax+ecx*4+8]` can mean array of 4-byte elements at field/base offset 8. `lea` computes the expression without dereferencing and is also used for arithmetic.

### Basic instructions

```asm
mov eax, [ebp+8]        ; load argument
lea edx, [eax+eax*2]    ; 3*eax, no memory read
add eax, ecx
sub esp, 10h
and eax, 0ffh
shl eax, 2
cmp eax, 5
setne al
```

Track width: writing `AL` changes only 8 bits; writing `EAX` defines 32 bits. On IA-32 there is no automatic x86-64 upper-half rule to consider, but partial-register dependencies remain.

### Function calls

`call` pushes return address and transfers. `ret` pops a target; `ret N` also adjusts stack. Indirect calls through registers/memory commonly represent function pointers, imports, or virtual dispatch.

## Difficult passage — translating a loop

### What the book is teaching

Compiler-generated assembly can be understood by mapping registers/branches back to induction variables, termination, and body effects.

### Step-by-step example

```asm
xor ecx, ecx          ; i=0
xor eax, eax          ; total=0
loop_start:
cmp ecx, [ebp+0ch]    ; compare i with length
jae done              ; unsigned i >= length
mov edx, [ebp+8]      ; buffer pointer
movzx edx, byte ptr [edx+ecx]
add eax, edx
inc ecx
jmp loop_start
done:
ret
```

1. `ECX` starts at 0 and increments: induction variable.
2. `jae` makes the bound unsigned.
3. `[buffer+ecx]` loads one byte and zero-extends it.
4. `EAX` accumulates and is conventional return value.

Equivalent model:

```c
unsigned sum(const unsigned char *buf, unsigned len) {
    unsigned total=0;
    for (unsigned i=0; i<len; ++i) total += buf[i];
    return total;
}
```

### Another example

If `movsx` replaces `movzx`, bytes contribute signed values. Same loop shape, different data semantics.

### Common misunderstanding

The source might not have used a `for` loop or these names. The recovered model is equivalent semantics.

## A primer on compilers and compilation

### Compiler architecture

```text
source
 → front end: lex/parse/type/language semantics
 → intermediate representation
 → optimizer: equivalence-preserving transformations
 → backend: instruction selection, allocation, scheduling
 → assembly/object
```

**IR:** compiler-internal language easier to analyze/transform than source or raw target code.

**Optimizer:** removes/rearranges/composes operations while preserving defined observable behavior under language assumptions.

**Backend:** maps IR to ISA/ABI instructions and registers.

### Listing files

Compiler listings can connect source and generated instructions for learning, but optimized mappings are many-to-many. Build tiny examples with several compilers/settings to learn families rather than signatures.

## Execution environments

### Bytecodes, interpreters, JIT

An interpreter reads bytecode and performs operations. A JIT translates hot bytecode to native code. Reversing can target:

1. metadata and bytecode for higher-level semantics;
2. runtime/interpreter for dynamic behavior;
3. JIT native output for final machine behavior.

### Hardware execution

The book discusses NetBurst-era micro-ops, pipelines, and branch prediction. Modern details differ, but distinction remains:

- **architectural state:** programmer-visible semantics reversers rely on;
- **microarchitecture:** internal execution, timing, caches, prediction.

Instructions can decode into micro-ops and overlap in a pipeline. Misprediction affects performance/timing, not architectural result after retirement. Side channels are a special case requiring microarchitectural analysis.

## Common mistakes

**Mistake:** naming stack slots as original variables. **Correct:** compiler can reuse/merge storage; name by observed role/confidence.

**Mistake:** treating `jl` and `jb` as interchangeable. **Correct:** signed and unsigned flags differ at edge values.

**Mistake:** assuming every `call` is a source function call. **Correct:** thunks, runtime helpers, tail calls, and indirect dispatch complicate structure.

**Mistake:** applying 32-bit calling rules to x86-64 or managed IL. **Correct:** identify architecture/ABI first.

## Chapter synthesis

### Chapter in one view

```text
high-level meaning
 → compiler/runtime transformations
 → low-level storage + instructions + control
 → architectural execution
 → reverse constraints from uses, widths, flags, ABI, and invariants
```

### Key definitions

register, stack frame, heap object, calling convention, flag, instruction operand, IR, optimizer, backend, bytecode, interpreter, JIT, micro-op, pipeline.

### Key processes

- Type inference: widths/extensions/branches/consumers → constrained type.
- Loop recovery: initialization → condition → body → update → invariant.
- Call recovery: arguments → target → side effects → cleanup → return.

### What you should be able to explain

- [ ] Map source constructs to several possible compiler patterns.
- [ ] Explain stack/heap/global/register lifetimes.
- [ ] Read IA-32 operands, flags, branches, and calls.
- [ ] Explain compiler stages and managed/native execution layers.

### What you should be able to solve

- [ ] Recover conditions, loops, switches, structures, lists, and callbacks.
- [ ] Infer calling convention from several sites.
- [ ] Distinguish signed/unsigned and sign/zero extension.
- [ ] Critique exact-source claims after optimization.

Practice and solutions: [[Reversing - Complete Practice Workbooks#Chapter 2 — Low-Level Software]].

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs I - Foundations Through Tools]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
