# Chapter 13 — Decompilation


## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs III - Protections Managed Code and Decompilation]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
> [!source]
> **From the book:** limits of native decompilation, intermediate representations, front-end decoding, data-flow/SSA/type/control-flow analysis, library recognition, and back-end generation.
> **Added mentor material:** paired C/assembly examples, IR transformations, equations, and a build-your-own decompiler pipeline.

## Chapter Overview

A native decompiler cannot recover the exact original program because compilation discards information and many source programs map to the same machine code. It can recover a useful, semantically equivalent high-level representation by repeatedly transforming low-level facts into stronger abstractions.

```text
machine bytes
  ↓ decode and lift
instructions + explicit effects
  ↓ CFG
basic blocks and edges
  ↓ data flow / SSA / propagation
expressions, variables, types
  ↓ structural analysis
loops, conditionals, calls
  ↓ back end
readable pseudocode
```

## 13.1 Why Exact Native Decompilation Is Unsolvable

Compilation commonly removes:

- variable and function names;
- comments and source formatting;
- original loop syntax;
- typedefs and many type distinctions;
- inlined function boundaries;
- macros and templates;
- dead source code;
- distinctions optimized into identical instructions.

### Many-to-one example

All of these may compile to the same optimized behavior:

```c
return x * 2;
return x + x;
return x << 1;  // for the relevant unsigned semantics
```

Possible x86-64:

```asm
lea eax, [rdi+rdi]
ret
```

The decompiler can state `return x * 2` or `x + x`, but cannot know which syntax the author wrote. The correct objective is semantic equivalence under defined machine behavior.

## 13.2 Typical Decompiler Architecture

| Stage | Input | Output | Main failure risk |
|---|---|---|---|
| loader | executable | sections, symbols, relocations | wrong image mapping |
| decoder | bytes | instructions | code/data ambiguity |
| lifter | instructions | IR effects | incomplete flag/exception model |
| CFG builder | targets | blocks/edges | indirect control flow |
| analyzer | IR + CFG | variables/types/structures | unsafe assumptions |
| back end | structured IR | pseudocode | misleading prettification |

Keep uncertainty. A guessed indirect target or type should be annotated, not silently promoted to fact.

## 13.3 Intermediate Representations

An IR makes implicit machine effects explicit and provides a smaller language for analysis.

### Paired example: assembly to three-address IR

```c
int f(int a, int b) {
    return (a + 5) * (b - 2);
}
```

```asm
; SysV x86-64: a in EDI, b in ESI
lea eax, [rdi+5]
sub esi, 2
imul eax, esi
ret
```

Lifted IR:

```text
t0:i32 = arg0
t1:i32 = arg1
t2:i32 = t0 + 5
t3:i32 = t1 - 2
t4:i32 = t2 * t3
return t4
```

The IR discards encoding noise while preserving width and operations.

### Expressions and expression trees

```text
        multiply
       /        \
     add       subtract
    /   \      /    \
   a     5    b      2
```

Expression folding must respect integer width, signedness, overflow, division rules, and side effects. Do not reorder volatile loads or calls as if they were pure arithmetic.

## 13.4 Control-Flow Graphs

A basic block is a maximal straight-line instruction sequence with one entry and one terminating control transfer. A CFG connects blocks with possible transfers.

### Paired example

```c
int absdiff(int a, int b) {
    if (a >= b) return a - b;
    return b - a;
}
```

```asm
cmp edi, esi
jl  LESS
mov eax, edi
sub eax, esi
ret
LESS:
mov eax, esi
sub eax, edi
ret
```

CFG:

```text
       [cmp a,b]
       /       \
   a>=b         a<b
    ↓            ↓
[return a-b] [return b-a]
```

### Leaders and blocks

A standard algorithm marks as leaders:

1. entry point;
2. every direct branch target;
3. instruction after a conditional branch/call when appropriate;
4. known exception/indirect targets.

Split at leaders, terminate blocks at branches/returns, then add edges. Indirect jumps require separate target recovery.

## 13.5 Front End and Semantic Analysis

The front end must decode instructions and model effects, including flags.

### Paired flags example

```asm
cmp eax, ebx
jb  unsigned_below
jl  signed_less
```

`CMP` computes subtraction flags without storing the result. `JB` uses carry for unsigned ordering; `JL` uses sign/overflow relation for signed ordering. A lifter that emits only `eax-ebx` but loses flag semantics cannot reconstruct correct conditions.

Conceptual IR:

```text
flags = sub_flags32(eax, ebx)
if flags.CF == 1 goto unsigned_below
if flags.SF != flags.OF goto signed_less
```

### Memory semantics

Model effective addresses:

```asm
mov eax, [rdi + rcx*4 + 8]
```

```text
addr = rdi + rcx*4 + 8
eax = load32(addr)
```

Possible interpretation is `base[index + 2]` for four-byte elements, but only type/use evidence justifies it.

## 13.6 Data-Flow Analysis

Data-flow frameworks compute facts reaching or leaving blocks until a fixed point.

### Reaching definitions

Which assignments may define a value at a use?

```c
if (flag) x = 10;
else      x = 20;
return x + 1;
```

At the return, both definitions reach the use. A decompiler must merge them rather than choose one trace.

### Liveness

A variable is live if its current value may be read before being overwritten. Liveness helps identify register reuse: the same hardware register can represent different logical variables in non-overlapping live ranges.

## 13.7 Single Static Assignment

SSA gives each logical definition a unique version. Merge points use φ functions.

### Paired example

```asm
test edi, edi
jz ZERO
mov eax, 10
jmp JOIN
ZERO:
mov eax, 20
JOIN:
add eax, 1
ret
```

SSA:

```text
if arg0 == 0 goto ZERO else NONZERO
NONZERO: eax_1 = 10; goto JOIN
ZERO:    eax_2 = 20; goto JOIN
JOIN:    eax_3 = phi(eax_1, eax_2)
         eax_4 = eax_3 + 1
         return eax_4
```

The φ is not executable code. It means the selected value depends on the incoming CFG edge.

### Why SSA helps

- constant propagation;
- dead-definition removal;
- use-def chains;
- expression recovery;
- type propagation;
- separating reused registers.

## 13.8 Data Propagation and Simplification

### Copy propagation

```text
t0 = a
t1 = t0
t2 = t1 + 4
```

becomes `t2 = a + 4` if aliases and side effects permit.

### Constant propagation

```text
x = 3
y = x * 8
```

becomes `y = 24`.

### Dead-code elimination

Remove a definition only if it has no live use and no side effects. A load from volatile/device memory, function call, faulting access, or atomic operation cannot be discarded merely because its return value is unused.

### Worked assembly example

```asm
mov eax, 7
mov ecx, eax
shl ecx, 2
add ecx, 1
mov eax, ecx
ret
```

IR simplifies:

```text
eax_1 = 7
ecx_1 = eax_1
ecx_2 = ecx_1 << 2
ecx_3 = ecx_2 + 1
eax_2 = ecx_3
return eax_2
```

to `return 29`, assuming exact 32-bit operations and no observable flags afterward.

## 13.9 Register Variable Identification

Registers are storage locations, not source variables. A compiler reuses them and splits one source variable across registers/stack.

### Example

```asm
mov eax, edi      ; eax holds input-derived t0
add eax, 5
mov [rsp+4], eax  ; spill
call g
mov ecx, [rsp+4]  ; reload same logical value
add eax, ecx      ; EAX now call result, distinct variable
```

Liveness and def-use chains show:

- pre-call `EAX` and stack slot may be one logical variable;
- post-call `EAX` is the return value of `g`;
- hardware-name continuity does not imply source-variable continuity.

## 13.10 Type Analysis

### Primitive types

Evidence sources include operation width, signed/unsigned branches, extensions, floating-point instructions, API signatures, and constants.

```asm
movzx eax, byte [rdi]   ; unsigned byte candidate
movsx ecx, byte [rsi]   ; signed byte candidate
```

These express different ranges: `0..255` versus `-128..127`.

### Pointer-versus-integer evidence

A value used as a memory base, passed to an API expecting a pointer, compared with null, or advanced by structure-like offsets is likely pointer-typed. One address-like value is insufficient because integers can be used as addresses and vice versa.

### Complex data types

Repeated offsets across functions suggest structures:

```asm
mov eax, [rdi+0]    ; candidate id
mov rcx, [rdi+8]    ; candidate pointer
cmp word [rdi+16], 0
```

Tentative model:

```c
struct Candidate {
    uint32_t id;       // offset 0
    /* padding */
    void *ptr;         // offset 8
    uint16_t flag;     // offset 16
};
```

Validate size/alignment, allocation size, arrays/strides, constructors, and all cross-function uses before finalizing.

## 13.11 Control-Flow Analysis

### Loop recognition

A back edge to a dominating header suggests a natural loop. Recover:

- initialization before header;
- condition;
- body;
- update;
- exits and `break/continue` edges.

### Irreducible flow

Multiple entries into a cyclic region may not map cleanly to `while/for`. A decompiler may emit labels/gotos or duplicate blocks. Readability must not override correctness.

### Switch recovery

Typical native switch:

```asm
cmp edi, 3
ja  DEFAULT
jmp qword [table + rdi*8]
```

The range check bounds the index; the table supplies targets. Recover default edge, case-to-target mapping, duplicate targets, and whether the index was normalized with subtraction first.

## 13.12 Finding Library Functions

Recognizing statically linked library/runtime functions removes noise and supplies known signatures.

Evidence includes:

- byte/signature matching with relocation normalization;
- constants and characteristic CFG;
- call-site behavior;
- imported callees;
- known compiler/runtime version;
- semantic hashing.

Optimizations and compiler versions change bytes. A match should have multiple supporting features, not one magic constant.

## 13.13 Back End

The back end chooses expressions, variables, types, and structured syntax.

### Same CFG, multiple valid outputs

```c
if (x) y = 1; else y = 2;
```

or:

```c
y = x ? 1 : 2;
```

Both can represent the same IR. Back-end prettiness is secondary to preserving widths, aliasing, evaluation order, exceptions, and side effects.

## 13.14 Real-World IA-32 Decompilation

IA-32 complicates recovery through variable-length instructions, limited registers, stack arguments, flags, x87 stack state, calling-convention variation, and indirect control flow.

### Paired calling-convention example

```c
int add(int a, int b) { return a + b; }
```

One 32-bit cdecl form:

```asm
push ebp
mov  ebp, esp
mov  eax, [ebp+8]
add  eax, [ebp+12]
pop  ebp
ret
```

Caller:

```asm
push 2
push 1
call add
add  esp, 8
```

Caller cleanup suggests cdecl. With `ret 8`, callee cleanup suggests stdcall. Optimization can omit the frame pointer, so infer convention from multiple call sites and stack balance.

### x87 expression recovery

```asm
fld  dword [a]     ; [a]
fld  dword [b]     ; [b,a]
faddp st1, st0     ; [a+b]
fld  dword [c]     ; [c,a+b]
fmulp st1, st0     ; [(a+b)*c]
fstp dword [out]   ; []
```

Paired C:

```c
out = (a + b) * c;
```

Write the x87 stack after every instruction; one mistaken pop reverses the formula.

## 13.15 Build Your Own Static Decompiler: Step by Step

This complements [[../practical-binary-analysis/Build Guide - Static Disassembler|Build Guide - Static Disassembler]].

### Milestone 1: loader

Parse one format/architecture. Map RVA/file offsets, executable sections, entry point, imports, exports, relocations, and symbols.

### Milestone 2: decoder

Decode bytes into instruction objects:

```text
address, length, opcode, operands, read-set, write-set, branch-kind, targets
```

Test malformed/truncated instructions and never read beyond section bounds.

### Milestone 3: recursive code discovery

Use a worklist from entry/export/function seeds. Decode until terminator, enqueue direct targets, record unresolved indirect edges, and keep code/data/unknown states separate.

### Milestone 4: lift to IR

Implement exact semantics for a small instruction subset first: moves, arithmetic, compare/flags, conditional branches, calls, returns, and memory addressing.

### Milestone 5: CFG

Split blocks at leaders, add edges, compute predecessors/successors, dominators, back edges, and reachability.

### Milestone 6: SSA and data flow

Compute def/use, liveness, SSA versions/φ nodes, constant/copy propagation, and dead-definition removal.

### Milestone 7: types and calling conventions

Seed known imports, infer argument locations, return values, signedness, pointer use, structures, and arrays. Carry confidence on inferred types.

### Milestone 8: structural recovery and backend

Recognize if/else, loops, and switches. Emit goto-based output when structure is uncertain rather than inventing a false loop.

### Verification

For each test function:

1. compile known C at `-O0`, `-O2`, and different compilers;
2. compare CFG against a trusted tool;
3. execute original and lifted IR on test vectors;
4. compare returns, memory writes, flags when relevant, and exceptions;
5. fuzz decoder and lifter boundaries.

## 13.16 Dynamic Decompiler/Disassembler Connection

A dynamic engine observes actual instructions and targets, solving some static ambiguity but covering only executed paths. Combine them:

```text
static CFG hypotheses
   + runtime executed blocks/indirect targets
   + memory snapshots after unpacking
   = refined but still coverage-bounded model
```

The detailed implementation path is in [[../practical-binary-analysis/Build Guide - Dynamic Disassembler|Build Guide - Dynamic Disassembler]].

## Common Mistakes

**Mistake:** claiming original source recovery.
**Correction:** claim semantic reconstruction with uncertainty.

**Mistake:** losing flags, width, or side effects in IR.
**Correction:** model exact machine semantics before simplifying.

**Mistake:** treating registers as variables.
**Correction:** use definitions, uses, liveness, and SSA.

**Mistake:** inventing types from one load.
**Correction:** combine operations, APIs, offsets, allocation, and callers.

**Mistake:** making the back end prettier than the evidence.
**Correction:** preserve gotos/unknown types where proof is incomplete.

## Chapter in One View

```text
bytes → instructions → IR → CFG → SSA/data flow
                         ↓
                    types + variables
                         ↓
                  structured pseudocode
                         ↓
              differential semantic tests
```

## Mastery Checklist

- [ ] Explain why exact source recovery is impossible.
- [ ] Lift assembly into width-aware three-address IR.
- [ ] Build basic blocks and a CFG.
- [ ] Convert a merge to SSA with φ nodes.
- [ ] Perform constant/copy propagation safely.
- [ ] Separate logical variables from reused registers.
- [ ] Infer primitive and structure types with evidence.
- [ ] Recover loops and jump tables.
- [ ] Validate lifted semantics against execution.

## Practice Questions and Solutions

1. **Why can three source expressions compile to one instruction?** Optimization preserves relevant semantics, not source spelling; multiple equivalent expressions collapse to the same machine operation.
2. **What must an IR preserve?** Widths, signedness where operations depend on it, flags, memory/alias effects, calls, exceptions, and control flow.
3. **What is a φ node?** A merge-time selection of the SSA value corresponding to the predecessor edge; it is an analysis construct.
4. **Why is unused-load elimination risky?** Volatile/device/atomic loads or faulting accesses have observable side effects.
5. **How do you infer a switch table?** Range check, normalized index, scaled table access, indirect jump, and valid target entries.
6. **What separates two variables reusing EAX?** A new definition whose old value is dead, often across a call or distinct live range.
7. **When should a decompiler emit goto?** When flow is irreducible or structured recovery is uncertain; correctness beats fabricated structure.
8. **How is a lifter tested?** Differentially execute original and IR on many inputs and compare all relevant observable state.

---

Previous: [[Chapter 12 - Reversing .NET]]
Next: [[Appendices - Code Structures, Arithmetic, and Program Data]]
