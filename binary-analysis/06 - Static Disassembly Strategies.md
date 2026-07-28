# Static Disassembly Strategies

## Purpose

Static disassembly extracts instructions without executing the binary. Its difficult step is not converting a known instruction's bytes into text. The hard problem is deciding:

> Which bytes are instructions, where does each instruction begin, and which code is reachable?

This note develops a rigorous model of linear sweep, recursive traversal, their failure modes, and the hybrid techniques used in practical analysis.

---

## 1. The disassembly pipeline

A static disassembler broadly performs:

```text
Load executable format
        ↓
Identify candidate code regions and entry points
        ↓
Choose instruction boundaries
        ↓
Decode bytes into instructions
        ↓
Recover control-flow relationships
        ↓
Group instructions into basic blocks and functions
        ↓
Annotate symbols, relocations, and data references
```

Each layer depends on assumptions made by earlier layers. A wrong instruction boundary can corrupt control-flow recovery and every higher-level analysis built on it.

---

## 2. Why x86 is difficult to disassemble

x86 has:

- variable-length instructions from 1 to 15 bytes;
- no architectural requirement that instructions begin at aligned addresses;
- a dense encoding in which many byte sequences decode successfully;
- prefixes that alter instruction interpretation;
- possible overlapping instruction streams;
- indirect branches whose targets are computed at runtime.

The same bytes can decode differently depending on the starting offset:

```text
bytes: 48 89 e5 48 83 ec 10

correct start:
48 89 e5          mov rbp, rsp
48 83 ec 10       sub rsp, 0x10

start one byte late:
89 e5             mov ebp, esp
48 83 ec 10       sub rsp, 0x10
```

Both sequences contain valid instructions. Successful decoding is therefore not sufficient proof of a correct boundary.

---

## 3. Linear-sweep disassembly

### Algorithm

Linear sweep starts at the beginning of a candidate code region and repeatedly decodes the next instruction:

```text
address = start
while address < end:
    instruction = decode(bytes at address)
    emit instruction
    address += instruction.length
```

`objdump` traditionally behaves broadly like a linear disassembler over expected code sections.

### Strengths

- simple and fast;
- high byte coverage;
- discovers code that has no known incoming control-flow edge;
- works reasonably well on conventional compiler-produced x86 ELF files whose code sections do not contain inline data.

### Core weakness

Linear sweep treats every byte in the selected region as part of an instruction stream. Inline data can be decoded as bogus instructions.

Examples of data found near or inside code include:

- jump tables;
- literal pools on some architectures;
- alignment padding;
- exception metadata or embedded constants;
- deliberately inserted anti-disassembly bytes.

### Desynchronization

If inline data decodes into an instruction that extends into real code, subsequent decoding begins at the wrong boundary:

```text
true layout:
[4 bytes data] [push rbp] [mov rbp,rsp] [sub rsp,0x10]

linear interpretation:
[bogus instruction consuming data + push bytes]
                          ↓
                 true prologue partly lost
```

x86 streams often resynchronize eventually, but even a few missed instructions can invalidate function analysis or binary rewriting.

### Invalid-opcode recovery

A linear disassembler must choose a policy when decoding fails:

- stop the region;
- skip one byte and retry;
- mark bytes as data;
- search for a plausible boundary.

Each policy can create false negatives or false positives.

---

## 4. Recursive-traversal disassembly

Recursive traversal is control-flow aware. It begins from known entry points and follows discovered edges.

### Candidate entry points

- ELF entry point;
- exported or known function symbols;
- relocation targets;
- initialization and termination arrays;
- exception/unwind metadata;
- targets referenced by discovered direct calls;
- manually supplied analyst hints.

### Worklist algorithm

```text
worklist = known entry points
visited = {}

while worklist is not empty:
    address = remove one target
    if address already visited:
        continue

    decode sequentially into a basic block
    stop when reaching:
      - conditional branch
      - unconditional jump
      - return
      - indirect control transfer
      - invalid instruction
      - known block boundary

    add statically known successors to worklist
```

### Successor rules

For a normal instruction:

```text
successor = next instruction
```

For a conditional branch:

```text
successors = branch target + fall-through
```

For an unconditional direct jump:

```text
successor = jump target
```

For a direct call:

```text
function candidate = call target
continuation candidate = instruction after call
```

For `ret`:

```text
no intraprocedural successor
```

For indirect jumps and calls:

```text
targets = unresolved unless additional analysis succeeds
```

### Strengths

- naturally avoids most inline data;
- recovers reachable control flow;
- produces basic blocks and graph structure during discovery;
- better suited to interactive reverse engineering.

### Core weakness

It can only follow edges it knows how to resolve. Unreferenced functions and unresolved indirect targets may be missed entirely.

---

## 5. The coverage-versus-precision tradeoff

| Strategy | Typical advantage | Typical failure |
|---|---|---|
| Linear sweep | High byte coverage | Data misclassified as code |
| Recursive traversal | Higher confidence in reachable code | Real code missed due to unknown entry points or edges |

These correspond to two error types:

- **false positive:** data presented as an instruction;
- **false negative:** real instruction not discovered.

There is no perfect general-purpose static solution because deciding all possible runtime targets can require solving program behavior.

---

## 6. Basic blocks and control-flow graphs

A **basic block** is a sequence with:

- one entry at the first instruction;
- no internal branch targets;
- control leaving only at the end.

Example:

```asm
401100: test edi, edi
401102: je   401110
```

This block has two successors:

```text
              ┌── zero ───→ 0x401110
0x401100 ─────┤
              └── nonzero → fall-through
```

A **control-flow graph (CFG)** represents basic blocks as nodes and possible transfers as directed edges.

### Block leaders

Common leaders include:

- function entries;
- direct branch targets;
- fall-through addresses after conditional branches;
- instructions following calls when the call can return;
- targets recovered from jump tables.

### Why CFG correctness matters

Higher-level analyses rely on it:

- loop discovery;
- dominance;
- reachability;
- data-flow analysis;
- taint propagation;
- symbolic execution;
- instrumentation placement.

An omitted edge can make reachable code appear dead. A spurious edge can create impossible paths and false results.

---

## 7. Indirect control flow

Examples:

```asm
jmp rax
call [rbx+0x18]
jmp [rip+table+rax*8]
```

The target depends on runtime state or memory.

Possible origins include:

- function pointers;
- C++ virtual dispatch;
- callbacks;
- return instructions;
- jump tables implementing `switch`;
- dynamic linking stubs;
- obfuscation.

### Resolution techniques

1. **Constant propagation**
   - Track whether the target register becomes a known constant.

2. **Value-set analysis**
   - Approximate the possible target values.

3. **Relocation and symbol information**
   - Use loader metadata to identify function-pointer locations.

4. **Jump-table recognition**
   - Detect bounds checks, indexed table loads, and table contents.

5. **Type or class recovery**
   - Infer virtual tables and possible object types.

6. **Dynamic traces**
   - Observe actual targets for particular executions.

7. **Analyst feedback**
   - Mark targets or repair incorrectly classified regions.

All are approximations or incomplete observations.

---

## 8. Jump tables

A compiler may translate:

```c
switch (x) {
    case 0: ...
    case 1: ...
    case 2: ...
}
```

into a shape such as:

```asm
cmp eax, 2
ja  .default
lea rdx, [rip+.jump_table]
movsxd rax, DWORD PTR [rdx+rax*4]
add rax, rdx
jmp rax
```

Reasoning:

1. `cmp` and `ja` establish a bounded unsigned index.
2. `rdx` points to a table.
3. A signed 32-bit table entry is selected using `index × 4`.
4. The entry is interpreted as an offset from the table base.
5. The indirect jump reaches the selected case.

A recursive disassembler that does not recognize this pattern stops at `jmp rax` and misses the cases.

---

## 9. Function discovery

Function boundaries are not an architectural property. `call` and `ret` manipulate control flow, but the CPU does not enforce compiler-style functions.

Evidence for function starts includes:

- direct call targets;
- symbols;
- exported entries;
- unwind metadata;
- address-taken code referenced by relocations;
- common prologue patterns;
- gaps following known functions;
- initialization arrays.

### Why prologue matching is insufficient

Classic:

```asm
push rbp
mov rbp, rsp
```

But functions can:

- omit frame pointers;
- begin with security or instrumentation instructions;
- be leaf functions with no stack frame;
- share tails;
- be split into hot and cold regions;
- be entered at multiple offsets;
- use hand-written or obfuscated layouts.

Prologue matching is a heuristic, not proof.

### Function overlap

Two logical functions may share instruction ranges through tail merging. Malicious binaries can also intentionally create overlapping instruction streams. A simplistic “every byte belongs to exactly one function” model can fail.

---

## 10. Code versus data classification

Useful evidence that bytes are code:

- reachable from a trusted entry through resolved control flow;
- targeted by a relocation or code pointer;
- covered by unwind metadata;
- dynamically executed;
- consistent with surrounding compiler patterns.

Useful evidence that bytes are data:

- referenced as an address by loads;
- belong to a known non-executable section;
- form a plausible table or string;
- cannot be entered through any supported control-flow evidence.

None is universally decisive. Self-modifying code, runtime unpacking, JIT compilation, unusual linkers, and obfuscation violate ordinary assumptions.

### Confidence labels

Use explicit confidence:

```text
Confirmed executed code
High-confidence reachable code
Heuristically discovered code
Ambiguous bytes
Likely data
```

This is more honest and useful than forcing an immediate binary classification.

---

## 11. Anti-disassembly patterns

Malicious or protected software may exploit disassembler assumptions.

### Jump over junk

```asm
jmp .real
db 0xe8              ; misleading byte
.real:
...
```

Recursive traversal follows the jump and avoids junk; linear sweep may decode it.

### Branch with constant outcome

```asm
xor eax, eax
test eax, eax
jz .real
; misleading path
```

Both CFG edges appear syntactically possible, but data-flow reasoning shows only one is feasible.

### Call/pop position discovery

```asm
call .next
.next:
pop rbx
```

This obtains the current address and may confuse simplistic call semantics.

### Overlapping instructions

A jump can target the middle of another decoded instruction. x86 permits execution from that byte, creating multiple valid streams over the same bytes.

### Return misuse

Code can push a chosen address and execute `ret` as an indirect jump. Treating every `ret` as a conventional function return can hide edges.

---

## 12. Hybrid disassembly

Practical systems combine evidence:

```text
Executable metadata
    + recursive traversal
    + selective linear sweep
    + relocation analysis
    + function heuristics
    + data-flow analysis
    + dynamic traces
    + analyst corrections
```

A useful policy:

1. Seed with high-confidence entry points.
2. Recursively recover reachable code.
3. Resolve indirect transfers where possible.
4. Examine unexplained executable-region gaps.
5. Apply linear decoding cautiously to those gaps.
6. rank discoveries by supporting evidence;
7. validate critical paths dynamically.

---

## 13. Static versus dynamic evidence

Static analysis aims to cover behavior without running the target. It can inspect dormant paths but must approximate runtime values.

Dynamic tracing records what executed in specific runs. It provides real instruction boundaries for the observed path but misses everything not exercised.

```text
Static analysis: may happen
Dynamic trace: did happen in this run
```

Neither alone proves the complete behavior of a nontrivial program.

---

## 14. Worked example

```asm
401000: cmp  edi, 2
401003: ja   401030
401005: lea  rdx, [rip+0x1ff4]
40100c: movsxd rax, DWORD PTR [rdx+rdi*4]
401010: add  rax, rdx
401013: jmp  rax

401020: mov  eax, 10
401025: ret
401026: mov  eax, 20
40102b: ret
401030: mov  eax, -1
401035: ret
```

### Initial recursive result

Starting at `0x401000`, traversal discovers the bounds check and reaches `0x401013`, but the indirect target is unknown. It can find the default block at `0x401030` through the `ja` edge, while the case blocks may remain undiscovered.

### Added pattern reasoning

The indexed 4-byte load followed by base addition suggests a relative-offset jump table. Inspecting its entries may reveal targets `0x401020` and `0x401026`.

### Evidence statement

- High confidence: input values above 2 reach `0x401030`.
- High confidence: `0x401013` performs an indirect jump based on `rdi`.
- Probable: the memory at the computed base is a jump table.
- Confirmed only after table validation: exact case targets.

---

## 15. Practical lab

Create:

```c
__attribute__((noinline))
int choose(int x) {
    switch (x) {
        case 0: return 11;
        case 1: return 27;
        case 2: return 42;
        case 3: return 99;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    return choose(argc);
}
```

Compile variants:

```bash
gcc -O0 -fno-pie -no-pie switch.c -o switch-O0
gcc -O2 -fno-pie -no-pie switch.c -o switch-O2
gcc -O2 -fPIE -pie switch.c -o switch-pie
objdump -d -M intel switch-O0
objdump -d -M intel switch-O2
objdump -d -M intel switch-pie
```

Tasks:

1. Locate the ELF entry point and explain why it is not `main`.
2. Locate `main` and `choose`.
3. Mark basic-block boundaries.
4. Draw each `choose` CFG.
5. Determine whether the compiler uses branches, arithmetic, conditional moves, or a jump table.
6. Explain any RIP-relative accesses.
7. Strip a copy and repeat function discovery without private symbols.
8. State which discoveries came from metadata, direct control flow, heuristics, and manual inference.
9. Increase the number and irregularity of cases until a jump table appears.
10. Predict where recursive traversal would stop without jump-table recovery.

---

## 16. Building a minimal recursive disassembler

Later, Capstone can decode individual instructions. A safe conceptual design is:

```text
Input:
  executable section bytes
  section virtual address
  seed addresses

State:
  worklist of block leaders
  decoded-instruction map
  block map
  unresolved indirect edges
  diagnostics/conflicts
```

Required safeguards:

- reject addresses outside executable mappings;
- translate virtual addresses to buffer offsets carefully;
- detect decoding overlap;
- stop a block at terminators;
- avoid decoding an address twice;
- distinguish call targets from fall-through;
- record unresolved targets instead of inventing edges;
- impose resource limits for malformed input;
- retain byte-level provenance for every decoded instruction.

The decoder answers:

> “What instruction can these bytes represent at this address?”

The traversal layer answers:

> “Why do we believe execution can begin at this address?”

Keeping those questions separate improves correctness.

---

## 17. Common analytical mistakes

- Treating every byte in `.text` as code.
- Treating unreachable bytes as definitely data.
- Assuming a decoded instruction is a real instruction.
- Stopping analysis permanently at every indirect jump.
- Assuming every direct call returns.
- Assuming bytes after a call must be its continuation.
- Using function prologues as definitive boundaries.
- Ignoring relocations and unwind metadata.
- Treating a dynamic trace as complete coverage.
- Silently converting uncertainty into a fabricated CFG edge.

---

## Mastery check

You understand this topic when you can:

1. implement or precisely describe linear sweep;
2. implement or precisely describe recursive traversal;
3. explain how inline data desynchronizes x86 decoding;
4. construct basic blocks and a CFG from a short listing;
5. identify unresolved indirect control flow;
6. recognize a likely jump-table pattern;
7. compare false-positive and false-negative risks;
8. explain why function discovery is heuristic;
9. design a hybrid recovery strategy;
10. label conclusions by confidence and supporting evidence.

