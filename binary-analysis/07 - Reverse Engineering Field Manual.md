---
aliases: [Practical Reverse Engineering Manual, RE Field Manual]
tags: [reverse-engineering, binary-analysis, linux, practical-guide]
source: Practical Binary Analysis by Dennis Andriesse
---

# Reverse Engineering Field Manual

> [!warning] Authorization and containment
> Analyze only software you own, CTF/wargame targets, malware samples in an isolated lab, or software for which you have explicit permission. Never run an unknown binary on your normal workstation. Prefer a disposable VM with snapshots, no shared clipboard/folders, and networking disabled or simulated.

## What this note gives you

This is a repeatable Linux x86-64 workflow for turning an unfamiliar executable into an evidence-backed explanation of what it does. It is designed to work when source code and symbols are absent, and to tell you when your conclusions are uncertain.

No checklist can make *every* binary easy: architecture, format, packing, self-modifying code, kernel behavior, managed runtimes, and hostile anti-analysis can require specialist methods. The durable skill is to move between four views of the same program:

```text
file structure ⇄ static code ⇄ runtime state ⇄ external behavior
       ELF/PE       CFG/data      registers       files/network
                                  and memory      processes/syscalls
```

Related foundations:

- [[02 - Source Code to Running Program]]
- [[03 - Executable Formats - ELF and PE]]
- [[04 - Binary Loading and Linux Analysis]]
- [[05 - x86-64 Assembly for Binary Analysis]]
- [[06 - Static Disassembly Strategies]]

---

## 1. The evidence discipline

Keep four separate labels in your working notes:

| Label | Meaning | Example |
|---|---|---|
| Fact | Directly observed | `read` receives 64 bytes into a stack address |
| Interpretation | Best current explanation | The destination appears to be a local input buffer |
| Hypothesis | Testable but unconfirmed | Input beginning with `MAGIC` selects an admin path |
| Unknown | Missing information | The target of an indirect call at `0x4012a8` |

Do not let a decompiler turn an interpretation into a fact. Decompiled C is a useful rendering of machine code, not recovered source. Verify important claims in instructions and at runtime.

### The analysis loop

```text
question → cheapest observation → hypothesis → discriminating test
         → result → update model → next question
```

Example:

```text
Question: What does argv[1] control?
Observation: xrefs show it reaches strcmp and fopen.
Hypothesis: it selects a mode and later becomes a filename.
Test: break at both calls; inspect arguments for three inputs.
Result: argv[1] is only compared; argv[2] is the filename.
Update: rename parameters and correct the data-flow model.
```

---

## 2. Build a safe analysis workspace

### Minimum toolkit

```bash
# identification and ELF metadata
file, sha256sum, xxd, strings, readelf, objdump, nm

# behavior
strace, ltrace, gdb

# richer static analysis
Ghidra or Cutter/rizin

# optional advanced work
checksec, radare2/rizin, rr, QEMU, Frida, angr, Z3, Triton
```

For hostile samples, use a dedicated VM. Take a snapshot before analysis. Record:

```bash
date -Is
uname -a
sha256sum ./target
file ./target
```

The hash gives the sample a stable identity. A filename can change; the contents represented by a cryptographic hash do not.

### Preserve the original

```bash
mkdir analysis
cp --preserve=all target analysis/target.working
chmod a-w target
```

Patch only a copy. If the sample may be malicious, do this inside the isolated lab and avoid invoking it until static triage is complete.

---

## 3. Phase A — identify before executing

### Step 1: determine the container and architecture

```bash
file ./target
xxd -l 64 ./target
```

Typical ELF magic begins with `7f 45 4c 46`; PE begins with `4d 5a` (`MZ`). `file` also reports bitness, endianness, architecture, dynamic/static linking, and whether symbols are stripped.

Questions to answer:

- Is this native code, bytecode, a script, an archive, or a disk image?
- Which ISA and ABI does it use?
- Is it position-independent (`PIE`/shared-object style)?
- Is it dynamically linked, statically linked, or packed?
- Does the host safely support this architecture?

### Step 2: hash and inspect metadata

```bash
sha256sum ./target
readelf -hW ./target
readelf -lW ./target
readelf -SW ./target
readelf -dW ./target
readelf -rW ./target
```

Mental model:

```text
sections = linker/analyst organization
segments = loader/runtime mappings
```

The program-header table remains important even if section headers are missing or falsified. Map an address to a file offset only when the containing load segment is known:

```text
file_offset = virtual_address - segment_vaddr + segment_offset
```

Example: in a segment with `p_vaddr=0x400000` and `p_offset=0`, virtual address `0x401234` corresponds to file offset `0x1234`. This formula does not apply across unrelated segments.

### Step 3: record mitigations and trust boundaries

```bash
checksec --file=./target
readelf -W -l ./target | rg 'GNU_STACK|GNU_RELRO'
readelf -W -d ./target | rg 'BIND_NOW|NEEDED|RPATH|RUNPATH'
```

For reversing, mitigations explain runtime addresses and indirection:

| Feature | Analytical consequence |
|---|---|
| PIE + ASLR | Static offsets stay stable; runtime base changes |
| NX | Stack/heap mappings normally lack execute permission |
| Canary | Function epilogue may call `__stack_chk_fail` |
| RELRO | GOT mutability and binding behavior differ |
| Stripping | Names disappear; code and dynamic imports remain |

### Step 4: mine cheap semantic clues

```bash
strings -a -n 4 -t x ./target | less
readelf -Ws ./target
nm -an ./target
objdump -p ./target
```

Interesting strings include error messages, usage text, file paths, URLs, format strings, protocol words, and compiler artifacts. Treat strings as leads, not proof: dead data and decoys exist. Find references to the string in the disassembler and confirm that reachable code uses it.

Imports reveal capabilities, not necessarily behavior:

| Import family | Investigate |
|---|---|
| `open/read/write/stat` | Files and data movement |
| `socket/connect/send/recv` | Network endpoints and protocol |
| `fork/execve/system` | Process creation and command construction |
| `mmap/mprotect/dlopen` | Dynamic code/data mappings and plugins |
| `strcmp/memcmp/strstr` | Input gates, signatures, or protocol parsing |
| crypto APIs | Authentication, encryption, hashes, key handling |

Deliverable after Phase A: a one-page intake sheet containing identity, format, architecture, linking, mitigations, suspicious metadata, likely inputs/outputs, and the next three questions.

---

## 4. Phase B — observe external behavior safely

Do not begin by reading thousands of instructions. Establish what enters and leaves the process.

### Step 1: run controlled input cases

Use a matrix:

| Case | Purpose |
|---|---|
| no arguments | usage/default path |
| empty input | boundary behavior |
| ordinary valid-looking input | normal path |
| wrong input | rejection path |
| shortest and longest accepted input | size assumptions |
| one field changed at a time | identify predicates |

Record exit status and output:

```bash
./target test
printf 'exit=%d\n' "$?"
```

### Step 2: trace the OS boundary

```bash
strace -f -s 256 -yy -o strace.log -- ./target test
```

Read the trace as a timeline. Filter noise only after retaining the full log:

```bash
rg 'openat|read\(|write\(|connect\(|execve\(|mmap\(|mprotect\(' strace.log
```

Example inference:

```text
openat(..., "/etc/app.conf", O_RDONLY) = 3
read(3, "mode=safe\n", 4096) = 10
write(1, "denied\n", 7) = 7
```

Facts: the process opened that path, read ten bytes, and printed `denied`. Hypothesis: `mode=safe` caused denial. Test with a different controlled config; the trace alone does not prove causation.

### Step 3: trace library calls when useful

```bash
ltrace -f -s 256 -o ltrace.log -- ./target test
```

`ltrace` can expose calls such as `strcmp(user, "open-sesame")`, but it can miss statically linked, inlined, hidden, or direct-syscall behavior. Do not interpret absence as proof.

Deliverable after Phase B: an input/output map and a behavioral timeline.

---

## 5. Phase C — recover static structure

### Step 1: locate entry points

Start with:

- ELF `e_entry`;
- exported and dynamic symbols;
- initialization/finalization arrays;
- relocation targets and imported functions;
- thread entry routines and callbacks;
- cross-references to high-value strings.

On a normal glibc ELF, `_start` prepares arguments and calls `__libc_start_main`; one argument points to `main`. A stripped binary may still expose this handoff pattern.

### Step 2: distinguish code from data

Review [[06 - Static Disassembly Strategies]]. Use both:

- recursive traversal from known entry points for control-flow confidence;
- linear sweep for coverage and code with no discovered inbound edge.

Warning signs of bad disassembly:

- impossible or privileged instructions in ordinary application code;
- abrupt changes in instruction quality;
- branches into instruction middles;
- many references treating the region as data;
- stack behavior that never balances;
- unreachable islands created by a guessed function boundary.

### Step 3: build basic blocks and a control-flow graph

A basic block is a maximal straight-line sequence with one entry and an ending transfer. Split at:

- function/branch targets;
- the instruction after a conditional branch;
- calls when your IR treats calls as terminators;
- returns and indirect jumps.

Example:

```asm
cmp edi, 10
jle .small
mov eax, 1
ret
.small:
xor eax, eax
ret
```

Recovered logic:

```c
return (argument > 10) ? 1 : 0;
```

Be precise about signedness: `jle` is signed less-or-equal; `jbe` is unsigned below-or-equal.

### Step 4: identify functions carefully

Evidence for a function start can include:

- a direct call target;
- a symbol or relocation;
- an address stored in a callback/vtable/init array;
- a standard prologue;
- a separately reachable CFG region.

A prologue such as `push rbp; mov rbp,rsp` is a clue, not a requirement. Optimized functions omit frame pointers, share tails, inline callees, or contain multiple entries.

### Step 5: annotate, rename, and type

Use names that encode evidence:

```text
FUN_401240       → parse_header
param_1          → packet
local_18         → declared_length
DAT_404080       → command_table
```

Type recovery is constraint solving:

- `movzx eax, byte ptr [rdi]` suggests byte access through a pointer;
- `[rdi+8]` and `[rdi+16]` suggest fields or array elements;
- a value passed in `rdi` to `strlen` must behave like a C-string pointer;
- multiplication by 4 before indexed access suggests 4-byte elements;
- repeated accesses at stable offsets suggest a structure.

Keep uncertain names marked, for example `maybe_count`.

---

## 6. Reading compiler patterns

### System V AMD64 calling convention

Integer/pointer arguments usually arrive in:

```text
rdi, rsi, rdx, rcx, r8, r9; extras on stack
return value: rax
```

Caller-saved: `rax rcx rdx rsi rdi r8-r11`. Callee-saved: `rbx rbp r12-r15`. The stack must satisfy ABI alignment at calls.

### Stack frame example

```asm
push rbp
mov rbp, rsp
sub rsp, 0x30
mov dword ptr [rbp-0x24], edi
lea rax, [rbp-0x20]
```

Likely model: a saved first integer argument at `[rbp-0x24]` and a local buffer beginning at `[rbp-0x20]`. Exact source declarations are not recoverable from offsets alone because compilers add padding and reuse storage.

### Common expressions

```asm
xor eax, eax                 ; eax = 0
lea eax, [rdi+rdi*4]         ; eax = 5 * edi
test rdi, rdi                ; compare pointer/value with zero
setne al                     ; al = condition ? 1 : 0
sar eax, 1                   ; signed arithmetic shift right
shr eax, 1                   ; logical shift right
```

`lea` computes an address expression but does not dereference memory. Compilers also use it as fast arithmetic.

### Loop recovery example

```asm
xor eax, eax
xor edx, edx
.loop:
cmp rax, rsi
jae .done
movzx ecx, byte ptr [rdi+rax]
add edx, ecx
inc rax
jmp .loop
.done:
mov eax, edx
ret
```

Reasoning:

1. `rax` starts at zero and increments: induction variable.
2. `rax` is compared with `rsi` using unsigned `jae`: loop while `rax < rsi`.
3. `[rdi+rax]` loads one byte: `rdi` is likely a byte buffer.
4. `edx` accumulates bytes and becomes the return value.

Equivalent model:

```c
uint32_t sum(const uint8_t *buf, size_t len) {
    uint32_t total = 0;
    for (size_t i = 0; i < len; i++) total += buf[i];
    return total;
}
```

### Switch/jump table

Typical shape:

```asm
cmp edi, 4
ja .default
lea rax, [rip+table]
movsxd rdx, dword ptr [rax+rdi*4]
add rax, rdx
jmp rax
```

The bounds check is part of the recovered semantics. Examine each table entry and the default path; do not treat the table bytes as sequential code.

### Optimization changes appearance, not semantics

Expect:

- constants folded;
- functions inlined;
- loops unrolled or vectorized;
- branches replaced with conditional moves;
- dead code removed;
- tail calls rendered as jumps;
- variables living only in registers;
- multiple source expressions combined.

Use debug builds to learn patterns, but practice on stripped optimized builds because they better represent real targets.

---

## 7. Phase D — answer focused questions dynamically

### GDB baseline

```gdb
gdb -q ./target
set disassembly-flavor intel
set pagination off
starti
info files
info proc mappings
```

Useful inspection:

```gdb
info registers
x/10i $rip
x/32gx $rsp
x/s $rdi
x/32bx ADDRESS
disassemble /r FUNCTION
```

At a System V function entry, inspect `rdi` through `r9` according to the expected signature. Dereference only after checking that an address lies in a valid mapping.

### PIE address arithmetic

Static tools usually show an image-relative virtual address/offset. At runtime:

```text
runtime_address = module_base + static_offset
```

Find the mappings with `info proc mappings`. Ensure the offset is relative to the correct image base, not blindly to the first executable mapping—the ELF segment's file offset matters.

### Break on semantic boundaries

Good breakpoints answer questions:

```gdb
break strcmp
commands
  silent
  x/s $rdi
  x/s $rsi
  continue
end
```

This tests which strings reach `strcmp`. For `read(fd, buf, count)`, x86-64 arguments are `rdi=fd`, `rsi=buf`, `rdx=count`; inspect the buffer after the call using `finish` or a breakpoint on the return site.

### Watchpoints establish causality

```gdb
watch *(unsigned int *)0xADDRESS
continue
```

A hardware watchpoint stops when the value changes, revealing the writer. It is excellent for answering “where is this state set?” but limited in number and complicated by dynamic addresses.

### Reverse engineer one predicate

Suppose a password check contains:

```asm
cmp byte ptr [rdi], 0x52
jne .fail
cmp byte ptr [rdi+1], 0x45
jne .fail
cmp byte ptr [rdi+2], 0x21
jne .fail
cmp byte ptr [rdi+3], 0
sete al
ret
```

State the constraints, not merely the guessed password:

```text
input[0] = 'R'
input[1] = 'E'
input[2] = '!'
input[3] = NUL
```

Test `RE!`, a short string, and `RE!x`. The final null constraint means the accepted value is exactly three bytes as a C string.

---

## 8. Data-flow reconstruction

For every important value, write:

```text
origin → transformations → comparisons → destinations
```

Example:

```text
argv[1]
 → strtoul(base 10)
 → truncate to uint16_t
 → multiply by 4
 → use as allocation size
 → loop copies original untruncated count elements
```

This representation exposes semantic mismatches that decompiled code can hide.

### Backward slicing

Start at an observation—branch, indirect call, output, or memory write—and trace only definitions that affect it. For a branch `cmp eax, 0x42; je success`, follow the definitions of `eax`, then their inputs, until reaching constants or external input.

### Forward slicing

Start at a source such as `read`, `recv`, `argv`, or a file mapping and trace what it can influence. This is useful for both behavior recovery and vulnerability analysis.

### Dynamic taint analysis mental model

Define:

- **source:** untrusted input bytes become tainted;
- **propagation:** instructions copy/combine taint labels;
- **sink:** a security-relevant use is checked for taint.

Example:

```text
recv → packet.length → memcpy size
```

If the `memcpy` size remains tainted, input influences it. That does not by itself prove a vulnerability; validation and destination capacity still matter.

Taint-policy choices matter. Byte-level taint is precise but expensive. Explicit-flow tracking misses implicit control flow such as:

```c
if (secret_bit) public_value = 1;
else            public_value = 0;
```

No direct data copy occurs, yet `public_value` reveals the bit.

---

## 9. Symbolic execution for path questions

Symbolic execution replaces a concrete input with symbols and accumulates path constraints.

Example:

```c
if (x > 5 && x * 2 == 18) success();
```

The success path has constraints:

```text
x > 5 ∧ x * 2 = 18
```

A solver returns `x = 9` (subject to the correct integer width and signedness).

Use symbolic execution when the question is bounded:

- which input reaches a target block?
- can an indirect branch become input-controlled?
- which bytes influence this comparison?
- is a supposedly unreachable path satisfiable?

Control state explosion with:

- a specific start and goal;
- constrained input length/alphabet;
- hooks/summaries for libraries and syscalls;
- loop bounds;
- concolic execution (one concrete path plus symbolic alternatives);
- backward slicing so only relevant expressions remain symbolic.

Limitations: environment modeling, solver cost, floating point, threads, self-modifying code, path explosion, and concretization can all create false confidence. Replay every generated input against the real binary.

---

## 10. Instrumentation, unpacking, and hostile binaries

Instrumentation inserts analysis behavior before/after instructions, blocks, functions, or syscalls.

| Method | Advantage | Cost/limit |
|---|---|---|
| Static rewriting | persistent, no runtime framework | relocation/layout correctness is hard |
| Dynamic instrumentation | observes executed code and runtime values | overhead and anti-instrumentation |
| Debugger breakpoints | quick and focused | easy to detect; awkward at scale |
| Emulation | strong isolation/control | environment gaps and performance |

Useful probes count basic blocks, log indirect branches, record memory writes, or capture code after unpacking.

### Recognizing a packer

Clues include a tiny import table, high-entropy regions, an entry point in an unusual section, writable-and-executable transitions, few meaningful strings, and a small stub that jumps into newly written memory.

Safe unpacking logic:

```text
loader stub executes
 → writes/decompresses code
 → changes memory permissions if needed
 → transfers control to original entry point
 → dump memory and reconstruct mappings/imports
```

Use execution/write tracing to locate the transition. A memory dump is not automatically a valid executable file; imports, relocations, headers, and section layout may need reconstruction.

### Anti-analysis checklist

- debugger checks and timing gaps;
- environment/VM fingerprinting;
- signal/exception tricks;
- opaque predicates and bogus branches;
- indirect dispatch or virtualization;
- overlapping instructions and inline data;
- self-modifying code;
- encrypted strings or APIs resolved by hash.

Respond by collecting independent evidence from different layers. If static control flow is untrustworthy, emphasize runtime traces; if execution is evasive, emulate or patch checks in a copy and document the modification.

---

## 11. Binary modification as an experiment

Patching is most valuable as hypothesis testing.

Example question: “Does this conditional branch cause the failure?”

Process:

1. identify the exact instruction and original bytes;
2. map its virtual address to file offset through the correct segment;
3. copy the binary and record hashes;
4. patch with an instruction of compatible size or redirect safely;
5. disassemble around the patch to verify boundaries;
6. run the same input matrix;
7. attribute only the changed behavior to the experiment.

`LD_PRELOAD` can interpose dynamically resolved functions for observation or controlled replacement, but not statically linked, direct-syscall, hidden, or already bound internal calls.

Code injection is harder than copying bytes: preserve registers/flags, ABI stack alignment, relocations, control flow back to the original code, segment permissions, and position independence. Prefer debugger or instrumentation probes when persistent modification is unnecessary.

---

## 12. Fully worked lab — reverse a stripped checker

Use only this local program or another authorized target.

```c
// checker.c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check(const unsigned char *s) {
    if (strlen((const char *)s) != 4) return 0;
    return ((s[0] ^ 0x13) == 0x58) &&
           ((uint8_t)(s[1] + 3) == 0x48) &&
           (s[2] == s[0] - 2) &&
           (s[3] == '!');
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s INPUT\n", argv[0]); return 2; }
    puts(check((unsigned char *)argv[1]) ? "accepted" : "denied");
    return 0;
}
```

Build two views:

```bash
gcc -O0 -g -fno-omit-frame-pointer -o checker.debug checker.c
gcc -O2 -s -o checker checker.c
```

### A. Intake

```bash
sha256sum checker
file checker
checksec --file=checker
strings -a -n 4 checker
readelf -hW checker
readelf -Ws checker
```

Expected observations: a dynamically linked x86-64 ELF, stripped local symbols, and imports such as `strlen`, `puts`, and `fprintf`. Strings reveal outputs but not the accepted input.

### B. Find the decision

In Ghidra, follow xrefs to `strlen` or `accepted`. In GDB, breaking at `strlen` confirms the candidate string:

```gdb
break strlen
run AAAA
x/s $rdi
finish
p/x $rax
```

### C. Translate predicates

Recover each condition algebraically:

```text
s[0] XOR 0x13 = 0x58  → s[0] = 0x4b = 'K'
s[1] + 3 = 0x48       → s[1] = 0x45 = 'E'
s[2] = s[0] - 2       → s[2] = 0x49 = 'I'
s[3] = 0x21            → s[3] = '!'
strlen(s) = 4
```

Candidate: `KEI!`.

### D. Validate and reject alternatives

```bash
./checker 'KEI!'
./checker 'KEI?'
./checker 'KEI!!'
```

The three cases test success, the final-byte predicate, and exact length. The conclusion is stronger than merely observing one successful input.

### E. Final recovered model

```text
Input: exactly one command-line string
Transformation: four independent byte predicates
Success effect: writes "accepted" to stdout
Failure effects: usage for wrong argc, otherwise "denied"
Dependencies: glibc string and output routines
Confidence: high; static constraints and runtime tests agree
```

---

## 13. When the target is not a normal Linux ELF

Apply the same questions with format-specific tools:

| Target | Adaptation |
|---|---|
| PE/Windows | inspect imports, resources, TLS callbacks, sections; debug in isolated Windows VM |
| ARM/MIPS/RISC-V | select correct endianness, ISA mode, ABI; use QEMU or native hardware |
| .NET/JVM | inspect managed metadata and bytecode before native stubs |
| firmware | identify containers, compression, filesystem, load address, peripherals |
| kernel module/driver | use an instrumented VM; model privileged inputs and concurrency |
| statically linked binary | signatures and syscall behavior replace many import clues |

Never force an x86/ELF assumption onto an unidentified sample.

---

## 14. Analysis report template

```markdown
# Target name

## Scope and safety
- Authorization:
- Isolation:
- Sample SHA-256:

## Identity
- Format / architecture / endianness:
- Compiler/runtime clues:
- Linking / stripping / mitigations:

## Executive behavior
One paragraph describing what it does and confidence level.

## Inputs and outputs
| Channel | Format | Constraints | Evidence |

## Component/function map
| Address/offset | Renamed function | Purpose | Confidence |

## Key algorithms and data structures

## Runtime timeline

## Important predicates
| Location | Condition | Inputs | Observed outcomes |

## Anti-analysis or packing

## Unknowns and competing hypotheses

## Reproduction commands

## Artifacts
- traces, scripts, database, screenshots, patched hashes
```

## Completion gate

You are finished only when you can:

- [ ] identify the exact sample and execution environment;
- [ ] explain its inputs, outputs, and major side effects;
- [ ] name the important functions by behavior, not guesswork;
- [ ] draw the main control-flow and data-flow paths;
- [ ] explain important predicates with types and signedness;
- [ ] reproduce dynamic evidence for central claims;
- [ ] distinguish facts, hypotheses, and unknowns;
- [ ] explain what packing/optimization/anti-analysis may hide;
- [ ] provide commands and artifacts another analyst can reproduce;
- [ ] state the limits of the analysis.

## Practice ladder

1. Build the checker above; reverse both debug and stripped variants.
2. Rebuild with `-O0`, `-O2`, and `-O3`; compare CFGs and decompiler output.
3. Replace direct comparisons with a loop and table; recover the table semantics.
4. Write a small file parser; reconstruct its input format from a stripped build.
5. Add a switch statement and function pointers; recover indirect control flow.
6. Pack an authorized toy binary with UPX; observe the unpacking transition.
7. Use a solver on a toy checker, then replay its candidate concretely.

For each exercise, produce the report above. The report—not merely finding a secret—is the proof that you can reverse the program.
