# Ghidra + GDB/pwndbg — Complete Integrated Field Manual

> [!scope]
> Use this workflow only on binaries you own, purpose-built labs, CTFs, or explicitly authorized assessments. Exploitation sections use local toy programs.

> [!version]
> Written against the official Ghidra 12.1 documentation and the current pwndbg stable documentation available in August 2026. Confirm commands when upgrading.

## Official References

- [Ghidra Getting Started](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
- [Ghidra Beginner Guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)
- [Ghidra Debugger Course](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/README.html)
- [GDB Manual](https://sourceware.org/gdb/current/onlinedocs/gdb)
- [pwndbg Setup](https://pwndbg.re/stable/setup/)
- [pwndbg Features and Commands](https://pwndbg.re/stable/features/)

## 1. The Correct Mental Model

Ghidra answers: “What might every statically discoverable path mean?”

GDB/pwndbg answers: “What exact state existed on this executed path?”

```text
Ghidra hypothesis
  ├── function RVA and CFG
  ├── tentative types/names
  └── predicted values
           ↓ runtime-address translation
GDB/pwndbg experiment
  ├── break/watch/catch
  ├── registers, stack, heap, mappings
  └── actual branch/target/value
           ↓
confirmed evidence returned to Ghidra
```

Do not use the debugger as a substitute for reading code, or the decompiler as a substitute for observing state.

## 2. Setup

### Ghidra

Official Ghidra 12.1 requires a 64-bit JDK 21. Download the release archive—not the GitHub “Source Code” archive—extract into a new directory, and launch `ghidraRun` (or `ghidraRun.bat`). Do not overwrite an older installation.

Verify:

```sh
java -version
/path/to/ghidra/ghidraRun
```

### GDB and pwndbg

The official pwndbg portable installer provides a `pwndbg` program. Review the installer before running remote scripts; the documented user install is:

```sh
curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' |
  sh -s -- -t pwndbg-gdb -u
```

Verify:

```sh
gdb --version
pwndbg --version
pwndbg ./your_lab_binary
```

“pwn gdb” is interpreted here as GDB enhanced by **pwndbg**. Core GDB commands remain authoritative; pwndbg adds context, pointer visualization, memory maps, allocator inspection, cyclic patterns, and other reversing/exploitation helpers.

## 3. Build a Reproducible Lab Corpus

```c
// branch.c
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
int classify(int x) {
    if (x < 0) return -1;
    if (x > 100) return 1;
    return 0;
}

int main(int argc, char **argv) {
    int x = argc > 1 ? atoi(argv[1]) : 0;
    printf("%d\n", classify(x));
}
```

Build variants:

```sh
gcc -g -O0 -fno-omit-frame-pointer -o branch_O0 branch.c
gcc -g -O2 -o branch_O2 branch.c
gcc -O2 -s -o branch_stripped branch.c
```

Maintain a build ledger: compiler/version, flags, architecture, PIE/non-PIE, hashes, expected inputs/outputs. Reverse the stripped build; use the symbolized build only to check your result.

## 4. Ghidra Project and Import Workflow

1. Create a **non-shared project** for local study or a shared project only when collaboration is intended.
2. Import the exact binary; verify format, language/compiler specification, and architecture.
3. Preserve the original under a hash-based sample name.
4. Run auto-analysis with defaults first.
5. Save an analysis snapshot before aggressive manual changes.
6. Record image base, entry point, sections/memory blocks, imports, exports, and detected compiler.
7. Open Listing, Decompiler, Symbol Tree, Data Type Manager, Function Graph, Function Call Tree, Bytes, and References as needed.

### What auto-analysis is allowed to be wrong about

- function starts/ends;
- code versus data;
- switch/jump-table targets;
- calling convention;
- parameter count/types;
- structure layout;
- non-returning functions;
- decompiler expressions.

Every annotation is an inference.

## 5. Ghidra Orientation: Where to Start

### Entry and imports

Follow entry through runtime startup to the application-level function. Imported calls reveal capabilities but not reachability.

### Strings and cross-references

Search meaningful errors, paths, formats, protocol tokens, and configuration. Open references to the string, then move upward to the function and callers. Strings can be dead or library data; require a live path.

### Call graph

Work from high-signal sinks backward and external sources forward:

```text
input APIs → parsing/transforms → target function → copy/allocation/call/output
```

### Function Graph

Use graph view to identify:

- loop back edges;
- success/failure branches;
- switch fan-out;
- common cleanup blocks;
- opaque/dead candidates.

Graph shape is a navigation tool; read instructions at each security-relevant edge.

## 6. Correcting Functions, Signatures, and Types

### Function boundaries

Check incoming calls, prologue/epilogue or unwind information, fall-through, tail calls, padding, and neighboring functions. Create/remove/resize functions only with evidence.

### Signatures

Infer:

- calling convention from ABI and stack balance;
- parameters from incoming registers/stack reads before definition;
- return from register/state used by callers;
- pointer types from dereference;
- signedness from branches/extensions;
- `const` from absence of writes, with caution.

Commit a corrected signature so the decompiler retypes callers.

### Structure recovery

Suppose assembly uses:

```asm
mov eax, [rdi+0]
mov rcx, [rdi+8]
cmp word [rdi+16], 0
```

Create a tentative structure with a 32-bit field at 0, padding, pointer at 8, and 16-bit field at 16. Apply it to `RDI`’s parameter. Then validate every cross-reference, allocation size, constructor/initializer, and array stride.

Use names such as `candidate_count` until proven.

## 7. Reading the Decompiler Properly

For every important line:

1. click the variable/operator and observe synchronized Listing instructions;
2. verify operand widths;
3. inspect branch mnemonic for signedness;
4. check casts inserted by decompiler;
5. identify aliases and global/volatile effects;
6. check all callers and error paths;
7. record confidence.

### Decompiler-to-assembly example

Decompiler:

```c
if (length < capacity) copy(dst, src, length);
```

Listing might be:

```asm
cmp edx, ecx
jl copy_path
```

`JL` is signed. If `length` can be negative and later becomes `size_t`, the pretty pseudocode hides the vulnerability. Rewrite types and comments to show exact semantics.

## 8. Ghidra Searching and Navigation

Use searches for:

- strings and scalar constants;
- direct and indirect references;
- instruction mnemonics;
- byte patterns with masks;
- memory blocks and undefined bytes;
- functions calling/importing a sink;
- symbols and namespaces.

Maintain bookmarks for source, transform, check, sink, first invalid instruction, and unresolved questions. Comments should record evidence (“`RDX = decoded byte count at callsite 0x...`”), not just conclusions.

## 9. Ghidra Scripting and Headless Analysis

Use Script Manager for repetitive markup, exports, or searches. Scripts can be Java or Python through supported mechanisms such as PyGhidra.

Safe starter task: export each function’s entry, size, callers, and callees. Never let a script automatically rename or define thousands of items without logging and a rollback snapshot.

Headless pattern:

```sh
analyzeHeadless /path/to/project ProjectName   -import ./sample   -postScript YourReportScript.py
```

Exact options depend on installation; consult local `support/analyzeHeadless` help. A good script outputs deterministic JSON/CSV keyed by binary hash and RVA.

## 10. GDB Core: Starting and Controlling Execution

```gdb
file ./branch_stripped
set disassembly-flavor intel
set args 101
starti
run
continue
stepi
nexti
finish
until
kill
```

- `starti` stops at the first instruction.
- `stepi/si` executes one machine instruction and enters calls.
- `nexti/ni` steps over calls when possible.
- `finish` runs until current function returns.
- `continue/c` resumes.
- Source-level `step/next` depends on debug information; stripped binaries need instruction stepping.

## 11. Breakpoints, Watchpoints, and Catchpoints

### Breakpoints

```gdb
break main
break *0x401234
break *function+23
info breakpoints
condition 2 $rdi > 100
ignore 2 9
disable 2
enable 2
delete 2
```

A software breakpoint normally changes code bytes temporarily. For checksum-sensitive code, use hardware breakpoints where supported:

```gdb
hbreak *address
```

### Watchpoints

```gdb
watch *(unsigned int*)address
rwatch *(char*)address
awatch *(char*)address
```

- `watch` stops on write/change;
- `rwatch` on read;
- `awatch` on access.

Hardware resources are limited and alignment/size support varies. Watch the smallest exact object that proves your hypothesis.

### Catchpoints and signals

```gdb
catch syscall openat
catch load
catch throw
handle SIGSEGV stop print pass
```

Availability varies by target. Catchpoints stop at events; `handle` controls debugger behavior for signals.

## 12. Registers, Expressions, and Memory

```gdb
info registers
info all-registers
print/x $rax
print/d (int)$eax
set $saved = $rsp
x/10i $pc
x/16gx $rsp
x/64bx address
x/s address
disassemble /r function
```

GDB’s memory syntax is `x/nfu address`:

- `n` count;
- `f` format: x/d/u/t/c/s/i;
- `u` unit: b/h/w/g.

Examples:

```gdb
x/8gx $rsp       # eight 8-byte hex values
x/20i $pc        # twenty instructions
x/32bx $rdi      # thirty-two raw bytes
x/s $rsi         # NUL-terminated string
```

## 13. pwndbg Core Workflow

At each stop, pwndbg’s `context` can show registers, disassembly, stack, backtrace, arguments, threads, and other configured sections.

```gdb
context
context regs disasm stack backtrace
regs
disasm
telescope $rsp 20
vmmap
xinfo $pc
checksec
dumpargs
auxv
search -t string "marker"
```

Consult `pwndbg` and `help command` because commands/options evolve.

### What these answer

| Command | Question |
|---|---|
| `context` | what is the current execution state? |
| `telescope` | what pointer chains exist from this memory range? |
| `vmmap` | where are modules/heap/stack and permissions? |
| `xinfo` | what mapping/symbol contains this address? |
| `checksec` | which common binary mitigations are visible? |
| `dumpargs` | what arguments appear at this call under known ABI? |
| `search` | where does a byte/string pattern exist in mapped memory? |

## 14. Translate Ghidra Addresses to Runtime Addresses

### Non-PIE

If loaded at the expected image base, Ghidra VA may match runtime VA.

### PIE/ASLR

```text
RVA = Ghidra_VA - Ghidra_image_base
runtime_VA = runtime_module_base + RVA
```

Use `vmmap` to find the runtime module base. Confirm with `xinfo runtime_VA` and `x/5i runtime_VA`.

pwndbg may provide `breakrva RVA` for the main executable:

```gdb
breakrva 0x1234
```

Always record RVAs in notes because they survive base relocation.

## 15. End-to-End Function-Recovery Session

1. In Ghidra, select a function and record RVA, callers, callees, tentative prototype, and predicted path for input.
2. In pwndbg, break at its RVA.
3. Run a minimal test vector.
4. At entry, record ABI argument registers and pointed-to buffers.
5. Use `nexti` across routine calls only after recording arguments; use `stepi` into unknown internal code.
6. Set conditional breakpoints on boundary iterations.
7. Set a watchpoint on a field whose mutation would prove the hypothesis.
8. Stop at return and record return register and memory effects.
9. Repeat with an input that takes the opposite branch.
10. Update Ghidra’s signature, variable names, structure, branch comments, and function comment.
11. Write pseudocode that predicts both traces.
12. Run a third unseen input as validation.

## 16. Crash Triage

On a local vulnerable lab:

```gdb
run
context
bt
info registers
x/10i $pc-16
telescope $rsp 30
vmmap
xinfo fault_address
```

Record:

- signal/exception;
- faulting instruction;
- accessed address and access type;
- controlling input offset/pattern;
- call stack;
- destination object and valid bounds;
- mitigations;
- first invalid write/read, which may occur before the final crash.

The crash site can be far downstream. Restart and set a watchpoint/catch near the earliest corruption.

## 17. Cyclic Patterns for Local Stack Labs

pwndbg provides cyclic-pattern helpers. Check the installed command help because syntax may evolve:

```gdb
cyclic --help
cyclic 200
cyclic -l observed_value
```

Use the pattern only in a deliberately vulnerable local binary. An offset tells where controlled data reached a register/memory location; it does not by itself prove reliable control-flow execution.

## 18. Stack Analysis Workflow

1. In Ghidra, recover frame size, local offsets, saved registers, copy destination, and canary checks.
2. In pwndbg, stop before the copy.
3. Record `$rsp/$rbp` and destination address.
4. Use `telescope` and raw byte examination.
5. Watch the first byte just beyond capacity.
6. Continue to the first invalid store.
7. Rebuild with/without hardening to understand mitigation artifacts.
8. Fix source and repeat boundary tests.

### ABI reminder: SysV x86-64

First integer/pointer args: `RDI, RSI, RDX, RCX, R8, R9`; return usually `RAX`.

### ABI reminder: Windows x64

First four integer/pointer args: `RCX, RDX, R8, R9`; caller reserves shadow space; return usually `RAX`.

## 19. Heap Analysis Workflow

Pwndbg supports allocator-specific inspection, especially glibc ptmalloc. Available commands depend on allocator/version; use:

```gdb
pwndbg
help heap
heap
bins
vis-heap-chunks
track-heap
```

Treat allocator presentation as version-specific. First establish application object sizes and lifetime:

1. break on allocation/free;
2. log requested size and returned pointer;
3. label object fields from Ghidra;
4. watch the field or boundary;
5. distinguish use-after-free, overflow, double free, and allocator-detected failure;
6. reset the process between layout experiments.

Never infer general exploitability from one convenient heap arrangement.

## 20. Exploit-Development Workflow for Owned Toy Binaries

The objective is to understand mitigations and control, not target deployed software.

1. **Root cause:** prove exact out-of-bounds/lifetime/format violation.
2. **Reachability:** show input controls the failing path.
3. **Offset/control:** use marker/cyclic data to determine influenced bytes.
4. **Mitigations:** inspect NX, PIE, canary, RELRO, ASLR and architecture.
5. **Information needs:** identify whether addresses/state are known in the toy lab.
6. **Minimal demonstration:** prefer a controlled call to a benign built-in `win()` function or a proof marker over arbitrary payloads.
7. **Reliability:** rerun across clean processes and boundary variants.
8. **Remediation:** fix source invariant and verify the demonstration fails safely.
9. **Report:** separate confirmed facts from assumptions.

Paired toy source:

```c
#include <stdio.h>
#include <string.h>

void win(void) { puts("controlled lab proof"); }

void vulnerable(const char *s) {
    char buf[32];
    strcpy(buf, s);
}
```

Compile only inside the lab with chosen mitigations, study the frame and corruption, then repair it. The book’s mastery goal is understanding why the invariant fails and how defenses change consequences.

## 21. Multithreading and Forks

```gdb
info threads
thread 3
thread apply all bt
set scheduler-locking step
set follow-fork-mode child
set detach-on-fork off
catch fork
catch exec
```

Thread scheduling changes observations. `set scheduler-locking step` can reduce stepping surprises, but can also deadlock a program waiting on another thread. Document debugger-induced behavior.

## 22. Shared Libraries and Dynamic Resolution

```gdb
info sharedlibrary
catch load
break dlopen
break dlsym
```

At `dlsym` on SysV x86-64, inspect name at `$rsi`; record returned address after the call. Translate that runtime target to its module/RVA and label the indirect call in Ghidra.

For stripped or manually resolved APIs, runtime module ranges are semantic anchors.

## 23. Record and Reverse Execution

Where supported:

```gdb
record
record btrace
reverse-stepi
reverse-nexti
reverse-continue
```

Record/replay support and fidelity vary. Device/network I/O and some instructions may not reverse cleanly. Use it to answer “which instruction last changed this state?” but validate against a normal run.

## 24. Automating GDB

### Breakpoint command list

```gdb
break *address
commands
  silent
  printf "len=%lu ptr=%p\n", $rdx, $rsi
  x/16bx $rsi
  continue
end
```

### GDB Python skeleton

```python
import gdb

class LogCall(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi"))
        gdb.write(f"arg0={rdi:#x}\n")
        return False

LogCall("*0xADDRESS")
```

Use module base + RVA rather than a hard-coded ASLR address. Scripts must log binary hash and test input.

## 25. Ghidra ↔ pwndbg Evidence Template

```text
Binary hash:
Build/architecture:
Ghidra image base:
Function name/RVA:
Runtime module base:
Breakpoint runtime VA:

Static hypothesis:
Inputs and ABI locations:
Predicted branches:
Predicted memory effects:

Dynamic observations:
Registers at entry:
Buffers:
Indirect targets:
First mutation/failure:
Return/state:

Updated Ghidra artifacts:
Signature:
Types/structures:
Names/comments:
CFG corrections:

Confidence:
Counterexample test:
```

## 26. Common Failure Modes

**Ghidra decompiler looks wrong:** fix function boundaries, calling convention, no-return functions, code/data, jump tables, and types; read Listing.

**Breakpoint never hits:** wrong PIE translation, path not reached, function in library, tail call, or code unpacked/generated later.

**Addresses differ every run:** use RVA and runtime mapping, not absolute VA.

**Watchpoint misses corruption:** wrong address/width, object moved/freed, hardware limitation, or vectorized wider write.

**Program behaves differently under debugger:** timing, signal/exception handling, thread scheduling, environment checks, or software breakpoint byte changes.

**pwndbg command is missing:** run `pwndbg`/`help`, consult installed version’s documentation, and fall back to core GDB.

## 27. Mastery Exercises

1. Recover `classify` from stripped O0 and O2 builds.
2. Recover a structure from three functions and validate with watchpoints.
3. Map five Ghidra RVAs under PIE using `vmmap`.
4. Prove an integer-overflow allocation mismatch without completing the dangerous loop.
5. Locate the first stack overwrite with a watchpoint.
6. Reverse a dynamic `dlsym` call into a named Ghidra function pointer.
7. Capture a decoded buffer and reconstruct its transform.
8. Normalize a switch dispatcher using static CFG plus runtime state.
9. Write a GDB Python logger keyed by RVA.
10. Produce a final report where every important claim has static and dynamic evidence.

## “If You See This, Think This”

| Observation | Next action |
|---|---|
| decompiler cast appears unexpectedly | inspect operand width and extension |
| indirect call | inspect target at runtime; recover table/object field |
| `cmp` plus `JL/JG` | signed relation |
| `cmp` plus `JB/JA` | unsigned relation |
| pointer adjusted before return | hidden header or subobject |
| allocation size differs from loop bound | integer/unit mismatch |
| breakpoint changes checksum behavior | use hardware breakpoint or external trace |
| valid code appears only in memory | unpack/decrypt/generate boundary |
| Ghidra VA misses under PIE | translate via RVA and `vmmap` |
| crash far after input copy | find first corruption with watchpoint/replay |
