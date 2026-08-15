---
tags: [binary-analysis, compilation, linking, symbols, chapter-notes]
chapter: 1
---

# Chapter 1 — Anatomy of a Binary

## Chapter overview

This chapter answers the first foundational question: **how does source code become a process the CPU can execute?** The author follows a C program through preprocessing, compilation, assembly, and linking; then shows what symbols and disassembly reveal and what the operating system does at launch.

By the end, you should be able to connect a source statement to assembly, object-file bytes, linked addresses, and runtime mappings. This prepares you for [[Chapter 02 - The ELF Format]], where the container holding those pieces is examined field by field.

```text
C source
├── preprocessor → translation unit
├── compiler     → assembly
├── assembler    → relocatable object
└── linker       → executable/shared object
                       ↓
                 OS + dynamic loader
                       ↓
                    process
```

### Chapter roadmap

```text
Anatomy of a Binary
├── 1.1 Translation pipeline
│   ├── preprocessing: construct the translation unit
│   ├── compilation: source semantics → target assembly
│   ├── assembly: instructions → relocatable bytes
│   └── linking: resolve names, relocate, lay out an image
├── 1.2 Symbols and stripping
├── 1.3 Object/executable disassembly
└── 1.4 File image → process → runtime startup → main
```

## 1.1 The C compilation process

### Core idea

“Compiling” is commonly used for the entire pipeline, but the stages solve different problems. Keeping them separate explains why declarations, symbols, relocations, and shared libraries exist.

### 1.1.1 Preprocessing

The preprocessor handles directives such as `#include`, `#define`, `#if`, and conditional platform selection. It emits an expanded translation unit.

```c
#define LIMIT 8
#include <stdio.h>
int main(void) { printf("%d\n", LIMIT); }
```

```bash
gcc -E demo.c -o demo.i
```

`stdio.h` contributes declarations—not the compiled implementation of `printf`. The declaration lets the compiler type-check and generate the call correctly. The linker later resolves the referenced implementation.

**Translation unit:** the preprocessed source handled by one compiler invocation.

**In simple words:** one complete source unit after headers and macros have been expanded.

**Why it matters:** a suspicious constant may be introduced by a macro, and conditional compilation can make the binary differ from visible source.

> [!example] Added example — conditional behavior
> If `#ifdef DEBUG` guards an authentication bypass, the preprocessed output proves whether that branch was compiled. Searching the original source alone cannot establish the build configuration.

### 1.1.2 Compilation

The compiler parses C, checks types, builds intermediate representations, optimizes, and selects target instructions.

```bash
gcc -S -masm=intel -O0 demo.c -o demo_O0.s
gcc -S -masm=intel -O2 demo.c -o demo_O2.s
```

Source-to-instruction mapping is not one-to-one. At `-O2`, the compiler may fold constants, inline functions, eliminate unreachable code, use registers instead of stack variables, or transform loops.

Example:

```c
int f(void) { int x = 5; return x * 2 + 1; }
```

An optimized body can be just:

```asm
mov eax, 11
ret
```

The variable and arithmetic are absent because their result was proven at compile time.

### 1.1.3 Assembly

The assembler encodes mnemonics into machine instructions and creates a **relocatable object file**.

```bash
gcc -c demo.c -o demo.o
objdump -drwC -Mintel demo.o
```

An object can contain machine code without final addresses. Calls or data references whose destinations are not yet known have relocation records. A placeholder value plus relocation says, “the linker must fill this when layout is known.”

### 1.1.4 Linking

The linker combines objects and libraries, resolves symbol references, applies relocations, lays out sections/segments, and chooses an entry point.

```bash
gcc demo.o -o demo
```

#### Static versus dynamic linking

| Feature | Static | Dynamic |
|---|---|---|
| Library code | copied into output | resolved from shared library |
| File size | usually larger | usually smaller |
| Runtime dependency | fewer | shared-object ABI/version matters |
| Analysis | more code, fewer imports | imports reveal capabilities |
| Updates | requires relink | library can be updated independently |

Dynamic linking does not mean every external address is known at file creation. The dynamic loader maps dependencies and applies dynamic relocations; lazy binding may resolve a function only on first call.

### Worked pipeline

**Situation:** determine where `puts` becomes real machine code.

1. `#include <stdio.h>` supplies the declaration.
2. The compiler emits a call with the ABI-prescribed argument placement.
3. The assembler creates code plus a relocation for unresolved `puts`.
4. The linker creates a PLT/import relationship and dynamic metadata.
5. The runtime loader maps libc.
6. Eagerly or lazily, the relocation mechanism connects the call path to libc’s `puts`.

**Key lesson:** a source declaration, link-time symbol, PLT stub, GOT slot, and runtime function address are related but not interchangeable.

### How this connects

The pipeline explains the artifacts that later tools inspect: symbols come from compilation/linking; relocations represent unresolved address relationships; sections organize linker content; program headers tell the loader what to map.

## 1.2 Symbols and stripped binaries

### Core idea

A symbol associates a name with an addressable entity such as a function or object. Symbols make analysis easier but are not required for the CPU to execute ordinary code.

```bash
nm -n demo
readelf -Ws demo
objdump -t demo
```

Important distinctions:

| Table | Purpose | Often remains after strip? |
|---|---|---|
| `.symtab` + `.strtab` | full link/debug-oriented symbols | no |
| `.dynsym` + `.dynstr` | runtime dynamic linking symbols | needed entries do |

Stripping removes metadata that is not necessary for execution, reducing size and analyst-friendly names. It does **not** encrypt the instructions, erase imported dynamic functions, or make behavior unrecoverable.

> [!deep-dive] Why stripped binaries still work
> Direct branches already encode destinations or relative displacements. Runtime-required dynamic names remain in dynamic tables. The processor follows addresses, not source names. Analysts reconstruct function boundaries and meaning from entry points, calls, control flow, constants, data references, and behavior.

### Common misunderstanding

**Wrong:** “No symbols means no functions.”

**Correct:** functions still exist as behavioral/code regions; only much of the convenient naming and boundary metadata is gone.

## 1.3 Disassembling objects and executables

Disassembly decodes machine bytes into instruction representations.

```bash
objdump -d -Mintel demo.o
objdump -d -Mintel demo
objdump -dr -Mintel demo.o
```

Object-file output can contain unresolved placeholders and relocation annotations. Executable output reflects final link-time layout but dynamic calls may still go through PLT/GOT machinery.

### Difficult point — code versus data

Bytes do not label themselves as instructions. A disassembler needs candidate code regions and starting addresses. On x86, decoding from the wrong byte can still produce valid-looking instructions because encoding is dense and variable length.

```text
bytes: 48 89 e5 48 83 ec 10
start 0: mov rbp,rsp ; sub rsp,0x10
start 1: mov ebp,esp ; sub rsp,0x10
```

Both decode, but only context, control flow, metadata, and runtime evidence identify the intended stream. Chapter 6 develops this problem fully.

## 1.4 Loading and executing

Launching a dynamically linked ELF broadly involves:

1. the shell calls an execution syscall;
2. the kernel validates the executable format;
3. loadable segments are mapped with specified permissions;
4. zero-fill memory accounts for `p_memsz > p_filesz` (commonly `.bss`);
5. the ELF interpreter/dynamic loader is mapped if requested;
6. shared libraries are located and mapped;
7. relocations and initialization routines are processed;
8. initial stack state carries `argc`, `argv`, environment, and auxiliary vector;
9. control reaches the entry point, normally `_start`, not `main`;
10. runtime startup eventually calls `main` and later handles termination.

**Entry point:** the virtual address where the loader initially transfers control.

**`main`:** a language/runtime convention reached after startup work.

This distinction explains why breaking at the ELF entry does not immediately show C arguments in the `main` calling convention.

## Common mistakes

- Treating preprocessing headers as copied library implementations.
- Assuming one source line maps to one instruction.
- Reading object placeholders as final addresses.
- Equating stripping with obfuscation or encryption.
- Assuming `.text` is what the kernel maps directly; the kernel follows segments.
- Calling the ELF entry point `main` without verifying startup code.

## Chapter in one view

```text
language meaning
 → compiler transformations
 → encoded instructions + symbols + relocations
 → linked executable layout
 → loader mappings and resolution
 → runtime machine state
```

## Practice set

### Questions

1. Why can a call instruction exist in an object file before its destination address is known?
2. What evidence distinguishes an omitted function caused by inlining from one removed as dead code?
3. Why can `.dynsym` survive when `.symtab` is stripped?
4. Compare the ELF entry point and `main`.
5. Compile one function at `-O0` and `-O2`; name three differences and their likely causes.
6. A binary imports `strcmp`. Does that prove it compares a password? Explain.
7. Why is successful x86 decoding insufficient to prove an instruction boundary?
8. Map the responsibilities of compiler, assembler, linker, kernel loader, and dynamic loader.

## Practice question solutions

1. The assembler emits placeholder bytes and a relocation describing the target symbol and patch rule; the linker resolves it after layout.
2. Examine callers and semantics: inlining duplicates the callee’s behavior inside callers; dead-code elimination removes unreachable behavior. Build variants and compiler IR/debug info can strengthen the conclusion.
3. Dynamic resolution still needs selected names and relocation relationships at runtime; full static symbols are not required.
4. The ELF entry is the loader’s first transfer address, usually runtime startup. `main` is called later after initialization with C-level arguments.
5. Typical differences are stack-frame removal, constant folding, register allocation, inlining, and changed control flow. Each must be tied to the actual listing rather than assumed.
6. No. Imports indicate potential capability. The call may compare modes, file extensions, or dead data; inspect reachable xrefs and arguments.
7. Variable-length dense encodings allow multiple valid decodings from different offsets. Control-flow reachability and corroborating evidence establish confidence.
8. Compiler selects/optimizes instructions; assembler encodes and emits relocatable objects; linker resolves/layouts; kernel maps loadable segments; dynamic loader maps libraries and handles dynamic relocations.

## Mastery checklist

- [ ] Explain every stage without collapsing them into “compiler.”
- [ ] Inspect preprocessed, assembly, object, and executable forms of one program.
- [ ] Explain a relocation in an object file.
- [ ] Compare static/dynamic linking and `.symtab`/`.dynsym`.
- [ ] Trace launch from execution syscall to `main`.

## Extended chapter synthesis

### Key ideas

1. Each build stage consumes one representation and produces another with different information resolved.
2. Relocations preserve address relationships that cannot yet be finalized.
3. Execution ultimately follows addresses; humans and linkers benefit from symbolic names.
4. Disassembly is an interpretation of bytes, not unique recovery of original source.
5. Static linking and runtime loading solve different placement/resolution problems.

### Key definitions

- **Translation unit:** preprocessed source consumed by one compilation.
- **Object file:** relocatable machine code/data plus metadata.
- **Relocation:** typed adjustment applied when placement/symbol value becomes known.
- **Entry point:** first virtual control-transfer address specified by the image.
- **Stripped binary:** image with selected nonessential symbol/debug metadata removed.

### Key processes

```text
preprocess → compile → assemble → link
validate image → map segments → load dependencies → relocate/initialize
 → transfer to entry → runtime startup → main
```

### Important examples

- Constant folding changes an expression into `mov eax,11`.
- An unresolved object call becomes final through relocation.
- Stripping removes analyst-friendly names but retains required executable relationships.

### Common confusions

| Confusion | Correct distinction |
|---|---|
| declaration vs implementation | header describes calling contract; library object supplies code |
| object vs executable | object is relocatable; executable has image layout/entry |
| link vs load | linker constructs file relationships; loader constructs runtime state |
| entry vs `main` | entry starts runtime; `main` is called later |
| disassembly vs decompilation | instructions versus higher-level reconstruction |

### What you should be able to explain

- [ ] Why every build stage exists.
- [ ] Why symbols and relocations are related but different.
- [ ] Why optimization breaks simple source/instruction mapping.
- [ ] Why stripping hinders analysis without preventing execution.

### What you should be able to solve

- [ ] Identify which build stage produced an artifact or error.
- [ ] Interpret a simple relocation and linked call.
- [ ] Compare `-O0` and `-O2` without inventing source.
- [ ] Trace the loader/runtime route to `main`.

Full 48-question set with worked solutions: [[Workbooks/Chapter 01 - Practice and Complete Solutions]].
