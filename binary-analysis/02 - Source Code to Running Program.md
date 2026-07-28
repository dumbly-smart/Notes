# Source Code to Running Program

This note collects the smaller concepts that make up the major topic of binary foundations.

## Learning objective

Understand how C source becomes an executable binary, how that executable becomes a running process, and why source-level variables may not appear directly in the final machine code.

Consider:

```c
#include <stdio.h>

int main(void) {
    int x = 5;
    printf("%d\n", x + 2);
    return 0;
}
```

The CPU cannot directly understand this C code. It ultimately executes machine instructions encoded as bytes. Converting the source into an executable normally involves four stages:

```text
Source code
   ↓ Preprocessing
Expanded source
   ↓ Compilation
Assembly
   ↓ Assembly
Object file
   ↓ Linking
Executable
```

## 1. Preprocessing

The preprocessor handles directives beginning with `#`, such as:

```c
#include <stdio.h>
#define VALUE 5
```

For `#include <stdio.h>`, it brings in declarations from the header. One important declaration is approximately:

```c
int printf(const char *format, ...);
```

This tells the compiler how `printf` should be called. It does **not** copy the complete implementation of `printf` into the source.

The preprocessor also:

- expands macros;
- processes conditional compilation such as `#ifdef`;
- removes comments;
- produces expanded C source for the compiler.

Observe this stage with:

```bash
gcc -E example.c
```

## 2. Compilation

The compiler translates preprocessed C into assembly language.

A simplified translation of:

```c
int x = 5;
printf("%d\n", x + 2);
```

might conceptually resemble:

```asm
mov esi, 7
lea rdi, [format_string]
call printf
```

Assembly is a human-readable representation of machine instructions. The actual instructions depend on the compiler, architecture, calling convention, and optimization settings.

An optimizing compiler may realize that `5 + 2` is always `7`. Instead of storing `x`, loading it, and performing addition at runtime, it may place `7` directly into a register. This optimization is called **constant folding**.

Request assembly output with:

```bash
gcc -S example.c
```

## 3. Assembly

The assembler converts assembly instructions into machine-code bytes and stores them in an object file:

```bash
gcc -c example.c
```

This creates a file such as:

```text
example.o
```

Suppose an assembly instruction is:

```asm
mov eax, 5
```

The object file contains the binary encoding of that instruction—not the textual words `mov eax, 5`.

An object file also contains organizational information:

- machine code;
- constants and other data;
- sections;
- symbols;
- references that still need resolution;
- relocation information.

It is usually incomplete. For example, `example.o` knows that the program calls `printf`, but the final runtime address of `printf` is not yet known.

## 4. Linking

The linker combines object files and libraries into the final executable:

```bash
gcc example.o -o example
```

It connects references between different pieces of the program.

Our object file effectively says:

> There is a call to `printf` here, but I do not contain `printf`.

The linker arranges for that reference to reach the implementation supplied by the C library. With normal dynamic linking, the complete `printf` implementation is not copied into our executable. Instead, the executable records its dependency on the appropriate shared library, and the dynamic linker resolves it when the program is loaded or first uses the function.

The resulting `example` is normally an ELF executable on Linux.

## A file is not yet a running program

The executable on disk contains code, data, metadata, and instructions describing how it should be loaded.

When we run:

```bash
./example
```

the operating system creates a new process and maps relevant portions of the executable into virtual memory. It also prepares areas such as:

```text
Higher addresses
┌─────────────────────┐
│ Stack               │ local variables and call information
├─────────────────────┤
│ Shared libraries    │ libc and other libraries
├─────────────────────┤
│ Heap                │ dynamic allocations
├─────────────────────┤
│ Program data        │ globals and static variables
├─────────────────────┤
│ Program code        │ machine instructions
└─────────────────────┘
Lower addresses
```

This is a simplified conceptual layout; real layouts vary and use address-space randomization.

The CPU begins executing at the program's **entry point**. This is generally runtime startup code, not `main` itself. The runtime performs initialization and eventually calls `main`.

## Where does `x` exist?

At the C level, `x` is a local variable. Without optimization, the compiler may give it space in the function's stack frame.

But C does not guarantee that a local variable physically lives on the stack. The compiler might:

- store it on the stack;
- keep it in a CPU register;
- eliminate it entirely.

In this example, an optimizing compiler can calculate `x + 2` during compilation. In that case, `x` might have no runtime storage at all.

This distinction is central to binary analysis: source-level ideas do not always correspond neatly to structures in the resulting binary.

## The four representations

| Representation | Meaning |
|---|---|
| Source code | Human-oriented C instructions such as `printf(...)` |
| Assembly | Readable names for CPU instructions, such as `mov` and `call` |
| Machine code | Encoded instruction bytes executed by the CPU |
| Executable binary | A structured file containing machine code, data, and loading metadata |

## Key connections

- The preprocessor understands directives, not the program's runtime behavior.
- The compiler decides how source-level operations map to instructions.
- The assembler encodes those instructions and records unresolved details.
- The linker connects separately produced components.
- The operating system and runtime turn the executable file into a process.
- Optimization can erase the apparent one-to-one relationship between source and machine code.

## Quick check

If the compiler removes `x` and places the value `7` directly into a register:

1. Does `x` still need a location on the stack?
2. Was the calculation `5 + 2` performed while compiling or while running?

Answer in your own words. The reasoning matters more than exact terminology.

---

## Topic 1 — Symbols and stripped binaries

### What is a symbol?

A symbol is a human-meaningful name associated with an address or program entity. Examples include:

- function names such as `main` or `calculate_total`;
- global variables;
- imported functions such as `printf`;
- labels produced during compilation.

At source level, names help humans describe the program. Machine instructions normally operate on addresses, registers, and offsets. Symbol tables preserve a mapping between some of those low-level locations and meaningful names.

Two important ELF symbol tables are:

- `.symtab` — the full symbol table commonly used during linking and debugging;
- `.dynsym` — the smaller dynamic symbol table containing symbols needed for dynamic linking.

`nm` can display symbols:

```bash
nm ./example
nm -D ./example
```

The second command focuses on dynamic symbols.

### Defined and undefined symbols

An object file can contain:

- **defined symbols** — implemented inside the object;
- **undefined symbols** — referenced here but supplied elsewhere.

For example, `main` may be defined in `example.o`, while `printf` is undefined there because its implementation comes from libc. “Undefined” does not necessarily mean broken; before final linking, it often means “the linker must locate this.”

### What stripping does

The `strip` utility removes symbol and debugging information that is not required for normal execution:

```bash
cp example example.stripped
strip example.stripped
```

The stripped file is usually smaller and harder to analyze because descriptive function and variable names disappear. However:

- executable machine code remains;
- runtime-required dynamic symbols generally remain;
- program behavior should remain unchanged;
- imports, strings, control flow, and recognizable patterns still reveal information.

> [!important]
> Stripping removes useful labels, not the program's logic. A stripped binary is harder to understand, not magically unreadable.

### Mental model

```text
Source name: calculate_total
        ↓ compiler/linker records a symbol
Symbol: calculate_total → address 0x401160
        ↓ strip removes optional name
Analyst sees: subroutine at 0x401160
```

### Check

1. Why can a stripped program still run after most symbols have been removed?
2. Why might `printf` remain discoverable even when private function names disappear?

---

## Topic 2 — Disassembling object files and executables

### Disassembly

Disassembly translates machine-code bytes into readable assembly instructions:

```text
Machine bytes             Assembly
55                        push rbp
48 89 e5                  mov rbp, rsp
b8 05 00 00 00            mov eax, 5
```

This is not the reverse of compilation in a perfect sense. Compilation can discard:

- comments;
- source formatting;
- local variable names;
- type information;
- high-level control structures;
- code removed or transformed through optimization.

A disassembler reconstructs instructions, not the original source code.

### Object file versus executable

An object file is relocatable. Its code may use placeholder offsets because final addresses are not known. It also carries relocation entries telling the linker what to repair.

An executable has undergone linking. Its sections, references, imports, and entry point have been arranged for loading, although position-independent executables and shared libraries still involve runtime relocation.

Inspect both with:

```bash
objdump -d example.o
objdump -d example
```

Useful variants include:

```bash
objdump -d -M intel example
objdump -S -M intel example
```

`-M intel` selects Intel syntax. `-S` can intermix source with assembly when debugging information and source are available.

### Why code discovery is difficult

Before decoding instructions, a disassembler must determine which bytes are code. Binary files contain both code and data, and x86 has variable-length instructions. Starting at the wrong byte can produce a different sequence of apparently valid instructions.

This leads to two broad approaches introduced more deeply later:

- **linear disassembly** — decode successive bytes;
- **recursive disassembly** — follow reachable control-flow targets.

Each can miss or misclassify bytes.

### Check

If a disassembler produces valid-looking instructions, does that prove the bytes were intended as executable code? Explain why.

---

## Topic 3 — Loading and executing a binary

### The kernel does not copy the whole file blindly

When an ELF program is executed, the kernel examines its program headers. Loadable segments describe:

- which file bytes should be mapped;
- where they belong in virtual memory;
- their memory size;
- their permissions: read, write, and execute;
- required alignment.

The loader maps code and data into a new process address space. A region such as `.bss` occupies memory even though its zero-initialized bytes do not all need to be stored in the file.

### Entry point versus `main`

The ELF header contains an entry-point address. Execution begins there, usually in a runtime routine named `_start`, not directly in `main`.

A simplified route is:

```text
Kernel loads ELF
      ↓
Dynamic linker resolves runtime dependencies
      ↓
Entry point / _start
      ↓
C runtime initialization
      ↓
main(argc, argv, envp)
      ↓
exit and cleanup
```

### Static and dynamic linking

With **static linking**, library code needed by the program is copied into the executable. The executable is larger and depends less on external libraries at runtime.

With **dynamic linking**, the executable records dependencies on shared libraries. A runtime dynamic linker maps those libraries and resolves required symbols.

Inspect dependencies with:

```bash
ldd ./example
readelf -l ./example
readelf -h ./example
```

> [!warning]
> Avoid using `ldd` on an untrusted executable. Depending on the system and file, examining it this way can be unsafe. Prefer safer static inspection methods such as `readelf -d` when trust is uncertain.

### Process memory is not identical to the file

File offsets and virtual addresses describe different coordinate systems:

- a **file offset** identifies a byte inside the ELF file on disk;
- a **virtual address** identifies a location in the running process;
- a segment mapping explains how a file range becomes a memory range.

Understanding this distinction is essential for patching, debugging, code injection, and interpreting ELF metadata.

### Check,

1. Why does execution usually begin at `_start` rather than `main`?
2. Why can a memory segment be larger than its corresponding range in the file?
