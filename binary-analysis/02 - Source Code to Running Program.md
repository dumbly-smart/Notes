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
