# Practical Binary Analysis — Study Hub

> [!info] Source
> Dennis Andriesse, *Practical Binary Analysis: Build Your Own Linux Tools for Binary Instrumentation, Analysis, and Disassembly* (460 pages).
>
> PDF: `/home/xtrmn8/books/practicalbinaryanalysis.pdf`

## Purpose

This vault folder records an interactive, mastery-oriented study of the book. The objective is not merely to finish every chapter, but to understand the concepts well enough to explain them, recognize them in real binaries, predict their effects, and use them independently.

## Navigation

- [[01 - Learning Blueprint]]
- [[02 - Source Code to Running Program]]
- [[03 - Executable Formats - ELF and PE]]
- [[04 - Binary Loading and Linux Analysis]]

## Topic map

| Topic | Subject | Note |
|---:|---|---|
| 1 | Symbols and stripped binaries | [[02 - Source Code to Running Program#Topic 1 — Symbols and stripped binaries]] |
| 2 | Disassembling object files and executables | [[02 - Source Code to Running Program#Topic 2 — Disassembling object files and executables]] |
| 3 | Loading and executing a binary | [[02 - Source Code to Running Program#Topic 3 — Loading and executing a binary]] |
| 4 | ELF executable header | [[03 - Executable Formats - ELF and PE#Topic 4 — The ELF executable header]] |
| 5 | ELF sections and section headers | [[03 - Executable Formats - ELF and PE#Topic 5 — ELF sections and section headers]] |
| 6 | ELF program headers and segments | [[03 - Executable Formats - ELF and PE#Topic 6 — ELF program headers and segments]] |
| 7 | Dynamic linking through GOT and PLT | [[03 - Executable Formats - ELF and PE#Topic 7 — Dynamic linking through the GOT and PLT]] |
| 8 | PE format and comparison with ELF | [[03 - Executable Formats - ELF and PE#Topic 8 — The PE format and comparison with ELF]] |
| 9 | Designing a binary loader with libbfd | [[04 - Binary Loading and Linux Analysis#Topic 9 — Designing a binary loader with libbfd]] |
| 10 | Basic Linux binary-analysis workflow | [[04 - Binary Loading and Linux Analysis#Topic 10 — Basic Linux binary-analysis workflow]] |

## Current position

- **Stage:** Binary foundations and executable formats
- **Prepared material:** Topics 1–10
- **Current interactive position:** Quick check at the bottom of [[02 - Source Code to Running Program]]

## Mastery standard

A topic counts as understood when it can be:

1. explained plainly without copying terminology;
2. identified in a real binary or tool output;
3. used to predict the effect of a change;
4. applied in a small practical task;
5. connected to earlier concepts;
6. discussed along with its limitations and common failure cases.

Merely reading a chapter or reproducing a command is not enough.

## Folder convention

Only major subject areas receive separate notes—for example, binary foundations, ELF, disassembly, instrumentation, taint analysis, and symbolic execution. Small concepts, individual commands, exercises, and supporting explanations remain together inside their major-topic note.
