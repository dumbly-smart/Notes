# Reverse Engineering & Binary Exploitation — Study Hub

> [!info] Source
> Dennis Andriesse, *Practical Binary Analysis: Build Your Own Linux Tools for Binary Instrumentation, Analysis, and Disassembly* (460 pages).
>
> PDF: `/home/xtrmn8/books/practicalbinaryanalysis.pdf`

## Purpose

This folder contains the active CTF learning route plus supporting notes from *Practical Binary Analysis*. Start with the one-week crash course; use the book notes for additional depth.

## Navigation

- [[nightmare-complete/Nightmare Course - Complete Solutions|Nightmare — Complete CTF solutions]]
- [[01 - One Week RE and Pwn Crash Course]]
- [[02 - Source Code to Running Program]]
- [[03 - Executable Formats - ELF and PE]]
- [[04 - Binary Loading and Linux Analysis]]
- [[05 - x86-64 Assembly for Binary Analysis]]
- [[06 - Static Disassembly Strategies]]
- [[07 - Reverse Engineering Field Manual]] — the complete, repeatable workflow for understanding an unfamiliar binary
- [[08 - Binary Vulnerability Analysis Field Manual]] — the complete workflow for finding, validating, and reporting vulnerabilities

## Choose your field manual

| Goal | Start here | Finished when |
|---|---|---|
| Understand what a binary does | [[07 - Reverse Engineering Field Manual]] | Inputs, outputs, algorithms, control/data flow, evidence, and unknowns are documented |
| Find and assess vulnerabilities | [[08 - Binary Vulnerability Analysis Field Manual]] | Root cause, attacker control, primitive, real mitigations, impact, fix, and regression tests are documented |

The field manuals are self-contained operational routes. The numbered foundation notes provide slower, concept-level explanations when a step needs more depth; the crash course and Nightmare material provide practice targets.

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
| 11 | x86-64 assembly for binary analysis | [[05 - x86-64 Assembly for Binary Analysis]] |
| 12 | Static disassembly strategies | [[06 - Static Disassembly Strategies]] |

## Current position

- **Course:** [[01 - One Week RE and Pwn Crash Course]]
- **Stage:** Day 1 — C, assembly, ELF, and GDB
- **Prepared material:** Topics 1–12
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

## Curriculum quality standard

Future material should be advanced but teachable. Major-topic notes should include:

- a precise mental model before tool usage;
- connections between source, assembly, executable metadata, and runtime behavior;
- worked examples with explicit reasoning;
- practical experiments and progressively harder exercises;
- compiler, ABI, optimization, and security implications;
- common mistakes and misleading interpretations;
- confidence boundaries separating observation from inference;
- a mastery check that requires explanation and application.

Commands should answer analytical questions rather than appear as isolated reference lists.

## Folder convention

Only major subject areas receive separate notes—for example, binary foundations, ELF, disassembly, instrumentation, taint analysis, and symbolic execution. Small concepts, individual commands, exercises, and supporting explanations remain together inside their major-topic note.
