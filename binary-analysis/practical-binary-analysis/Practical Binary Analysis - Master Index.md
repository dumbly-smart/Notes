---
aliases: [PBA Companion, Practical Binary Analysis Notes]
tags: [binary-analysis, reverse-engineering, study-notes, index]
source: Dennis Andriesse — Practical Binary Analysis (2019)
---

# Practical Binary Analysis — Complete Companion

> [!warning] Lab scope
> Modification, instrumentation, vulnerability research, and exploitation exercises are for binaries you own or are explicitly authorized to test. Run unknown samples only inside an isolated, disposable environment.

## How to use this companion

These notes follow the book’s intellectual progression rather than grouping unrelated topics into generic cheat sheets. Each chapter separates:

- **Book concept** — the author’s idea and sequence;
- **Added explanation** — extra mental models and edge cases;
- **Added example/lab** — original exercises for understanding;
- **Practice** — questions followed later by worked answers.

Recommended loop:

```text
read overview → study one section → reproduce examples → answer without notes
→ check solutions → run the lab → explain the idea aloud → continue
```

## Book map

```text
Part I — representation
source → object → ELF/PE → normalized loader
                       ↓
Part II — observation and modification
Linux tools → disassembly/analysis → code injection
                       ↓
Part III — automation
custom disassembly → instrumentation → taint → symbolic execution
                       ↓
Applications
reverse engineering, unpacking, vulnerability discovery, exploit generation
```

## Chapter notes

### Part I — Binary Formats

1. [[Chapter 01 - Anatomy of a Binary]]
2. [[Chapter 02 - The ELF Format]]
3. [[Chapter 03 - The PE Format]]
4. [[Chapter 04 - Building a Binary Loader with libbfd]]

### Part II — Binary Analysis Fundamentals

5. [[Chapter 05 - Basic Binary Analysis in Linux]]
6. [[Chapter 06 - Disassembly and Analysis Fundamentals]]
7. [[Chapter 07 - ELF Code Injection]]

### Part III — Advanced Binary Analysis

8. [[Chapter 08 - Customizing Disassembly with Capstone]]
9. [[Chapter 09 - Binary Instrumentation]]
10. [[Chapter 10 - Dynamic Taint Analysis Principles]]
11. [[Chapter 11 - Practical Taint Analysis with libdft]]
12. [[Chapter 12 - Symbolic Execution Principles]]
13. [[Chapter 13 - Practical Symbolic Execution with Triton]]

### Appendices and synthesis

- [[Appendices - x86, ELF Injection, Tools, and Reading]]
- [[Book Synthesis - Maps, Definitions, Comparisons, and Mastery]]

## Practical build and vulnerability tracks

- [[Build Guide - Static Disassembler]] — create an ELF-aware recursive disassembler and CFG builder
- [[Build Guide - Dynamic Disassembler]] — create a ptrace-based execution tracer, then scale to DBI
- [[Authorized Binary Exploitation Guide]] — root cause to primitive to mitigation-aware lab exploitation

## Complete practice workbooks

Every chapter has exactly 48 nonrepetitive chapter questions—10 recall, 10 conceptual, 10 application, 5 multi-step, 5 challenging, 5 misconception, and 3 case-based—followed by worked solutions.

1. [[Workbooks/Chapter 01 - Practice and Complete Solutions]]
2. [[Workbooks/Chapter 02 - Practice and Complete Solutions]]
3. [[Workbooks/Chapter 03 - Practice and Complete Solutions]]
4. [[Workbooks/Chapter 04 - Practice and Complete Solutions]]
5. [[Workbooks/Chapter 05 - Practice and Complete Solutions]]
6. [[Workbooks/Chapter 06 - Practice and Complete Solutions]]
7. [[Workbooks/Chapter 07 - Practice and Complete Solutions]]
8. [[Workbooks/Chapter 08 - Practice and Complete Solutions]]
9. [[Workbooks/Chapter 09 - Practice and Complete Solutions]]
10. [[Workbooks/Chapter 10 - Practice and Complete Solutions]]
11. [[Workbooks/Chapter 11 - Practice and Complete Solutions]]
12. [[Workbooks/Chapter 12 - Practice and Complete Solutions]]
13. [[Workbooks/Chapter 13 - Practice and Complete Solutions]]

## Separate companion curriculum

Continue with [[../reversing-secrets-of-reverse-engineering/Reversing - Complete Book Companion|Reversing: Secrets of Reverse Engineering — Complete Book Companion]] for chapter-by-chapter Windows/IA-32 reversing, paired C/assembly laboratories, undocumented APIs, formats, vulnerability auditing, malware/anti-analysis, Ghidra with GDB/pwndbg, .NET, and decompilation.

## Mastery milestones

| Stage | You can do |
|---|---|
| Foundations | explain compilation, symbols, ELF/PE structures, and runtime loading |
| Manual analysis | identify a binary, trace behavior, recover functions/CFG/data flow |
| Modification | patch or inject into a copy while preserving executable invariants |
| Tool building | parse binaries, disassemble, instrument, and collect structured results |
| Advanced analysis | define taint policies and solve bounded path constraints |
| Security assessment | connect attacker input to a violated invariant and justified impact |

## Evidence standard

Use these labels throughout your own notes:

| Label | Standard |
|---|---|
| Fact | directly observed in bytes, metadata, instructions, memory, or execution |
| Inference | best explanation of facts, with reasoning stated |
| Hypothesis | unconfirmed claim paired with a discriminating test |
| Unknown | missing fact that limits the conclusion |

The point is not merely to obtain an answer. It is to produce an explanation another analyst can reproduce.
