---
aliases: [Secrets of Reverse Engineering Curriculum, Reversing Mastery Curriculum]
tags: [reverse-engineering, curriculum, windows, ia32, index]
source: Eldad Eilam — Reversing: Secrets of Reverse Engineering (2005)
---

# Reversing: Secrets of Reverse Engineering — Separate Mastery Curriculum

> [!warning] Historical and legal context
> The book’s Windows internals, tools, protection examples, and legal discussion reflect its 2005 publication context. Learn the enduring concepts, reproduce only authorized lab exercises, and verify current platform behavior and applicable law independently. The curriculum uses benign `LAB_SUCCESS` objectives instead of bypassing real commercial protections.

## Purpose

This is separate from [[../practical-binary-analysis/Practical Binary Analysis - Master Index|Practical Binary Analysis]]. The PBA route emphasizes Linux ELF, custom analysis, instrumentation, taint, and symbolic execution. This route emphasizes IA-32 compiler patterns, Windows internals/tools, systematic code/data reconstruction, undocumented-interface/file-format case studies, malware/anti-reversing concepts, .NET, and decompiler theory.

```text
Foundation knowledge
 → observe whole-system behavior
 → read compiler-generated IA-32
 → reconstruct APIs, structures, files, and protocols
 → audit security properties and hostile code
 → defeat analysis obstacles in authorized labs
 → reason about managed code and decompilation
 → perform independent capstone investigations
```

## Book structure and curriculum modules

### Part I — Reversing 101

1. [[Module 01 - Foundations and the Reversing Process]]
2. [[Module 02 - Low-Level Software and Compiler Patterns]]
3. [[Module 03 - Windows Fundamentals for Reversers]]
4. [[Module 04 - Reversing Tools and Evidence Workflow]]

### Part II — Applied Reversing

5. [[Module 05 - Undocumented APIs and Data Structures]]
6. [[Module 06 - Deciphering File Formats and Protocols]]
7. [[Module 07 - Auditing Program Binaries]]
8. [[Module 08 - Malware Reversing in an Isolated Lab]]

### Part III — Cracking and Anti-Reversing

9. [[Module 09 - Protection Technology and Threat Modeling]]
10. [[Module 10 - Anti-Reversing Techniques]]
11. [[Module 11 - Authorized Protection Analysis]]

### Part IV — Beyond Disassembly

12. [[Module 12 - Reversing Managed .NET Code]]
13. [[Module 13 - Decompilation Theory and Practice]]
14. [[Appendix Lab - Code Structures, Arithmetic, and Program Data]]

## 28-week professional progression

| Phase | Weeks | Outcome | Required artifact |
|---|---:|---|---|
| Orientation and ethics | 1 | define lawful scope and evidence discipline | rules-of-engagement template |
| IA-32 fluency | 2–5 | read calls, frames, branches, loops, structures | 25 annotated functions |
| Windows model | 6–8 | reason about processes, memory, handles, API/native boundary | process/memory map report |
| Tool fluency | 9–10 | combine dead-listing, debugger, monitoring, patch copies | reproducible triage notebook |
| Reconstruction | 11–15 | recover undocumented API and file/protocol structures | clean-room spec + parser |
| Security analysis | 16–18 | identify root cause and primitive in labs | three vulnerability reports |
| Hostile-code analysis | 19–21 | unpack and analyze samples safely | behavior/IOC/CFG report |
| Anti-analysis | 22–23 | recognize and neutralize toy checks | annotated countermeasure matrix |
| Managed/decompiler | 24–25 | reverse IL and critique decompiler output | native/managed comparison |
| Capstone | 26–28 | independently reverse an unseen authorized target | full professional report/tooling |

## Weekly operating rhythm

```text
Day 1: concepts + closed-notes explanation
Day 2: reproduce book pattern on tiny source-built examples
Day 3: strip/optimize/change compiler; reverse without source
Day 4: focused debugger/system-monitor experiment
Day 5: unseen challenge and evidence report
Day 6: tool/script improvement and spaced review
Day 7: rest or mastery repair
```

## The reversing loop

```text
scope and isolate
 → identify representations and runtime boundary
 → establish observable behavior
 → choose one precise question
 → static slice from clue/sink
 → dynamic discriminating experiment
 → name types/functions from evidence
 → reconstruct invariant/algorithm/interface
 → test competing hypotheses and edge cases
 → document confidence and unknowns
```

## Graduation standard

You graduate only when you can independently:

- [ ] read ordinary optimized IA-32/x86-64 code and explain flags/signedness/ABI;
- [ ] recover functions, loops, switches, objects, lists, and callbacks without symbols;
- [ ] derive a Windows process/memory/API model from evidence;
- [ ] specify an undocumented file format or API and implement an interoperable clean-room client/parser;
- [ ] unpack an authorized toy and reconstruct meaningful code/data;
- [ ] audit binary input-to-sink paths and report root cause/primitive accurately;
- [ ] recognize debugger detection, opaque predicates, data/control transformations, and managed obfuscation;
- [ ] critique decompiler output using CFG, SSA/data flow, and concrete execution;
- [ ] build small automation for naming, trace normalization, structure inference, or coverage;
- [ ] produce a report another analyst can reproduce from hashes and commands.

## Portfolio requirements

1. Ten micro-pattern notebooks: loop, switch, recursion, list, virtual call, exception, arithmetic optimization, string routine, callback, state machine.
2. Two clean-room interoperability specifications.
3. Three binary vulnerability assessments with fixed regression labs.
4. One isolated malware-like toy unpacking/behavior report.
5. One anti-analysis toy and documented neutralization.
6. One managed .NET reversing comparison.
7. One final unseen capstone with scripts, annotated database, CFG/data model, uncertainty register, and executive summary.

## Supporting deep guides

- [[Secrets of Reversing - Field Method]] — the daily evidence and hypothesis discipline
- [[../practical-binary-analysis/Build Guide - Static Disassembler]]
- [[../practical-binary-analysis/Build Guide - Dynamic Disassembler]]
- [[../practical-binary-analysis/Authorized Binary Exploitation Guide]]
- [[Professional Reverser - 100 Lab and Assessment Roadmap]]
