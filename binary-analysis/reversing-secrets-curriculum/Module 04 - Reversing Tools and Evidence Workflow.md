---
tags: [reverse-engineering, tools, debugging, curriculum]
source_chapter: 4
---

# Module 4 — Reversing Tools and Evidence Workflow

## Module overview

The historical chapter surveys offline analysis, live debugging, decompilers, monitors, patchers, and executable dumpers. Tool names age; evidence roles endure.

## Tool roles

| Role | Answers | Modern examples |
|---|---|---|
| static disassembler/decompiler | possible code, xrefs, CFG, pseudocode | Ghidra, IDA, Binary Ninja, rizin |
| user debugger | concrete state/control in one process | WinDbg, x64dbg, IDA debugger |
| kernel debugger | OS/driver/kernel state | WinDbg kernel VM setup |
| system monitor | files, registry, process, network behavior | Process Monitor, ETW/Wireshark tools |
| PE dumper | headers/imports/exports/sections | dumpbin, PE-bear, libraries |
| patch/hex tool | controlled experiment on a copy | hex editor/rewriter |

## Dead-listing versus live analysis

Static work has broad potential coverage and low execution risk but uncertain runtime values/indirect targets. Live work gives concrete causality and generated code but only one exercised state and can be detected. Iterate between them.

## Tool-selection algorithm

1. state the question;
2. choose the least invasive view that can answer it;
3. record exact target/tool/version/settings;
4. preserve raw evidence before annotations;
5. cross-check critical claims in another layer;
6. automate repeated collection;
7. export a reproducible report, not only a tool database.

## Patch-as-experiment lab

On a self-built toy, hypothesize that one conditional produces an error. Patch a copy, record old/new bytes and hashes, re-disassemble, run identical input matrix, and restore. The result tests causality; it does not authorize altering third-party software.

## Mastery gate

- [ ] Select tools by question rather than habit.
- [ ] Correlate one system event to code and data origin.
- [ ] Explain static/dynamic/decompiler limitations.
- [ ] Perform and document a reversible patch experiment.
