---
tags: [ctf, reverse-engineering, ghidra, crackme]
day: 2
---

# Day 2 — Reverse Engineering Workflow

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Turn a stripped binary into a defensible program model and solver using static and dynamic evidence.

## Lesson

Read [[08 - Core Theory Handbook#4. Static and dynamic reversing]]. Keep it open while performing the first guided analysis.

## Schedule

### Block 1 — Fast triage (60 min)

- [ ] Run the canonical metadata checks.
- [ ] List imports, strings, input paths, comparison functions, and success/failure sinks.
- [ ] Form three ranked hypotheses.
- [ ] Identify the smallest experiment that could disprove each.

### Block 2 — Ghidra workflow (2 hr)

- [ ] Find entry, `main`, and meaningful user code.
- [ ] Use cross-references, call graph, and control-flow graph.
- [ ] Rename functions and variables immediately.
- [ ] Correct parameter, return, pointer, array, and struct types.
- [ ] Treat decompiler output as a hypothesis; confirm ambiguous behavior in disassembly.
- [ ] Work backward from the success sink and forward from controlled input.

Read: [[06 - Static Disassembly Strategies]]

### Block 3 — Recover data and algorithms (2 hr)

- [ ] Recognize loops, switches, jump tables, arrays, structs, and state machines.
- [ ] Identify XOR, rotations, lookup tables, base encodings, hashes/checksums, and PRNG patterns.
- [ ] Recover structure fields from repeated offsets and allocation sizes.
- [ ] Extract only decisive logic into Python.

Lab: compile small validators with GCC and Clang at multiple optimization levels, strip them, then recover the original intent.

### Block 4 — Dynamic confirmation (90 min)

- [ ] Break on input, comparison, and success/failure.
- [ ] Use watchpoints to trace a transformed value.
- [ ] Compare two executions with different input.
- [ ] Patch a conditional branch only to test a hypothesis, then explain the real condition.

### Block 5 — Blind challenge set (3 hr)

Solve:

- [ ] one stripped password/key-check crackme;
- [ ] one challenge using an encoding, lookup table, or nontrivial validation loop.

For each, spend at least 60 minutes before hints.

## Deliverables

- [ ] Renamed and retyped Ghidra project.
- [ ] Recovered pseudocode independent of decompiler mistakes.
- [ ] Python keygen/solver where appropriate.
- [ ] Two clean challenge notes separating facts from hypotheses.

## Gate

Given an unseen stripped binary, recover its decisive validation logic and produce accepted input within 90 minutes. Explain at least one place where raw disassembly was more trustworthy than the decompiler.

**Result:** [ ] Pass [ ] Repair needed

Next: [[03 - Stack Overflows and Shellcode]]
