---
tags: [ctf, pwn, automation, seccomp, symbolic-execution]
day: 6
---

# Day 6 — Advanced Pwn, Constraints, and Automation

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Handle an unfamiliar constraint, automate the boring parts, and turn a fragile proof of concept into a dependable exploit.

## Block 1 — Strategy under constraints (90 min)

- [ ] Inventory available read, write, leak, allocation, free, and control primitives.
- [ ] Map each mitigation to the exact part of the naïve chain it blocks.
- [ ] Read a simple seccomp policy and identify permitted syscalls.
- [ ] Understand ORW chains when direct process-spawn paths are unavailable.
- [ ] Recognize when stack pivot, partial overwrite, SROP, or ret2dlresolve may help.

Do not attempt every advanced technique. Select one because the target’s constraints demand it.

## Block 2 — Automated analysis (90 min)

Create or improve a triage helper that reports:

- [ ] architecture and binary format;
- [ ] mitigations;
- [ ] interpreter and dynamic libraries;
- [ ] imports, interesting strings, and sections;
- [ ] likely first debugger breakpoints.

Automation reports evidence; it must not declare a vulnerability without proof.

## Block 3 — Exploit engineering (2 hr)

Refactor the pwntools template:

- [ ] local, GDB, and remote modes;
- [ ] explicit timeouts and synchronized prompt handling;
- [ ] leak validation and address-range assertions;
- [ ] named stages and logging;
- [ ] supplied libc/loader support;
- [ ] no unexplained constants;
- [ ] clean failure instead of hanging.

Run a chosen exploit at least 20 times. Categorize every failure:

- parsing/synchronization;
- address calculation;
- stack alignment;
- environmental mismatch;
- incorrect assumption;
- target nondeterminism.

Fix the cause, not the symptom.

## Block 4 — Solver tools (90 min)

- [ ] Use Z3 for a small system of input constraints.
- [ ] Understand symbolic value, path constraint, and state explosion.
- [ ] Use angr only on a small targeted validation problem.
- [ ] Compare manual, direct-Z3, and symbolic-execution approaches.

## Block 5 — Blind constrained challenge (2–3 hr)

Pick an unseen medium challenge requiring at least two stages or one unfamiliar constraint. Examples:

- seccomp plus ORW;
- PIE leak plus pivot;
- format-string leak feeding a second primitive;
- custom validator best solved with Z3;
- limited gadgets requiring careful side-effect tracking.

## Deliverables

- [ ] Triage helper.
- [ ] Reusable exploit scaffold.
- [ ] 20-run reliability report.
- [ ] One Z3 solver.
- [ ] One constrained blind solve or a rigorous partial analysis.

## Gate

Present an exploit/solver where every stage has an assertion, every runtime address is derived, and the selected technique is justified by target constraints. It must either solve reliably or document the exact remaining blocker with reproducible evidence.

**Result:** [ ] Pass [ ] Repair needed

Next: [[07 - Mock CTF and Final Assessment]]

