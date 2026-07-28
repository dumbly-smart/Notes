---
tags: [ctf, pwn, stack-overflow, shellcode, pwntools]
day: 3
---

# Day 3 — Stack Overflows, Shellcode, and Pwntools

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Prove a stack corruption bug, control execution precisely, and package the result as a reproducible pwntools exploit.

## Lesson

Read [[08 - Core Theory Handbook#5. Stack corruption and shellcode]]. Review the ABI chapter before constructing function arguments.

## Schedule

### Block 1 — Root cause to RIP control (2 hr)

- [ ] Understand buffer layout, saved frame pointer, return address, and compiler padding.
- [ ] Distinguish crash, overwrite, and controlled instruction pointer.
- [ ] Generate a cyclic pattern and calculate the exact offset.
- [ ] Inspect the crash with GDB/core file.
- [ ] Account for newline, null bytes, maximum length, and endianness.

Labs:

- [ ] simple `ret2win`;
- [ ] call a target function with controlled arguments;
- [ ] off-by-one or partial overwrite.

### Block 2 — Shellcode (90 min)

- [ ] Linux x86-64 syscall ABI.
- [ ] Position-independent addressing.
- [ ] Null-byte and input restrictions.
- [ ] NX and why injected code may not execute.
- [ ] Assemble/disassemble payloads and explain every instruction.

Write small lab payloads that:

- [ ] print a known message;
- [ ] read a permitted local lab file;
- [ ] execute a benign lab command when the target permits executable memory.

### Block 3 — Pwntools architecture (90 min)

Your exploit must support:

```python
# local process
# GDB launch
# remote host/port
```

- [ ] Set binary context.
- [ ] Use `p64`/`u64`, cyclic helpers, assemblers, and ELF symbols.
- [ ] Parse prompts deterministically.
- [ ] Log offsets and addresses.
- [ ] Separate static offsets from runtime addresses.
- [ ] Avoid unexplained sleeps and magic constants.

### Block 4 — Mitigation experiments (90 min)

Compile one vulnerable target in several configurations:

- no canary/no PIE/executable stack;
- NX enabled;
- canary enabled;
- PIE enabled;
- partial and full RELRO.

For each:

- [ ] predict what breaks;
- [ ] confirm with `checksec`;
- [ ] observe address changes;
- [ ] state the new primitive required.

### Block 5 — Blind pwn (2–3 hr)

Solve one unseen beginner stack challenge from triage to working script. Test from a clean process ten times.

## Deliverables

- [ ] Three controlled-overwrite labs.
- [ ] Explained shellcode samples.
- [ ] Reusable pwntools skeleton.
- [ ] Blind challenge exploit and root-cause write-up.

## Gate

On an unseen non-PIE beginner target, find the overflow offset without guessing, redirect control to the intended goal, and achieve 10/10 clean runs.

**Result:** [ ] Pass [ ] Repair needed

Next: [[04 - ROP, Leaks, and Mitigations]]
