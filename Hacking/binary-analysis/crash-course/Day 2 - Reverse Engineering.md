---
tags: [ctf, reverse-engineering, ghidra, crackme]
day: 2
---

# Day 2 — Reverse Engineering

Back: [[practical-binary-analysis/Practical Binary Analysis - Master Index|Practical Binary Analysis — Complete Companion]]

## Static workflow

1. Identify architecture, imports, strings, sections, and mitigations.
2. Find input sources and success/failure sinks.
3. Follow cross-references toward the validation core.
4. Rename functions and variables immediately.
5. Correct parameter, pointer, array, and structure types.
6. Treat decompiler output as a hypothesis.
7. Verify ambiguous behavior in disassembly or GDB.

Work backward from the success branch and forward from attacker input. Their intersection is often the decisive logic.

## Decompiler traps

The decompiler can infer:

- wrong signedness;
- wrong pointer/array types;
- incorrect function prototypes;
- misleading loop structure;
- merged or split variables;
- expressions hiding truncation and partial-register behavior.

When pseudocode contradicts runtime behavior, inspect the exact instructions and ABI.

## Recognizing code patterns

```asm
mov eax, [rdi+rcx*4]
```

Likely a 4-byte array element at index `rcx`.

```asm
mov rax, [rdi+0x18]
```

Likely an 8-byte structure field at offset `0x18`.

Dense switches often use a bounds check and jump table. Optimized loops may compare a moving pointer with an end pointer. Repeated offsets, access widths, and allocation sizes reveal structure layout.

## Common validation patterns

- XOR/add/subtract/rotate sequences.
- Lookup tables and substitutions.
- Base encodings and hex parsing.
- Checksums and hashes.
- PRNG-driven comparisons.
- State machines and custom bytecode.

Do not label every XOR loop “encryption.” Extract inputs, transformations, state, and output precisely.

## Dynamic confirmation

- `strace`: system calls and files.
- `ltrace`: visible dynamic library calls.
- GDB: exact register and memory state.
- Ghidra: static relationships and decompilation.

Useful experiment:

1. Run with input A and record the comparison state.
2. Run with one-byte-different input B.
3. Observe the first state divergence.
4. Trace backward to the transformation responsible.

Patching a branch can confirm that it controls success, but it does not explain the real accepted input.

## Solver extraction

Translate only decisive logic:

```python
def check(data):
    state = 0x42
    for b in data:
        state = ((state ^ b) + 7) & 0xff
    return state == 0x91
```

Make widths explicit with masks and preserve signedness where relevant.

## Labs

- [ ] Triage an unseen binary in ten minutes.
- [ ] Fully rename/retype one stripped Ghidra project.
- [ ] Recover one structure or array layout.
- [ ] Solve one key-check and one encoding/algorithm crackme.
- [ ] Produce a Python solver and evidence-based write-up.

## Gate

Recover accepted input for an unseen stripped binary in 90 minutes and explain one point where disassembly corrected the decompiler.

Next: [[crash-course/Day 3 - Stack Exploitation]]

