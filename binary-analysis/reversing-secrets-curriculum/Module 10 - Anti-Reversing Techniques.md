# Module 10 — Anti-Reversing Techniques

## Purpose

Study symbol removal, code encryption, debugger detection, trap/timing/checksum tricks, disassembler confusion, obfuscation, opaque predicates, table interpretation, inlining/outlining/interleaving, and data transformations.

For each technique record: protected assumption, observable artifact, which tool/view it attacks, bypass experiment in a toy, false positives, and cost to developer/runtime.

### Lab ladder

1. Add a debugger-presence check to a toy and neutralize only in a copy.
2. Add checksum validation and identify the checked range.
3. Insert jump-over-data to compare linear/recursive disassembly.
4. Add always-true opaque predicates and prove them with concrete tests/bitvectors.
5. Encode a structure’s fields and recover invariant/decoder.

### Mastery gate

- [ ] Identify the attacked analysis assumption.
- [ ] Preserve original behavior while removing a toy obstacle.
- [ ] Explain why every countermeasure is contextual, not universal.
