---
tags: [ctf, pwn, rop, ret2libc, aslr]
day: 4
---

# Day 4 — ROP, Leaks, and Mitigation Bypass

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Build and debug a two-stage ROP/ret2libc exploit that defeats NX and randomized library addresses.

## Schedule

### Block 1 — ROP mechanics (2 hr)

- [ ] Understand gadgets as instruction sequences ending in control transfer.
- [ ] Satisfy the System V calling convention.
- [ ] Track `rsp` after every gadget.
- [ ] Account for gadget side effects and stack alignment.
- [ ] Find gadgets manually, then verify with ROPgadget/ropper.

Lab chain:

```text
overflow → pop argument → imported function → safe re-entry
```

### Block 2 — Leaks and base calculations (2 hr)

- [ ] Leak a GOT entry through an imported output function.
- [ ] Parse short leaks safely and pad before unpacking.
- [ ] Calculate `libc_base = leaked_symbol - symbol_offset`.
- [ ] Derive target function/string addresses from the base.
- [ ] Validate that calculated addresses fall inside expected mappings.

Write every address as:

```text
runtime address = randomized base + stable offset
```

### Block 3 — Two-stage ret2libc (2 hr)

Stage 1:

```text
leak libc address → return to vulnerable input
```

Stage 2:

```text
alignment if needed → target function → controlled argument
```

- [ ] Test with ASLR enabled.
- [ ] Explain why NX is irrelevant to ROP.
- [ ] Explain why PIE may require a binary leak too.
- [ ] Diagnose a crashing library call as a possible alignment issue.

### Block 4 — Mitigation strategy table (60 min)

| Mitigation | What it blocks | Common required response |
|---|---|---|
| NX | injected executable stack code | code reuse or permitted executable region |
| ASLR | fixed runtime addresses | information leak or justified partial overwrite |
| PIE | fixed main-binary base | leak binary pointer/base |
| Canary | simple return-address overwrite | leak/preserve canary or use another bug |
| Full RELRO | GOT overwrite | alternate control target/ROP |

Do not memorize the response as universal; reason from available primitives.

### Block 5 — Blind challenge (2–3 hr)

Solve one NX+ASLR target requiring a leak and second-stage chain. If a matching libc/loader is supplied, reproduce the intended environment and record exact versions.

## Stretch topics

- stack pivots;
- ret2csu-style sequences;
- SROP;
- ret2dlresolve;
- ORW chains under seccomp.

Study these only after the required exploit is reliable.

## Deliverables

- [ ] Gadget-by-gadget stack diagram.
- [ ] Leak parsing helper.
- [ ] Reliable two-stage exploit.
- [ ] Mitigation-to-strategy explanation.

## Gate

Exploit an unseen NX+ASLR challenge using a leak and ROP/ret2libc. The exploit must calculate all randomized addresses, contain assertions, and succeed 10 consecutive times.

**Result:** [ ] Pass [ ] Repair needed

Next: [[05 - Format Strings and Heap Foundations]]

