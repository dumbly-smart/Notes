---
tags: [ctf, pwn, format-string, heap, glibc]
day: 5
---

# Day 5 — Format Strings and Heap Foundations

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Construct format-string read/write primitives and reason accurately about basic glibc heap state.

## Block 1 — Format-string mechanics (90 min)

- [ ] Explain why attacker-controlled format strings expose variadic arguments.
- [ ] Map argument positions with controlled markers.
- [ ] Leak stack, binary, canary, and library values.
- [ ] Use field widths and `%n` family writes.
- [ ] Understand byte/short writes and modular padding.

### Format-string labs (2 hr)

- [ ] Discover the controlled argument offset.
- [ ] Leak a chosen address with a positional read.
- [ ] Write a chosen byte/short to a lab target.
- [ ] Build a multi-write payload and verify every change.
- [ ] Solve one target with a leak and one target with a write.

State clearly why full RELRO blocks GOT replacement but does not remove the arbitrary-write primitive.

## Block 2 — Heap mental model (2 hr)

> [!important]
> Heap techniques depend on the exact allocator version. Record the libc build before reasoning about metadata, bins, hooks, or hardening.

- [ ] Draw allocated and freed chunk layout.
- [ ] Understand alignment, size metadata, top chunk, and neighboring chunks.
- [ ] Trace `malloc`, `free`, `calloc`, and `realloc`.
- [ ] Learn tcache, fastbin, unsorted-bin, and consolidation concepts.
- [ ] Understand heap overflow, use-after-free, double free, and dangling pointers.

For each operation, draw:

```text
request → returned pointer → chunk size → in-use/free state → bin/freelist links
```

### Heap labs (2 hr)

Use small purpose-built programs:

- [ ] UAF: allocate, free, reallocate same-size object, observe stale alias.
- [ ] Double-free defense: trigger it and identify the allocator check.
- [ ] Overflow: corrupt an adjacent object field without attempting a complex chain.
- [ ] Tcache: observe LIFO reuse and encoded linkage in the installed libc.

### Primitive-first reasoning (60 min)

For each bug, answer:

1. What invariant is violated?
2. What allocator/program state is required?
3. What can be read, written, overlapped, or reallocated?
4. What hardening check prevents the simplest attack?
5. What additional leak or primitive would be required?

## Deliverables

- [ ] Two format-string exploit scripts.
- [ ] Four heap-state diagrams.
- [ ] Exact libc version recorded.
- [ ] Root-cause/primitives table for four heap bug classes.

## Gate

Demonstrate a controlled format-string leak and write without payload guessing. Then explain, from a debugger heap trace, why a freed allocation is reused and how a UAF could become type confusion or a controlled pointer.

**Result:** [ ] Pass [ ] Repair needed

Next: [[06 - Advanced Pwn and Automation]]

