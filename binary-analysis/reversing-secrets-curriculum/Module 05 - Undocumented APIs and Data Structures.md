# Module 5 — Undocumented APIs and Data Structures

## Purpose

Follow the book’s generic-table case study to learn clean-room interface recovery: infer calling convention, callbacks, tree/list structure, invariants, and source-equivalent behavior without mistaking reconstructed code for historical source.

```text
find candidate export/caller → observe arguments/returns → map helper calls
→ recover node fields and traversal → test edge cases → publish specification
```

Study `RtlInitializeGenericTable`, element count/empty/get, insertion helpers, lookup, deletion, and splay-tree behavior in the book’s order. For each, maintain a table of argument hypothesis, evidence, side effects, error cases, and confidence.

### Lab

Reverse an authorized undocumented toy collection library. Reconstruct comparator/allocator callbacks, node layout, ordering invariant, insert/lookup/delete behavior, then implement an independent compatible client. Test empty, singleton, duplicate, sorted/reverse/random, deletion, and allocation failure.

### Mastery gate

- [ ] Recover an interface from at least three callers.
- [ ] Draw and validate the data structure after every mutation.
- [ ] Distinguish semantic specification from guessed original source.
