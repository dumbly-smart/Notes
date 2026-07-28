---
tags: [ctf, pwn, format-string, heap, glibc]
day: 5
---

# Day 5 — Format Strings and Heap Foundations

Back: [[01 - One Week RE and Pwn Crash Course]]

## Format-string root cause

Safe:

```c
printf("%s", user_input);
```

Vulnerable:

```c
printf(user_input);
```

The vulnerable form interprets attacker input as directives. Variadic calls do not give `printf` reliable argument type/count metadata, so conversions can consume register-save-area or stack values not intended as arguments.

## Read primitive

- `%p` exposes pointer-sized values.
- `%7$p` selects a positional argument.
- `%s` treats an argument as a pointer and dereferences it; invalid pointers may crash.

Use controlled marker bytes to discover which argument position contains input. Classify leaks as stack, PIE, canary, or libc using mappings and value shape.

## Write primitive

`%n` writes the number of characters printed:

- `%hhn`: byte;
- `%hn`: two bytes;
- `%n`: usually four bytes;
- `%ln`: long-sized.

Padding is modular. For byte writes, make the low byte of the printed count equal the desired byte. Order multiple writes to minimize wraparound.

```python
payload = fmtstr_payload(offset, {target: value}, write_size="short")
```

First implement one manual write so the helper is understandable. Full RELRO blocks GOT overwrite, not the underlying format-string write.

## Heap mental model

The allocator returns aligned user space inside a chunk whose surrounding state includes allocator metadata. Freed chunks may enter size-class caches/bins.

```text
free(A) → tcache[size]: A
free(B) → tcache[size]: B → A
malloc(size) returns B
```

Bug classes:

- heap overflow: crosses into adjacent object or metadata;
- use-after-free: stale pointer used after lifetime ends;
- double free: same allocation identity released twice;
- invalid free: non-chunk/non-live pointer released.

A UAF becomes useful when a stale pointer aliases a replacement object. If old code interprets replacement bytes as a pointer, size, or callback, type confusion can yield a read, write, or control primitive.

## Version dependence

Record the exact libc build. Tcache behavior, safe-linking, double-free checks, hooks, bins, and viable targets change across releases. Named techniques are version-specific case studies.

After every heap action, answer:

1. Which chunk and real size?
2. Allocated or free?
3. Which bin/cache contains it?
4. Which program pointers still reference it?
5. What changes on the next allocator operation?
6. Which hardening check will run?

## Labs and gate

- [ ] Discover a format-string argument offset.
- [ ] Produce a controlled leak.
- [ ] Produce a byte/short write.
- [ ] Trace tcache reuse in GDB.
- [ ] Demonstrate UAF aliasing and draw four heap states.

**Gate:** explain and demonstrate one format read/write primitive, then explain heap reuse from exact allocator state without relying on a memorized technique.

Next: [[crash-course/Day 6 - Advanced Techniques and Reliability]]

