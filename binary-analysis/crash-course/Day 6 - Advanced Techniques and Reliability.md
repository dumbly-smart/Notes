---
tags: [ctf, pwn, seccomp, z3, reliability]
day: 6
---

# Day 6 — Advanced Techniques and Reliability

Back: [[practical-binary-analysis/Practical Binary Analysis - Master Index|Practical Binary Analysis — Complete Companion]]

## Strategy under constraints

Inventory proven capabilities:

```text
read? write? leak? allocate? free? control RIP? control rsp?
```

Then map mitigations to the exact naïve step they block. Select an advanced technique only because the target demands it.

## Seccomp and ORW

Seccomp filters restrict syscalls. Read the policy instead of assuming a shell is possible. If file syscalls are permitted:

```text
open allowed target → read from returned fd → write to stdout
```

Verify syscall numbers, architecture, file descriptor assumptions, and filter branches.

## Constraint solving

Direct Z3 is suitable for extracted validation equations:

```python
from z3 import *

x = [BitVec(f"x{i}", 8) for i in range(4)]
s = Solver()
for c in x:
    s.add(c >= 0x20, c <= 0x7e)
s.add(x[0] ^ x[1] == 0x12)
s.add(x[2] + x[3] == 0x90)

if s.check() == sat:
    m = s.model()
    print(bytes(m[c].as_long() for c in x))
```

Symbolic execution models program paths, but unconstrained input and environment behavior cause state explosion. Bound input, hook irrelevant functions, and target precise success/failure addresses. Manual reasoning or direct Z3 is often simpler.

## Exploit reliability

- Derive all randomized addresses from leaks.
- Assert page alignment and plausible address ranges.
- Synchronize on exact protocol states.
- Preserve raw binary leak bytes.
- Match binary, loader, and libc.
- Remove timing sleeps that hide parsing bugs.
- Log each stage and calculated base.
- Test fresh processes with ASLR enabled.

| Symptom | Likely investigation |
|---|---|
| crash in `ret`/SIMD code | chain or stack alignment |
| jump to unmapped memory | parsing/base arithmetic |
| works only in GDB | environment/layout assumptions |
| waits forever | wrong delimiter or target awaits input |
| local only | libc/loader/protocol mismatch |
| intermittent heap result | incorrect heap-state assumption |

Debug the first divergence between intended and observed state, not merely the final crash.

## Reusable exploit structure

- Local, `GDB`, and `REMOTE` modes.
- Explicit timeouts.
- Named stages.
- Helpers for parsing and packing.
- Static offsets separated from runtime bases.
- Assertions after every leak.
- Clear failure rather than silent hanging.

## Labs and gate

- [ ] Read one simple seccomp policy and design an ORW chain.
- [ ] Solve one extracted validator with Z3.
- [ ] Add assertions/modes/logging to the exploit scaffold.
- [ ] Run an exploit 20 times and classify every failure.
- [ ] Solve one constrained medium challenge or document a rigorous partial chain.

**Gate:** every stage justified and asserted; all addresses derived; selected technique follows from target constraints.

Next: [[crash-course/Day 7 - Mock CTF and Assessment]]

