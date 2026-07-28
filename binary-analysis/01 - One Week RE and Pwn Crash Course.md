---
aliases: [RE and Pwn Crash Course, Binary Exploitation Crash Course]
tags: [ctf, reverse-engineering, binary-exploitation, curriculum]
status: active
---

# One-Week Reverse Engineering & Binary Exploitation Crash Course

> [!warning]
> Work only on CTFs, wargames, your own lab programs, or targets for which you have explicit permission.

## Goal

Build a practical Linux x86-64 CTF workflow in seven intensive days. Each daily note contains the theory, examples, commands, labs, and a mastery gate. Expect 8–10 focused hours per day.

## Course

| Day | Lesson | Outcome |
|---:|---|---|
| 1 | [[crash-course/Day 1 - C, Assembly, ELF and GDB]] | Read ordinary assembly and debug a stripped ELF |
| 2 | [[crash-course/Day 2 - Reverse Engineering]] | Recover logic and solve stripped crackmes |
| 3 | [[crash-course/Day 3 - Stack Exploitation]] | Prove an overflow and control execution |
| 4 | [[crash-course/Day 4 - ROP and Mitigation Bypass]] | Build a two-stage ret2libc chain |
| 5 | [[crash-course/Day 5 - Format Strings and Heap]] | Create read/write primitives and model heap state |
| 6 | [[crash-course/Day 6 - Advanced Techniques and Reliability]] | Handle constraints and engineer reliable exploits |
| 7 | [[crash-course/Day 7 - Mock CTF and Assessment]] | Demonstrate the complete workflow under time pressure |

## Daily rhythm

| Block | Time |
|---|---:|
| Closed-notes recall | 30 min |
| Read and reproduce lesson examples | 2 hr |
| Guided labs | 2 hr |
| Unseen challenges | 3 hr |
| Write-up and cleanup | 1 hr |
| Stretch/repair | 1–2 hr |

## Required environment

- [ ] Disposable Linux VM or container
- [ ] GCC/Clang, binutils, GDB, Python, Git, `make`
- [ ] Ghidra
- [ ] pwndbg or GEF
- [ ] pwntools, `checksec`, ROPgadget/ropper, patchelf
- [ ] ASLR enabled during final testing

## Universal solve loop

```text
triage → model behavior → prove root cause → inventory primitives
→ account for mitigations → construct chain → test reliability → document
```

### Triage commands

```bash
file ./chall
checksec --file=./chall
readelf -hW ./chall
readelf -lW ./chall
readelf -sW ./chall
readelf -rW ./chall
strings -a -n 4 ./chall
ldd ./chall
```

## Evidence discipline

- **Fact:** directly observed in metadata, instructions, memory, or execution.
- **Hypothesis:** an explanation that still needs a test.
- **Root cause:** the precise violated program invariant.
- **Primitive:** demonstrated capability such as leak, write, allocation control, or RIP control.
- **Chain:** the justified path from root cause to the CTF objective.

## Challenge template

```markdown
# Challenge
## Triage
## Facts
## Hypotheses and tests
## Program model
## Root cause
## Primitives and constraints
## Exploit/solver chain
## Reliability
## Dead ends
## Lessons
```

## Completion checklist

- [ ] All seven daily gates passed
- [ ] Four reverse challenges solved
- [ ] Four stack/ROP challenges solved
- [ ] Two format-string challenges solved
- [ ] Three heap-state labs completed
- [ ] Three exploits succeed 10/10 clean runs
- [ ] Final mock CTF attempted without walkthroughs
- [ ] Every solve has a root-cause explanation

