---
aliases:
  - One-Week RE and Pwn Crash Course
tags: [ctf, reverse-engineering, binary-exploitation, crash-course]
status: active
---

# One-Week Reverse Engineering & Binary Exploitation Crash Course

> [!warning]
> Use these techniques only in CTFs, wargames, your own lab, or systems where you have explicit permission.

## Mission

This is a seven-day, high-intensity Linux x86-64 CTF sprint. It will not make anyone omniscient in a week; it will build the strongest practical foundation possible and a repeatable solve process.

**Time:** 8–10 focused hours/day  
**Rule:** Do not advance without completing the daily gate.  
**Output:** Every day ends with working artifacts, not only reading.

## Course navigation

| Day | Focus | Required result |
|---:|---|---|
| 1 | [[01 - Foundations and Assembly]] | Read functions and navigate a binary in GDB |
| 2 | [[02 - Reverse Engineering Workflow]] | Solve two stripped crackmes |
| 3 | [[03 - Stack Overflows and Shellcode]] | Control RIP and build a working exploit |
| 4 | [[04 - ROP, Leaks, and Mitigations]] | Defeat NX and ASLR with a two-stage chain |
| 5 | [[05 - Format Strings and Heap Foundations]] | Build read/write primitives and explain heap state |
| 6 | [[06 - Advanced Pwn and Automation]] | Solve a constrained target with a reliable script |
| 7 | [[07 - Mock CTF and Final Assessment]] | Complete a timed mixed mini-CTF |

## Daily operating rhythm

| Block | Duration | Activity |
|---|---:|---|
| Recall | 30 min | Closed-notes review and assembly tracing |
| Concepts | 90 min | Learn only what today’s labs require |
| Guided labs | 2 hr | Controlled experiments |
| Blind challenges | 3 hr | Unseen CTF problems |
| Review | 1 hr | Write-up and exploit cleanup |
| Stretch | 1–2 hr | Harder challenge or failed-gate repair |

Use 50/10 focus cycles. After 90 minutes stuck, write down facts, hypotheses, and the smallest missing fact before taking a hint.

## Lab setup

- [ ] Use a disposable Linux VM/container.
- [ ] Install GCC/Clang, binutils, GDB, Python, Git, and `make`.
- [ ] Install Ghidra.
- [ ] Install one GDB enhancement: pwndbg, GEF, or PEDA.
- [ ] Install pwntools, `checksec`, ROPgadget or ropper, and patchelf.
- [ ] Create a Git repository for scripts and write-ups.
- [ ] Confirm ASLR status with `cat /proc/sys/kernel/randomize_va_space`.
- [ ] Never run unknown binaries outside the disposable lab.

## Canonical solve loop

```text
triage → map behavior → prove root cause → inventory primitives
→ account for mitigations → build chain → make reliable → document
```

### Triage

```bash
file ./chall
checksec --file=./chall
readelf -hW ./chall
readelf -lW ./chall
readelf -sW ./chall
strings -a -n 4 ./chall
```

Record:

- architecture, format, interpreter, libraries, and mitigations;
- input channel and restrictions;
- interesting strings/imports;
- attacker-controlled data and where it is used.

## Evidence rules

- **Fact:** directly observed in code, metadata, or execution.
- **Hypothesis:** plausible explanation awaiting a test.
- **Primitive:** capability demonstrated reliably, such as leak, write, or RIP control.
- **Exploit chain:** every transition from bug to objective, including mitigation bypasses.

Never write “probably vulnerable” when a debugger experiment can prove it.

## Challenge note template

```markdown
# Challenge

## Triage
- Architecture:
- Mitigations:
- Inputs:
- Interesting imports/strings:

## Facts

## Hypotheses and tests

## Root cause

## Primitives and constraints

## Exploit or solver chain

## Reliability

## Dead ends

## Lesson
```

## Course scoreboard

| Metric | Target | Result |
|---|---:|---:|
| Functions hand-traced | 20 | 0 |
| Crackmes solved | 4 | 0 |
| Stack pwn solved | 4 | 0 |
| ROP/ret2libc solved | 2 | 0 |
| Format-string solved | 2 | 0 |
| Heap labs completed | 3 | 0 |
| Blind challenges without hints | 7 | 0 |
| Reliable exploits tested 10/10 | 3 | 0 |
| Clean write-ups | 7 | 0 |

## Completion standard

The course is complete only when:

- [ ] all seven daily gates pass;
- [ ] every exploit runs from a clean start;
- [ ] at least three exploits succeed 10 consecutive times;
- [ ] the final mock CTF is attempted without walkthroughs;
- [ ] every solved challenge has a concise root-cause explanation;
- [ ] a post-course weakness list and next practice plan exist.

