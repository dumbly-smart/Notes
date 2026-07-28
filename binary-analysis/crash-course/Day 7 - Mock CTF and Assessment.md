---
tags: [ctf, assessment, reverse-engineering, binary-exploitation]
day: 7
---

# Day 7 — Mock CTF and Final Assessment

Back: [[01 - One Week RE and Pwn Crash Course]]

## Six-hour mock CTF

Choose unseen legal archived tasks:

- [ ] Easy stripped key-check reverse.
- [ ] Medium algorithm/encoding reverse.
- [ ] Easy stack pwn.
- [ ] Medium NX+ASLR ROP pwn.
- [ ] Format-string or beginner heap stretch task.

Rules:

- no walkthroughs;
- references and personal notes allowed;
- smallest hint only after 90 minutes, recorded;
- facts/hypotheses log maintained;
- change task after 45 minutes without new evidence.

## Live log

| Time | Challenge | New fact | Hypothesis | Next test |
|---|---|---|---|---|
| | | | | |

## Required workflow

- [ ] Triage architecture, inputs, imports, and mitigations.
- [ ] Locate input sources and important sinks.
- [ ] Prove validation rule or vulnerability root cause.
- [ ] Inventory primitives and constraints.
- [ ] Account for every mitigation.
- [ ] Build reproducible code.
- [ ] Record dead ends and useful handoff notes.

## Scoring

| Result | Points |
|---|---:|
| Easy solve without hint | 100 |
| Medium solve without hint | 200 |
| Stretch solve without hint | 350 |
| Solve after small hint | 70% |
| Proven root cause plus useful partial chain | 25–50% |
| Unsubstantiated guess | 0 |

Target: 600 points with at least one reverse and one pwn solve.

## Oral assessment

Explain without notes:

1. x86-64 argument passing and stack alignment.
2. ELF sections versus segments.
3. PLT/GOT and how a GOT address can support a leak.
4. NX, PIE, ASLR, canary, and RELRO.
5. Root cause versus primitive versus exploit chain.
6. Format-string reads and `%n` writes.
7. Why heap exploitation is allocator-version-specific.
8. How to diagnose intermittent exploit failure.

## Reliability final

Select one exploit:

- [ ] 20 fresh runs;
- [ ] at least 90% success;
- [ ] no hard-coded randomized address;
- [ ] no unexplained sleeps/constants;
- [ ] clear stage logs and failures;
- [ ] root cause and complete chain documented.

## Retrospective

- Score:
- Solves:
- Hints:
- Strongest skill:
- Weakest skill:
- Recurring failure:
- Next four-week practice focus:

## Pass gate

- [ ] 600 points
- [ ] one reverse and one pwn solve
- [ ] one medium solve without walkthrough
- [ ] one exploit at least 90% over 20 runs
- [ ] root-cause write-ups for every solve
- [ ] follow-up plan written

