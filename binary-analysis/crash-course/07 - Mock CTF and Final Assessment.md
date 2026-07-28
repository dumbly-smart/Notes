---
tags: [ctf, assessment, reverse-engineering, binary-exploitation]
day: 7
---

# Day 7 — Mock CTF and Final Assessment

Back: [[00 - One-Week RE and Pwn Crash Course]]

## Outcome

Demonstrate a complete independent workflow under time pressure and leave with an evidence-based next practice plan.

## Preparation

Review [[08 - Core Theory Handbook]] using only the headings and examples needed to repair weak areas. The mock CTF itself remains a closed-walkthrough assessment.

## Rules

- 6-hour timed mini-CTF.
- No walkthroughs or full solutions.
- Documentation and personal notes are allowed.
- A small hint is allowed only after 90 minutes; record it.
- Maintain a live facts/hypotheses/blockers log.
- Stop and triage another challenge when a path produces no new evidence for 45 minutes.

## Challenge set

Prepare unseen legal archived CTF tasks:

- [ ] Reverse A: stripped password/key-check.
- [ ] Reverse B: optimized algorithm, encoding, or light obfuscation.
- [ ] Pwn A: stack overflow/ret2win or controlled arguments.
- [ ] Pwn B: NX+ASLR leak and ROP/ret2libc.
- [ ] Pwn C: format string or beginner heap/UAF.

Use a balanced difficulty set: two easy, two medium, one stretch.

## Competition log

| Time | Challenge | Fact learned | Current hypothesis | Next test |
|---|---|---|---|---|
| | | | | |

## Required solve workflow

For every attempted challenge:

- [ ] Triage metadata and mitigations.
- [ ] Identify input and important sinks.
- [ ] Separate facts from hypotheses.
- [ ] Prove the root cause or validation rule.
- [ ] List primitives and constraints.
- [ ] Explain the chosen chain.
- [ ] Build reproducible code.
- [ ] Record dead ends and handoff-quality notes.

## Scoring

| Result | Points |
|---|---:|
| Easy solve without hint | 100 |
| Medium solve without hint | 200 |
| Stretch solve without hint | 350 |
| Solve after small hint | 70% |
| Proven root cause + useful partial chain | 25–50% |
| Unsubstantiated guess | 0 |

Target: **600 points**, including at least one reverse and one pwn solve.

## Reliability final

Choose the best pwn exploit:

- [ ] run it from a clean process 20 times;
- [ ] report success percentage;
- [ ] test local/GDB/remote modes where applicable;
- [ ] verify no fixed ASLR-derived address is embedded;
- [ ] remove sleeps and unexplained constants;
- [ ] make parsing fail clearly.

## Closed-notes oral check

Explain:

1. System V AMD64 argument passing and stack alignment.
2. Sections versus segments.
3. PLT/GOT and one legitimate use in a leak.
4. What NX, PIE, ASLR, canary, and RELRO each change.
5. Root cause versus primitive versus exploit chain.
6. How a format string yields a leak and `%n`-style write.
7. Why heap exploitation depends on allocator version.
8. How to debug an exploit that works only sometimes.

## Final retrospective

### Results

- Challenges solved:
- Points:
- Hints used:
- Most reliable exploit:
- Fastest root cause:

### Strengths

- 

### Weaknesses

- 

### Recurring failure patterns

- 

### Next four weeks

Pick the weakest two categories. For each week:

- two focused labs;
- three unseen challenges;
- one timed re-solve;
- one clean write-up;
- one 10/10 or 20/20 reliability test.

Recommended directions:

- weak assembly → compiler experiments and daily hand tracing;
- weak reversing → stripped optimized crackmes and type recovery;
- weak stack pwn → progressively mitigated ROP challenges;
- weak format strings → manual offset/padding labs before helpers;
- weak heap → allocator source, diagrams, and version-matched beginner tasks;
- weak speed → twice-weekly 90-minute mixed sets.

## Final gate

- [ ] At least 600 points.
- [ ] At least one reverse and one pwn solved.
- [ ] One medium problem solved without a walkthrough.
- [ ] One exploit reaches at least 90% over 20 clean runs.
- [ ] Every solved task has a root-cause explanation.
- [ ] Four-week follow-up plan is written.

**Course result:** [ ] Passed [ ] Repeat selected days
