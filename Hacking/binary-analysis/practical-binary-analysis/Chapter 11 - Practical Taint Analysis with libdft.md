---
tags: [binary-analysis, libdft, taint-analysis, pin, chapter-notes]
chapter: 11
---

# Chapter 11 — Practical Dynamic Taint Analysis with libdft

## Chapter overview

This chapter implements DTA policies on libdft, a Pin-based framework. It first detects untrusted influence over control-sensitive data and `execve` arguments, then builds a data-exfiltration detector that labels file data and checks network sends.

## 11.1 libdft internals

libdft supplies instruction instrumentation and tag maps for register/memory state. A tool adds policy around events such as syscalls and checks tags at chosen sinks.

Conceptual setup:

```text
initialize Pin/libdft
 → select tag representation/policy
 → register syscall entry/exit callbacks
 → register instruction/control-flow sink callbacks
 → start program
```

Version/API details may differ from the book’s environment. Preserve the architecture, not blindly old build commands.

## 11.2 Detecting remote control hijacking

### Source — received bytes

At syscall entry, capture buffer address and requested length. At syscall exit, use the actual positive return count:

```text
tainted interval = [buffer, buffer + bytes_actually_received)
```

Do not taint the requested count; short reads are normal. Associate state with the correct thread because another syscall can intervene.

### Sink — `execve` arguments

Check taint on the pathname string and each argument string, with bounded safe reads. A tainted argument can be legitimate user data; the policy needs context about intended trust.

### Sink — control transfers

Before executed indirect call/jump/return, examine tags contributing to the target. Report instruction location, concrete target, source color, and relevant stack/register state.

Control-flow hijack evidence becomes strong when attacker-received bytes label a saved return target. It still does not prove reliable code execution under ASLR, CFI, stack canaries, or input constraints.

## 11.3 Implicit-flow evasion

An attacker/program can encode data through control:

```c
if (input_bit) target_byte |= mask;
```

If constants written on each path are untainted and program-counter taint is absent, the reconstructed target loses taint. This demonstrates that a DTA result is relative to propagation policy.

## 11.4 Data-exfiltration detector

### File-source state machine

```text
open/openat success
 → map returned fd to file identity/color
read/pread success
 → taint actual returned bytes in buffer
dup/dup2/fork
 → propagate descriptor association as modeled
close
 → remove association
```

File descriptor numbers are reused. If state is not cleared on close, unrelated later reads receive the old secret color.

### Network sinks

At `send`, `sendto`, `sendmsg`, or `write` to a known socket, check only actual outbound byte ranges and scatter/gather structures. Model partial writes and nested iovecs with strict bounds.

### Worked state example

```text
open("secret", O_RDONLY) = 3      fd 3 → color S
read(3, buf, 100) = 12            tag buf[0..12) with S
close(3)                           remove fd 3 mapping
open("public", O_RDONLY) = 3      fd 3 is now uncolored/public
```

Failing to process `close` falsely tags the public read.

## Engineering details

- per-thread syscall context;
- bounded user-memory access and error handling;
- multithread-safe descriptor map;
- `mmap`-based file input if in scope;
- inherited descriptors/processes;
- TLS/encryption: plaintext may flow to crypto then ciphertext, so byte-level explicit taint can persist or become policy-dependent;
- provenance storage and report deduplication.

## Common mistakes

- Tainting requested rather than returned bytes.
- Ignoring negative/error returns.
- Using one global pending-syscall buffer across threads.
- Forgetting `dup`, `close`, and fd reuse.
- Checking only `send` while exfiltration uses `write`/`sendmsg`/mmap.
- Treating any labeled outbound data as unauthorized.

## Practice questions

1. Why are both syscall entry and exit needed for a read source?
2. What exact evidence supports a tainted-return-target report?
3. Design fd tracking for `dup2(old,new)`.
4. How does `sendmsg` complicate sink checking?
5. Give a legitimate flow that a naïve exfiltration detector flags.
6. Propose one defense against implicit-flow undertaint and its cost.

## Solutions

1. Entry supplies address/request; exit supplies success and actual length. Taint only bytes written by the kernel.
2. Executed indirect return target’s tag set includes source labels assigned to received bytes, with trace showing propagation; impact remains separately assessed.
3. On success, clear prior `new` mapping, then copy/share `old`’s file-description association into `new`; handle `old==new` and errors.
4. It contains arrays of iovecs and optional nested control data; each length/pointer must be read safely and only actual transmitted bytes assessed.
5. Authorized upload/backup sends data from a marked file. Policy needs destinations, process roles, or allowlists.
6. Program-counter taint through control-dependent regions catches implicit flow but increases overhead and overtaint.

## Mastery checklist

- [ ] Implement source tagging from actual syscall results.
- [ ] Maintain thread and descriptor state correctly.
- [ ] Check control/data sinks with provenance.
- [ ] State explicit-flow and coverage limitations in every report.

## Extended chapter synthesis

**Key process:** capture syscall arguments at entry → use actual result at exit → assign provenance → maintain per-thread/fd state → inspect exec/control/network sinks → report concrete event and policy limitations.

**Common failures:** tainting requested bytes, stale fd colors, one global syscall context, ignoring scatter/gather and implicit flows.

Full 48-question set with worked solutions: [[Workbooks/Chapter 11 - Practice and Complete Solutions]].
