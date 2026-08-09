# Chapter 7 — Auditing Program Binaries

> [!workthroughs] Complete tool-backed labs: [[Walkthroughs - Chapter 07 - Fifteen Complete Analyses]]

> [!source]
> **From the book:** vulnerability classes, mitigations available at publication time, and the historical IIS Indexing Service case study.
> **Added explanation:** modernized reasoning, proof-oriented audit workflow, toy examples, safe lab procedure, and defensive remediation. Historical details are studied to understand root causes—not to target systems.

## Chapter Overview

Binary auditing asks whether machine code preserves its security invariants when it receives hostile input. Unlike ordinary reversing, the endpoint is not merely a description of behavior. It is a defensible claim about a dangerous data flow:

```text
attacker-controlled source
        ↓
parsing / decoding / conversion / arithmetic
        ↓
missing or invalid security check
        ↓
memory or control-sensitive sink
        ↓
demonstrable impact in an isolated test
```

The chapter introduces stack and heap overflows, inadequate string filters, integer overflow, and type-conversion errors, then examines a historical IIS vulnerability. The lasting skill is to reason in machine-level units: widths, signedness, allocation sizes, pointer ranges, and actual control flow.

## 7.1 Defining the Problem

### What is a binary audit?

A binary audit is a systematic search for security-relevant mismatches between what the program assumes and what untrusted input can cause. Without source, you must reconstruct:

- trust boundaries and externally controlled bytes;
- parsers and transformations;
- buffer origins and capacities;
- arithmetic that computes lengths and indexes;
- writes, copies, allocations, indirect calls, and privilege changes;
- error paths and mitigations.

### Audit versus ordinary reversing

| Dimension | Functional reversing | Security auditing |
|---|---|---|
| Main question | What does it do? | What can hostile input make it do? |
| Path focus | common/success path | boundary and failure paths |
| Values | representative | min, max, negative, wrapped, truncated |
| Completion | coherent algorithm | reproducible root cause and impact |
| Output | model/pseudocode | evidence, severity, remediation |

## 7.2 Vulnerabilities and Exploitability

A **bug** is incorrect behavior. A **vulnerability** is a bug that violates a security property. **Exploitability** asks whether the violation can be turned into useful attacker influence under the real environment and mitigations.

These are separate claims:

1. Input reaches the function.
2. A safety invariant can fail.
3. The failure is reachable and reproducible.
4. The resulting corruption/disclosure/control has security impact.
5. Environmental mitigations change reliability or consequence.

Do not skip from suspicious `memcpy` to “remote code execution.”

## 7.3 Stack Overflows

### Core Idea

A stack overflow occurs when a function writes beyond a stack object’s bounds. Adjacent locals, saved registers, frame metadata, exception records, or return-control data may be corrupted depending on layout and compiler.

```text
higher addresses
┌───────────────────────┐
│ caller state          │
├───────────────────────┤
│ return address        │
├───────────────────────┤
│ saved frame/registers │
├───────────────────────┤
│ local char buf[16]    │ ← unbounded write starts here
└───────────────────────┘
lower addresses
```

Actual order varies. Never infer exploitability from this cartoon alone; inspect the compiled frame.

### A simple stack vulnerability

```c
void copy_name(const char *input) {
    char name[16];
    strcpy(name, input);
}
```

**What do we know?** Destination capacity is 16 bytes. `strcpy` copies through a terminator but receives no capacity.

**Failure condition:** if the input requires more than 16 bytes including the terminator, the write crosses the object boundary.

**Binary audit procedure:**

1. Identify the local buffer’s frame offset and capacity.
2. Identify the copy call or inlined loop.
3. Trace the source to untrusted input.
4. Determine whether any dominating length check exists.
5. Compare units—bytes versus characters.
6. Reproduce with a benign cyclic or canary pattern inside a disposable process.
7. Record the first corrupted object and exact failing instruction.

### Intrinsic implementations

Compilers may inline common copies. Searching imports for `strcpy` is therefore insufficient. Recognize semantic patterns:

```text
load source byte/word
store destination byte/word
advance pointers
test terminator or counter
loop
```

Optimized code may copy whole words first, making the write look unlike the source library function.

### Stack checking

Stack cookies place a value between vulnerable local state and control metadata. The epilogue verifies that it remains intact. They convert many overwrites into detected termination, but are not a proof of safety:

- corruption that does not cross the cookie may still matter;
- non-control data can be security-sensitive;
- disclosure may reveal guard material;
- functions/objects may be unprotected;
- logic, integer, and heap bugs remain.

### Nonexecutable memory

NX/DEP prevents executing data pages. It changes exploitation strategy and often turns direct injected-code execution into a crash. It does not prevent the out-of-bounds write itself, data-only corruption, information disclosure, or reuse of already executable code. Modern conclusions must also account for ASLR, control-flow protection, shadow stacks, hardened allocators, and compiler instrumentation.

## 7.4 Heap Overflows

Heap objects live in dynamically managed memory. An overflow can corrupt:

- an adjacent application object;
- a length, pointer, callback, or virtual-function pointer;
- allocator metadata, especially in historical allocators;
- the contents of a neighboring buffer without immediate crash.

### Why heap bugs are harder to reason about

Layout depends on allocation order, size classes, allocator version, thread behavior, and previous frees. Separate:

- **root cause:** the write can exceed its allocation;
- **layout observation:** what was adjacent in one run;
- **security impact:** what an attacker can reliably influence.

### Safe proof pattern

Create a toy program with two adjacent logical objects, place recognizable canaries around the destination, and demonstrate that a boundary input changes only the canary. Do not begin by building control-flow takeover. A minimal corruption proof is enough to establish the bug.

## 7.5 String Filters

### Core Idea

A filter is safe only if it reasons about the same representation the consumer uses. Inputs may be decoded, normalized, case-folded, truncated, or interpreted through alternate syntax after the filter.

```text
raw input → filter → decoder → canonical path → operation
                    ↑
             dangerous mismatch
```

### Common mismatches

| Filter sees | Consumer sees | Risk |
|---|---|---|
| percent-encoded text | decoded characters | forbidden bytes appear later |
| mixed case | case-insensitive token | deny-list bypass |
| one path syntax | normalized path | traversal after canonicalization |
| full integer | truncated field | validation applies to different value |
| first NUL convention | length-delimited data | components disagree on endpoint |

### Correct design principle

Canonicalize once, validate the canonical representation, and pass exactly that validated representation to the sensitive operation. Prefer allow-lists and structural parsers over ad hoc substring removal.

## 7.6 Integer Overflows

### Fixed-width arithmetic

For an unsigned `w`-bit integer:

\[
x + y \text{ is stored as } (x+y) \bmod 2^w
\]

If a mathematical result exceeds the type’s range, the stored result wraps. Signed overflow has language-level complications, but at the binary level you must inspect the emitted operation and the flags/checks the program actually uses.

### Arithmetic on user-supplied integers

The dangerous pattern is a small allocation followed by a large logical operation:

```c
uint32_t bytes = count * element_size;
void *p = malloc(bytes);
for (uint32_t i = 0; i < count; i++)
    read_element((char *)p + i * element_size);
```

If multiplication wraps, allocation may be too small while the loop still trusts the original `count`.

### Worked example

Assume 32-bit unsigned arithmetic, `count = 0x40000001`, and `element_size = 4`.

1. Mathematical product is `0x100000004`.
2. Stored low 32 bits are `0x00000004`.
3. Allocation requests four bytes.
4. The loop conceptually processes over one billion elements.
5. The invariant `allocation_size >= count × element_size` is broken.

### Correct precondition

Before multiplication:

```c
if (count > SIZE_MAX / element_size)
    fail();
bytes = count * element_size;
```

Then also validate protocol limits and downstream type conversions.

### Flags in binary analysis

`ADD`, `SUB`, and `MUL` affect carry/overflow indicators, but a compiler may implement checks using comparisons or division thresholds. Determine whether the dangerous operation is dominated by a valid check along every path.

## 7.7 Type-Conversion Errors

Conversions can change width, signedness, or interpretation.

### Important machine operations

| Operation | Meaning | Audit concern |
|---|---|---|
| zero extension | fill high bits with zero | intended for unsigned source |
| sign extension | replicate sign bit | intended for signed source |
| truncation | discard high bits | validated value may change |
| signed compare | orders negatives below positives | differs for high-bit values |
| unsigned compare | high-bit values are large positive | negative sentinel becomes huge |

### Worked example: signed length

```c
int32_t n = parse_length();
if (n < 1024) {
    memcpy(dst, src, (size_t)n);
}
```

For `n = -1`, the signed check succeeds. Conversion to `size_t` produces a very large positive number. The correct validation requires both lower and upper bounds before conversion:

```c
if (n < 0 || (size_t)n > capacity)
    fail();
```

### Recognition in assembly

Pay attention to `MOVSX` versus `MOVZX`, operand widths, and signed versus unsigned conditional branches (`JL/JG` versus `JB/JA` on x86). The same bit pattern can take opposite branches.

## 7.8 Historical Case Study: IIS Indexing Service

### Background

The book analyzes a historical vulnerability in the IIS Indexing Service. The educational objective is to reconstruct how encoded input, length accounting, allocation, and copying interact inside two routines: `CVariableSet::AddExtensionControlBlock` and `DecodeURLEscapes`.

### Security boundary

An externally supplied request reaches parsing/decoding logic in a privileged network service. That makes every transformation of length and representation security-relevant.

### `CVariableSet::AddExtensionControlBlock`

The audit method is:

1. recover the function’s inputs and object fields;
2. identify where input-derived lengths are computed;
3. track allocation-size calculation;
4. follow the pointer and lengths into the decoding/copy routine;
5. determine which value bounds writes;
6. check whether source and destination lengths refer to the same representation.

### `DecodeURLEscapes`

URL escape decoding converts encoded sequences into bytes. Decoding often shrinks data, but that fact alone does not guarantee safety. The caller and decoder must agree on:

- source length;
- destination capacity;
- terminator space;
- malformed escape handling;
- character width;
- whether length fields are signed or truncated.

### Root-cause model

```text
request-controlled encoded bytes
        ↓
length/size calculation under one representation
        ↓
allocation or destination selection
        ↓
DecodeURLEscapes processes under another assumption
        ↓
write exceeds intended destination boundary
```

The key lesson is the **contract mismatch** between caller and callee. Auditing only the decoder or only the allocation site can miss it.

### Reconstructing the proof

For a historical sample in an isolated lab:

1. snapshot the test VM and disable external exposure;
2. place breakpoints at the caller, allocation, and decode loop;
3. record raw input length, computed capacity, destination bounds, and loop iterations;
4. use a non-executing marker pattern;
5. stop at the first write whose address is outside `[dst, dst + capacity)`;
6. preserve the instruction, registers, call stack, and input transformation;
7. reduce the sample until removing any remaining component prevents the violation;
8. state the missing invariant and remediation.

This is a vulnerability proof, not a weaponized exploit.

### Remediation

- Give the decoder an explicit destination capacity.
- Use checked arithmetic for allocation and terminator.
- Reject malformed escape sequences consistently.
- Define lengths in bytes with unsigned size types.
- Validate canonical decoded output before use.
- Add regression cases for maximal, malformed, and boundary encodings.

## 7.9 A Repeatable Binary-Audit Workflow — Added

### Phase 1: Scope and threat model

1. Confirm authorization and isolate the target.
2. Identify attacker-controlled interfaces.
3. Note process privilege and valuable assets.
4. Record architecture, build, and mitigations.

### Phase 2: Triage

1. Map imports, strings, handlers, and parsers.
2. Locate dangerous sinks: copies, writes, allocations, formatters, indirect calls.
3. Trace backward to sources.
4. Rank paths by reachability and consequence.

### Phase 3: Prove the invariant failure

For every candidate, write:

```text
Object/capacity:
Attacker-controlled value:
Transformation chain:
Required safety condition:
Actual check:
Counterexample:
First invalid instruction:
```

### Phase 4: Assess impact

Check reproducibility, controllability, information disclosure, adjacent objects, privilege, and mitigations. Keep “confirmed” separate from “plausible.”

### Phase 5: Report and retest

Provide exact build, minimal reproducer, root cause, preconditions, mitigations, recommended fix, and a regression test. Verify the patched binary enforces the intended invariant.

## Comparison Table

| Class | Broken invariant | Binary clue | Defensive fix |
|---|---|---|---|
| Stack overflow | write within local object | frame-relative buffer + unbounded copy | capacity-aware copy + compiler hardening |
| Heap overflow | write within allocation | allocation size disagrees with later loop/copy | checked sizing and bounds |
| Filter bypass | validation matches consumed representation | decode/normalize occurs after filtering | canonicalize then validate |
| Integer overflow | computed size represents mathematical result | unchecked narrow add/multiply | precondition/checked arithmetic |
| Conversion error | value meaning survives cast | sign/zero extension, truncation, branch mismatch | validate range before conversion |

## Common Mistakes

**Mistake:** searching only imported unsafe functions.
**Correction:** recognize inlined operations and audit caller/callee contracts.

**Mistake:** proving a crash and declaring code execution.
**Correction:** separately prove root cause, control, reachability, and impact.

**Mistake:** ignoring integer units.
**Correction:** annotate every length as bytes, characters, elements, or encoded bytes.

**Mistake:** assuming mitigations repair the bug.
**Correction:** mitigations reduce exploitability; the invalid access still needs fixing.

## Chapter in One View

```text
trust boundary
   ↓
representation and length transformations
   ↓
allocation / buffer / index decision
   ↓
security-sensitive sink
   ↓
check invariant at machine width and actual control flow
```

## What You Should Be Able to Explain

- [ ] Bug versus vulnerability versus exploitability.
- [ ] Why post-filter decoding is dangerous.
- [ ] How multiplication overflow creates undersized allocations.
- [ ] Why signed and unsigned branches matter.
- [ ] What stack cookies and NX do—and do not—guarantee.

## What You Should Be Able to Do

- [ ] Recover a local buffer’s real capacity from a stack frame.
- [ ] Trace an input length through conversions and arithmetic.
- [ ] Write the exact safety invariant for a copy or loop.
- [ ] Produce a minimal, non-weaponized corruption proof in an isolated lab.
- [ ] Recommend a root-cause fix and regression boundary set.

## Practice Questions

1. Why is a crash not sufficient proof of a security vulnerability?
2. Give three reasons imported-function searches miss stack copies.
3. For a 16-bit unsigned size, compute the stored result of `40000 + 30000`.
4. Explain how a negative 32-bit length can become huge on a 64-bit call.
5. What facts must be known before declaring a stack overwrite reaches a return address?
6. Design boundary tests for `count * 24 + 16` on a 32-bit size type.
7. A filter rejects `..` before percent decoding. State the broken invariant and repair.
8. In a decode routine, source length is bytes but destination capacity is wide characters. What must the auditor determine?
9. Describe a minimal proof for a heap overwrite that does not attempt control-flow takeover.
10. How would you verify that a vendor patch fixes root cause instead of suppressing one test case?

## Practice Question Solutions

1. The crash may be unreachable to an attacker, caused by non-security input, or yield no security-property violation. Reachability, broken invariant, control, and impact need evidence.
2. The compiler may inline it, use an intrinsic/vectorized loop, or the copy may reside in a statically linked/private helper.
3. `70000 mod 65536 = 4464`.
4. A signed negative value passes an incomplete upper-bound check, then conversion/sign extension to an unsigned `size_t` reinterprets it as a massive positive count.
5. Exact local layout, write direction and length, intervening objects/cookie, control-flow path, compiler protections, and first overwritten address.
6. Test zero, one, maximum allowed, values around `(UINT32_MAX - 16)/24`, the first overflowing count, and protocol-specific maxima. Verify both arithmetic and allocation/use agree.
7. Validation applies to raw form while the consumer sees canonical decoded form. Decode/canonicalize first, reject malformed encodings, validate once, and use the same bytes.
8. Character width, maximum expansion/contraction, terminator units, conversion behavior, actual allocated byte capacity, and whether loop counters use source or destination units.
9. Place canaries after a toy allocation, provide the smallest boundary input, break at the first out-of-range store, and show canary corruption with the exact missing bound.
10. Re-run the minimized input plus adjacent boundaries and equivalent encodings; inspect the patched control/data flow for a dominating capacity check and checked arithmetic.

---

Previous: [[Chapter 06 - Deciphering File Formats]]
Next: [[Chapter 08 - Reversing Malware]]
Related lab guide: [[../practical-binary-analysis/Authorized Binary Exploitation Guide|Authorized Binary Exploitation Guide]]

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs II - Formats Vulnerabilities and Malware]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
