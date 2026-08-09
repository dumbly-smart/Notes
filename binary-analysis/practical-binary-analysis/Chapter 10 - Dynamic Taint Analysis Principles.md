---
tags: [binary-analysis, taint-analysis, information-flow, chapter-notes]
chapter: 10
---

# Chapter 10 — Principles of Dynamic Taint Analysis

## Chapter overview

Dynamic taint analysis (DTA) labels selected runtime data and propagates labels as executed instructions transform values. It answers a bounded question: **did information from chosen sources influence chosen sinks during this execution under this policy?**

```text
source bytes + labels
      ↓ executed operations and propagation policy
register/memory shadow state
      ↓
sink check → report label provenance
```

## 10.1 What DTA is—and is not

DTA is dynamic information-flow tracking. It is path-specific and policy-specific.

- Absence of taint at a sink does not prove global noninterference.
- Presence of taint proves policy-defined influence for that run, not automatically maliciousness or exploitability.
- Unsupported operations and missed implicit flows can create false negatives.

## 10.2 Sources, sinks, propagation

### Sources

Sources assign labels: bytes from `read/recv`, command-line inputs, environment variables, secret files, or selected memory.

Precise source definition includes channel, byte range, event time, and color/provenance.

### Sinks

Sinks are uses worth checking: indirect control targets, command arguments, file/network output, lengths, authorization decisions, or memory addresses.

### Propagation

Representative explicit policies:

| Operation | Destination taint |
|---|---|
| `mov dst,src` | `T(src)` |
| `xor reg,reg` | empty (known zero idiom) |
| `add dst,src` | `T(dst) ∪ T(src)` |
| load | taint of addressed memory bytes |
| store | taint of source written to shadow memory |
| comparison | flags receive operand influence if flags tracked |

Naively using union for every operation overtaints. Semantic identities can clear dependence: `x XOR x = 0`; `x - x = 0`; `x AND 0 = 0`. Aliasing the same operand matters.

## 10.3 Heartbleed as an information-flow case

The vulnerability class: a peer provides actual payload plus a claimed length; the response copies/sends the claimed number of bytes without ensuring it is no greater than available payload. Adjacent process memory is disclosed.

Two useful taint formulations:

1. taint sensitive/non-request payload memory and alert if it reaches network output;
2. taint the untrusted claimed length and inspect its control over an outbound memory range.

The first directly detects secret flow but requires identifying secrets. The second detects untrusted length influence but needs a bounds model to distinguish safe validated use.

Violated invariant:

```text
claimed_length ≤ received_payload_length
```

Safe check after parsing:

```text
if claimed_length > available_length: reject
```

## 10.4 Design choices

### Granularity

Bit-level is precise/expensive; byte-level is common; word/object-level is cheaper but smears labels. Choose according to the property.

### Colors

One bit answers “untrusted or not.” Multiple colors preserve which source/byte class influenced a value. Color sets cost memory and operations.

### Overtaint and undertaint

**Overtaint:** label spreads to values not semantically dependent, producing noise.

**Undertaint:** true influence loses its label, producing missed flows.

There is no universal perfect policy: semantic precision, unsupported instructions, implicit flows, native/library summaries, and performance interact.

### Control dependencies

```c
if (secret) out = 1;
else        out = 0;
```

`out` contains no explicit copied secret bit, but reveals it. Tracking program-counter/control taint catches this class but often overtaints everything inside large controlled regions. Post-dominators can bound how long control dependence persists, but exceptions and complex control flow complicate it.

### Shadow memory

Shadow state maps application registers/memory to taint metadata.

```text
application byte address A ↔ shadow label S(A)
```

Designs include direct mapping, page tables, hash maps, and compressed metadata. They trade lookup speed, address-space cost, sparsity, and color richness.

## Added example — validated length

```c
n = input_byte();
if (n > 16) return;
memcpy(dst, src, n);
```

`n` remains tainted at `memcpy`, yet its influence is safe under the shown invariant if `dst` and `src` capacities are at least 16. Taint flags influence; a vulnerability detector must pair it with range/capacity reasoning.

## Common mistakes

- Defining “network” as one undifferentiated source when provenance matters.
- Clearing taint after validation without proving the validation dominates every use.
- Treating a tainted sink as a vulnerability automatically.
- Ignoring file-descriptor reuse and short reads.
- Claiming unexecuted paths are safe.

## Practice questions

1. Define two source/sink policies for confidentiality and integrity.
2. Why should `xor eax,eax` clear taint even if `eax` was tainted?
3. Give one overtaint and one undertaint example.
4. Why does implicit-flow tracking spread labels aggressively?
5. Design a DTA policy for untrusted indirect-call targets.
6. Explain why a tainted length after a correct bounds check is not automatically dangerous.

## Solutions

1. Confidentiality: secret-file bytes → socket/file output. Integrity: network bytes → indirect target, command, or privileged state.
2. Result is constant zero independent of the old value; operand identity is semantically important.
3. Overtaint: union through `x & 0`; undertaint: secret controls a branch assigning public constants while control dependence is ignored.
4. One tainted predicate can influence all assignments in a region; nested/long-lived control makes precise termination difficult.
5. Taint bytes from untrusted channels, propagate at byte/register level, inspect every executed indirect call/jump/return target and report provenance plus concrete target.
6. Taint tracks origin/influence, not validated range. The security invariant can permit controlled bounded values.

## Mastery checklist

- [ ] Define precise source, sink, granularity, colors, and policies.
- [ ] Explain explicit and implicit flows.
- [ ] Distinguish overtaint, undertaint, and path undercoverage.
- [ ] Model the Heartbleed invariant and detector tradeoffs.
