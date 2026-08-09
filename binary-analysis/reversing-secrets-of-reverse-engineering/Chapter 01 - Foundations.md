---
tags: [reverse-engineering, foundations, legal, chapter-notes]
chapter: 1
---

# Chapter 1 — Foundations

## Chapter overview

The opening chapter defines software reverse engineering, explains why people reverse software, introduces the low-level knowledge and tool families required, separates system-level from code-level work, and surveys legal questions. It exists to establish that reversing is a disciplined discovery process whose legitimacy depends on purpose, authorization, and law—not a synonym for piracy.

By the end you should be able to formulate a reversing problem, choose an observation layer, explain why binary analysis is necessary, and state the legal/safety questions that must be resolved before work begins. Chapter 2 then supplies the low-level model needed to read compiled programs.

### Chapter roadmap

```text
Reverse engineering
├── applications
│   ├── security: malware, crypto, DRM, binary audit
│   └── development: interoperability, competition, quality
├── required low-level model
│   ├── assembly and compilers
│   ├── virtual machines/bytecodes
│   └── operating systems
├── process
│   ├── system-level reversing
│   └── code-level reversing
├── tools
│   ├── monitors, disassemblers, debuggers, decompilers
│   └── evidence produced by each
└── legality and authorization
```

## What is reverse engineering?

### Core idea

**From the book:** reverse engineering analyzes an existing system to identify its components and relationships and to create a representation at another or higher abstraction level.

### Detailed explanation

Forward engineering begins with requirements/design and creates an implementation. Reversing begins with an implementation/artifact and recovers explanations: architecture, algorithms, interfaces, data structures, invariants, protocols, or behavior.

```text
forward: intent/design → source → binary → behavior
reverse: behavior/binary → model of code/data/design → tested explanation
```

Exact historical source is often unrecoverable because compilation discards names, comments, formatting, type details, macro boundaries, and dead code. A successful result is therefore usually an **equivalent model**, not the original text.

**Reverse engineering:** systematic recovery of structure and meaning from an artifact.

**In simple words:** take software apart intellectually until you can predict and reproduce how it works.

**Example:** infer an undocumented archive layout, implement an independent reader, and correctly parse unseen archives.

### Common misunderstanding

Reversing is not automatically decompilation. System-call timelines, a protocol specification, an object layout, or an identified vulnerability root cause are legitimate reverse-engineering outputs.

### How this connects

This definition determines the entire method: create representations, test them, and improve abstraction—not merely collect instructions.

## Reversing applications

### Security-related reversing

#### Malicious software

Analysis can determine installation, persistence, communication, command handling, propagation, concealment, and destructive/data-stealing behavior. The book later performs a malware case study. Modern analysis must begin with containment because executing a sample gives it the same opportunities as any other program.

#### Cryptographic algorithms

Reversing may identify a proprietary transformation, locate key handling, or verify implementation. Identifying an algorithm is different from breaking its mathematics. A secure standard cipher can be implemented poorly; a proprietary algorithm can merely look complex.

#### Digital rights management and copy protection

The book examines how protection systems work and how analysts attack them. The durable lesson is trust placement: if a client must possess a key/decision and the adversary controls the client environment, protection can raise cost but rarely create perfect secrecy. Apply this only to authorized toy systems.

#### Auditing program binaries

Source may be unavailable, out of date, or compiled with dangerous transformations. Binary auditing checks what actually ships: input parsing, arithmetic widths, memory operations, mitigations, and library/runtime behavior.

### Software-development applications

#### Interoperability

Recover an undocumented interface/format so independently written software can communicate. A disciplined clean-room process separates observation/specification from implementation and documents legal authorization.

#### Competing/compatible software

Behavioral compatibility may require learning externally visible semantics. The line between lawful compatibility and infringement/contract violation is jurisdiction-specific; technical capability does not answer legality.

#### Quality and robustness

Reverse shipped code to diagnose failures, compiler output, undocumented behavior, performance, or security weaknesses.

### Comparison

| Application | Primary question | Typical output |
|---|---|---|
| malware analysis | what can it do and how? | behavior/capability/protocol report |
| interoperability | what contract must another program obey? | clean-room specification |
| binary audit | where is a security invariant violated? | finding, primitive, repair guidance |
| algorithm recovery | what transformation is implemented? | pseudocode/test vectors |
| quality diagnosis | why does shipped behavior differ? | causal trace and component model |

## Low-level software

### Assembly language

Assembly is a readable representation of machine operations. Reversers learn compiler-generated patterns rather than only hand-written assembly. The central question is always: which machine state does an instruction read and change?

### Compilers

Compilers preserve required observable semantics but freely change surface structure. Optimization explains missing variables, inlining, reordered arithmetic, tail calls, and branchless code.

### Virtual machines and bytecodes

Managed/runtime environments introduce an intermediate instruction set interpreted or JIT-compiled. Reversing strategy must choose the most informative layer: metadata/bytecode, runtime, or generated native code.

### Operating systems

The OS defines processes, virtual memory, files, handles, threads, synchronization, exceptions, and syscalls. Code cannot be interpreted fully without its environment.

> [!deep-dive] The layer-selection problem
> If the question is “which file is changed?”, OS monitoring may answer immediately. If it is “why is this field rejected?”, code/data analysis is needed. If managed metadata names every type, beginning with JIT native code wastes information. Experts choose the highest layer that preserves the needed truth, then descend only when necessary.

## The reversing process

### System-level reversing

Observe whole-program interactions: files, registry, processes, handles, modules, network, IPC, and timing. This quickly maps external behavior and suggests high-value code regions.

### Code-level reversing

Analyze instructions/data, control flow, calls, types, algorithms, and internal state. Static analysis offers breadth; debugging offers concrete values and causality for exercised paths.

```text
system event (file write)
 → identify process/thread/call boundary
 → locate call site
 → trace filename/data producers
 → recover condition/algorithm
 → test with controlled inputs
```

### Step-by-step method

1. Establish authorization, target hash, environment, and question.
2. Observe external behavior with safe controlled inputs.
3. Identify relevant modules/imports/strings/events.
4. Build a focused static slice/CFG.
5. Form competing hypotheses.
6. Run a discriminating debugger/monitor experiment.
7. Rename/retype only when evidence supports it.
8. Reconstruct an equivalent model.
9. Test normal, boundary, error, and negative cases.
10. Report confidence and unknowns.

## Tools

### System-monitoring tools

Observe externally visible events. They establish *what crossed a boundary*, not necessarily why.

### Disassemblers

Decode candidate instruction bytes and often build xrefs/CFG. They face code/data ambiguity and indirect control flow.

### Debuggers

Control execution and inspect concrete registers/memory/threads. They cover only the tested run and can change timing or be detected.

### Decompilers

Build high-level pseudocode using inferred types/control flow. They accelerate comprehension but invent representation details.

| Tool | Best evidence | Main limitation |
|---|---|---|
| monitor | concrete external effects | internal computation hidden |
| disassembler | possible instructions/control | uncertain boundaries/values |
| debugger | concrete state and causality | path-specific/observer effect |
| decompiler | readable semantic hypothesis | inferred types/structure |

## Is reversing legal?

The book discusses interoperability, competition, copyright, trade secrets, patents, the DMCA, cases, and license agreements. These categories overlap but answer different questions.

**Added current guidance:** do not treat a 2005 survey as current legal advice. Before a project, record jurisdiction, ownership/authorization, license terms, access controls, purpose, distribution, confidentiality, and counsel/contact if stakes are meaningful.

### Practical authorization checklist

- Do I own the target or have explicit permission?
- Does the license/contract restrict analysis?
- Am I bypassing an access-control measure?
- Will I copy/distribute protected expression or only publish facts/interfaces?
- Are trade secrets/patents/confidential data involved?
- Does an interoperability/security-research exception plausibly apply here?
- What disclosure/data-handling rules govern findings?

## Worked example — from vague goal to investigation

**Situation:** an undocumented client writes an incompatible cache file.

**What we know:** file path and two samples; no source.

**Goal:** recover the minimum format needed for interoperability.

1. Define authorized clean-room scope and preserve samples/hashes.
2. Monitor file create/write/rename operations.
3. Generate samples changing one input property at a time.
4. Diff bytes and locate length/version/checksum candidates.
5. Find write-call code and backward-slice field producers.
6. Draft a field table with confidence.
7. Implement independent parser and test unseen files.
8. Document unknown fields rather than copying code.

**Final result:** a tested behavioral format specification, not guessed original source.

## Common mistakes

**Mistake:** opening a huge binary and reading from entry with no question. **Why wrong:** effort is not prioritized. **Avoid:** begin from behavior, a clue, or precise unknown.

**Mistake:** treating a decompiler as authoritative. **Why wrong:** types/names/control are reconstructed. **Avoid:** verify important semantics in instructions/runtime.

**Mistake:** assuming technical possibility equals legal permission. **Why wrong:** law/contract/authorization are separate. **Avoid:** document scope first.

**Mistake:** one successful input proves the model. **Why wrong:** alternatives and edge cases remain. **Avoid:** negative and boundary tests.

## Chapter synthesis

### Chapter in one view

```text
legitimate question + authorization
 → select system/code layer and tool
 → gather independent evidence
 → reconstruct a higher-level model
 → falsify/test it
 → reproducible answer with confidence and unknowns
```

### Key ideas

- Reversing is representation recovery and hypothesis testing.
- System and code analysis are complementary.
- Tool output has scope and approximation limits.
- Equivalent behavior is more recoverable than historical source.
- Authorization/legal analysis precedes technical action.

### What you should be able to explain

- [ ] Define reversing without reducing it to decompilation.
- [ ] Compare five legitimate applications.
- [ ] Select the correct layer/tool for a question.
- [ ] Explain why compilation and OS knowledge matter.
- [ ] State legal questions without pretending to give legal advice.

### What you should be able to solve

- [ ] Turn a vague reversing goal into a bounded investigation.
- [ ] Correlate one system event with responsible code/data.
- [ ] Produce a tested equivalent specification.
- [ ] Maintain facts, hypotheses, confidence, and unknowns.

Practice questions and full solutions: [[Reversing - Complete Practice Workbooks#Chapter 1 — Foundations]].

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs I - Foundations Through Tools]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
