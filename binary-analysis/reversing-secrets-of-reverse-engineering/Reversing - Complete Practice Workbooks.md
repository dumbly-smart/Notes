# Reversing — Complete Practice Workbooks

This bank adds 78 non-repetitive core problems with complete solution approaches to the questions already embedded in every chapter and the [[Reversing - 100 Lab Mastery Roadmap]]. Attempt each question before opening its solution.

# Chapter 01 Foundations Workbook

## Questions

1. A stripped utility exits after printing “invalid archive.” Where do you begin?
2. What separates a fact from an inference when naming a function?
3. Why combine static and dynamic analysis?
4. How do you scope an authorized reversing task?
5. A decompiler labels a parameter int. What evidence can refute it?
6. Design a mastery test for an unfamiliar function.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Reproduce with a tiny input; locate the message reference/output call; trace backward to its controlling branch and forward to the parser; record observations before naming the format check.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** A fact is directly observed, such as a call to ReadFile; “parses header” is an inference supported by arguments, callers, and buffer uses. Add a falsification test.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Static analysis covers discovered alternatives but lacks concrete values; dynamic analysis proves exact values/targets on one path. Use each to challenge the other.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Record owner/authorization, exact binaries, permitted techniques, lab boundaries, prohibited external interaction, data handling, and report destination before execution.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Pointer dereferences, ABI call-site preparation, passed-to-API signatures, 64-bit use, and null comparisons can establish a pointer/size type instead.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Predict prototype, CFG, outputs, and state for two opposite inputs; validate dynamically; test a third unseen input; document discrepancies and confidence.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 02 Low-Level Software Workbook

## Questions

1. Recover a loop from compare, conditional branch, body, increment, and back edge.
2. How do you distinguish signed and unsigned comparison on x86?
3. Why is RAX not one source variable throughout a function?
4. Infer an array access from [rdi+rcx*4+8].
5. Caller adds 12 to ESP after a call. What can you infer?
6. Translate an x87 expression safely.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Identify header and back edge; map induction variable and bound; prove initialization and exit; translate with exact signedness and test zero/one/max iterations.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Inspect conditional mnemonic and preceding flag-producing instruction: JL/JG use signed relations, JB/JA unsigned. Verify extensions and caller types.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Every write creates a new definition; calls also redefine return registers. Use def-use chains and liveness to split logical variables.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Candidate base is RDI, index RCX, four-byte elements, plus two-element/field offset. Confirm loop bounds, neighboring accesses, and type uses before finalizing.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Likely three 4-byte stack arguments with caller cleanup under a cdecl-like convention, but verify other pushes, alignment, variadic behavior, and multiple call sites.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Write the full x87 stack after every load, exchange, arithmetic operation, and pop; then build an expression tree and validate numerically.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 03 Windows Fundamentals Workbook

## Questions

1. Differentiate a HANDLE from a mapped view pointer.
2. How do Win32 and native APIs relate to system calls?
3. What evidence identifies a PE section mapping?
4. Why include exception edges in a CFG?
5. How do you identify process initialization versus application logic?
6. Design a file-mapping dynamic test.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Trace creation and cleanup: handles go to CloseHandle and index kernel objects; the view is a virtual address used for memory access and UnmapViewOfFile.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** A public API may validate/adapt arguments and call an NTDLL native API, whose stub transitions to kernel. Exact layering varies; follow the build’s calls.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Header virtual/raw fields, loader memory map, page permissions, relocations, and references. Translate RVA/VA/raw offsets explicitly.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Faults and language exceptions transfer to handlers/cleanup without ordinary branches. Omitting them mislabels reachable recovery code and resource lifetime.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Recognize runtime/loader setup, TLS, constructors, security-cookie initialization, and argument adaptation; follow the call into the program-specific entry.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Break at CreateFile, CreateFileMapping, MapView, unmap, and close; record each returned value/type, mapping permissions, and bytes at view; correlate with Ghidra call sites.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 04 Reversing Tools Workbook

## Questions

1. When should you distrust Ghidra’s function boundary?
2. What does a breakpoint prove?
3. How do you map a Ghidra RVA under PIE?
4. Why use a watchpoint?
5. What is the correct role of a decompiler?
6. Design a two-tool evidence loop.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** When calls enter mid-function, fall-through crosses it, epilogue/unwind evidence disagrees, padding/data is included, or decompilation has impossible stack/control state.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Only that execution reached an address in that run with observed state. It does not prove all callers, inputs, or paths.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Compute RVA from Ghidra image base; find runtime module base with vmmap; add them; validate with xinfo and instruction bytes.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** It stops at the instruction that reads/writes/accesses an exact location, connecting a corrupted field to its first mutation instead of only the later crash.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Generate a readable hypothesis. Verify widths, flags, branches, aliases, types, calls, and exceptions against assembly.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Static hypothesis and RVA in Ghidra; runtime breakpoint/watchpoint in pwndbg; record values/targets; update Ghidra types/edges; validate with unseen input.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 05 Beyond Documentation Workbook

## Questions

1. Why start with initialization and accessors?
2. How do indirect calls reveal callbacks?
3. How do you prove a count field?
4. Why maintain both tree and list?
5. What does a fixed returned-pointer adjustment mean?
6. Design duplicate-insertion tests.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** They write/read a small number of fields with obvious baseline semantics, creating labels that make complex insertion/deletion understandable.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Recover the function pointer field, arguments set before call, return use, and repeated call sites; derive prototype and role from that contract.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Find direct accessor, zero initialization, exactly one increment/decrement on successful insert/delete, and no mutation on lookup.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** The tree supports comparison-key search; list supports insertion-order ordinal access. Cross-linked nodes keep one payload in both representations.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Caller payload is likely embedded after an internal header. Confirm allocation size, metadata accesses before the pointer, and inverse adjustment in deletion.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Insert same comparison key with changed non-key bytes; observe count, allocation calls, returned pointer identity, status flag, and stored bytes.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 06 File Formats Workbook

## Questions

1. Why create identical archives twice?
2. How do you locate password verification?
3. How does a seek call identify a field?
4. How do you prove fixed versus variable records?
5. Write the safe offset-length check.
6. How do you validate a recovered parser?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** It reveals nondeterministic salts/IVs/timestamps, preventing false attribution of changing bytes to the variable being tested.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Trigger failure, break at message/output, backward-slice the controlling comparison, and trace archive/password inputs to both sides.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** If an entry-derived value is passed as file position and matches observed payload offset, it strongly supports offset semantics; validate absolute/relative base.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Vary name lengths and entry count; observe parser pointer increments, alignment rounding, and archive growth.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Require offset <= total, then length <= total-offset. This avoids overflow in offset+length.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Compare with program output across empty, multiple, boundary, malformed, and corrupted samples; use independent field and bounds checks.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 07 Binary Auditing Workbook

## Questions

1. State the proof chain for a vulnerability.
2. Why is a crash not code execution?
3. Explain count*size overflow.
4. Why can decode-after-filter fail?
5. How do signed lengths become huge?
6. How do you find first corruption?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Untrusted source, transformations, required invariant, missing/invalid check, first invalid instruction, reachability, controllability, impact, mitigations.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** A crash proves failure on one run; execution control requires evidence about corrupted control-sensitive state, influence, addresses, mitigations, and reliability.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Fixed-width product wraps to a smaller allocation while original count drives later writes. Check count <= SIZE_MAX/size before multiplying.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** The validator sees raw representation while sink sees canonical decoded bytes. Decode strictly first, validate canonical bytes, and use the same buffer.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** A negative signed value passes an incomplete upper bound, then conversion/sign extension to unsigned size produces a large count.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Establish object bounds, watch the first byte/field beyond them, run minimal benign input, and stop at the earliest crossing store.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 08 Malware Reversing Workbook

## Questions

1. What is the first malware-analysis step?
2. How do you validate an OEP?
3. How do you prove a command capability?
4. Polymorphism versus metamorphism?
5. How do you assign proxy socket roles?
6. Why is eradication a graph problem?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Containment: isolated disposable system, no production/public routing, captured telemetry, fake services, sample hash, snapshot, and stop condition.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Transfer follows decoding; destination contains coherent initialization, calls/references, stable original call graph, and meaningful runtime behavior.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Trace received bytes through framing/token comparison, authorization/preconditions, reachable handler, OS/API effects, and response.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Polymorphism changes encoding/decryptor with generally stable decoded payload; metamorphism rewrites executable semantics-preservingly.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Track socket returns: bind/listen descriptor, accept result, outbound connect descriptor, and paired receive/send forwarding loop.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Components/artifacts can restore each other. Record creator→artifact→trigger edges, stop creators, remove triggers/artifacts, and verify cycles are broken.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 09 Copy Protection Workbook

## Questions

1. What is a class break?
2. Why are signed licenses preferable to embedded symmetric generators?
3. What does SaaS change?
4. What does a hardware token not solve?
5. Watermarking versus DRM?
6. Design a protection threat model.

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** One technique defeats many protection instances, such as extracting a shared client master secret.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Clients hold only public verification material; client compromise does not reveal the private issuance key.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Valuable implementation/state remains server-side, shifting attack surface to accounts, APIs, authorization, availability, and server security.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** The client can still be patched to ignore a result; protocol, driver, physical, side-channel, and oracle misuse risks remain.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** DRM controls access/use; watermarking supports attribution/deterrence after distribution. They can complement each other.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Identify asset, adversary, access, goal, scale/class-break risk, offline/availability needs, privacy/usability cost, and acceptable delay/detection.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 10 Antireversing Workbook

## Questions

1. Why can encrypted code still be observed?
2. Linear sweep versus recursive traversal failure?
3. How do you analyze an antidebug check?
4. How do you prove an opaque predicate?
5. Recognize a table interpreter.
6. How do you normalize encoded variables?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** The processor needs usable instructions, creating a plaintext memory/execution window after decryption and before re-encryption.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Linear sweep decodes embedded data/desynchronizes; recursive traversal misses unresolved indirect targets.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Map sensor, interpretation, branch/state update, every downstream use, and consequence. Determine whether result also feeds a key.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Use algebra or bit-vector constraints at exact width, confirm dominating definitions/ranges, and test boundaries before deleting an edge.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Repeated dispatcher loop, opcode/state load, handler table indirect call/jump, next-state update, and termination rule.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Pair every writer encoder with reader decoder, simplify inverses under exact width, and validate logical values dynamically.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 11 Breaking Protections Workbook

## Questions

1. Why does flipping success branch fail?
2. What must a reliable patch account for?
3. What is required to reproduce a toy key relation?
4. How do you capture function-level plaintext?
5. How do you identify manual export resolution?
6. What makes a bounded key search valid?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Validation outputs may initialize state or decryption keys and be rechecked. Forced flow enters with invalid downstream state.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Correct decision semantics, whole instruction boundaries, VA/RVA/raw mapping, integrity checks, and later dependencies.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Exact normalization, encoding, width, recurrence, overflow, parsing/formatting, environment inputs, and final comparison.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Break after final decryption write or before call, dump range with base/context, observe return and re-encryption, validate coherent code.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Loader-list walk, PE export parsing, name/hash loop, ordinal/function table, and indirect call into known module range.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Small authorized space and strong low-false-positive oracle using several coherent-code/control/reference invariants, followed by manual validation.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 12 Reversing .NET Workbook

## Questions

1. Why does .NET decompile well?
2. Trace stfld.
3. Why callvirt on nonvirtual method?
4. How do you diagnose incompatible IL stacks at a merge?
5. How do you recover encrypted assembly?
6. What survives renaming?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Metadata retains types/member signatures and IL is a regular stack machine with CLR semantics.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Before stfld, stack contains object reference then value; instruction consumes both and writes the token-selected field.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Compiler may use callvirt for its null-check behavior even when dispatch target is not overridable.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Recheck CFG/exception edges and reachability; obfuscation/tool error or invalid/unverifiable IL may be involved.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Observe byte array after decrypt and before Assembly.Load/loader consumption; validate PE/CLR metadata in authorized isolated process.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Types/signatures, inheritance/interfaces, call graph, fields, constants, resources, attributes, and behavior.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Chapter 13 Decompilation Workbook

## Questions

1. Why is exact original source unrecoverable?
2. What must a correct IR preserve?
3. What is a phi node?
4. Why are registers not variables?
5. How do you infer a switch?
6. How do you validate a decompiler/lifter?

## Complete Solutions

### 1. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Compilation is many-to-one and discards names, comments, syntax choices, types, boundaries, and dead code.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 2. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Widths, flag semantics, memory/alias effects, calls, exceptions, control flow, and relevant ordering.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 3. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** SSA merge selecting the definition corresponding to the incoming CFG edge; it is analysis notation, not executed instruction.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 4. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Registers are reused and redefined. Def-use, liveness, spills/reloads, and calls reveal logical variable ranges.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 5. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Bound/normalization, scaled table access, indirect branch, valid targets, default edge, and case mapping.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

### 6. Solution

**What it tests:** the chapter’s core evidence method.
**Approach:** identify the relevant machine-level contract, then seek independent static and dynamic evidence.
**Step-by-step:** Differentially execute original and IR on varied inputs, comparing returns, memory effects, branches, flags/exceptions where relevant.
**Common wrong approach:** accepting a label, decompiler statement, or one execution trace without a counterexample test.

# Cumulative Case Questions

1. A packed network service decrypts a parser at runtime, allocates `count*entry_size`, then decodes URL escapes into entries. Build the full analysis plan.
2. A .NET loader decrypts a native DLL and calls an export through P/Invoke. Which managed and native boundaries must be captured?
3. An undocumented table API crashes only after duplicate insert/delete sequences. Which representations and invariants should be tested?
4. A license check passes after a patch but unlocked code is invalid. Build the dependency graph that explains this.
5. Your static decompiler misses a malware command handler observed dynamically. How do you reconcile the CFG?

# Cumulative Solutions

## 1

Contain first. Capture parser plaintext window; recover count and element-size widths; prove checked multiplication; reconstruct raw→decoded representation and destination capacity; watch first boundary crossing; map network source to parser; assess mitigations; fix arithmetic and canonicalization contracts.

## 2

Capture managed resource/decrypt buffer before `Assembly.Load` or file write; resolve P/Invoke metadata/signature; identify native module load/base/export RVA; break at native entry; validate ABI, buffers, return, exceptions, and ownership across CLR/native transition.

## 3

Model tree ordering, insertion-order list links, count, cache, duplicate status, payload/header ownership, and free callback. Build operation sequences and verify each invariant after every step with a local harness and watchpoints.

## 4

Trace validation result into branches, user-derived values, environment/timing state, decryption keys, encrypted range, and later checks. A branch patch changed control but not the correct key/state; recover the accepted relation and plaintext oracle.

## 5

Record runtime target/module/RVA; inspect the indirect dispatch state and table in memory; back-slice target computation; add the missing table/code region or dynamic-unpacking snapshot to Ghidra; correct code/data and CFG; test other commands to expand coverage.
