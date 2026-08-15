# Reversing — Final Reference and Complete Concept Map

## A. Complete Concept Map

```text
observable program
│
├── representation
│   ├── executable format, sections, imports, metadata
│   ├── machine instructions, ABI, stack, heap, globals
│   └── managed IL/metadata or native code
│
├── behavior recovery
│   ├── static code discovery and CFG
│   ├── dynamic registers/memory/targets
│   ├── structures, types, algorithms, protocols, formats
│   └── pseudocode validated by test vectors
│
├── hostile/defensive conditions
│   ├── malformed input → vulnerability invariant
│   ├── packing/encryption → runtime exposure window
│   ├── antidebug/obfuscation → normalize semantics
│   └── persistence/communication → behavior graph
│
└── advanced reconstruction
    ├── undocumented API contract
    ├── decompilation IR/SSA/type recovery
    ├── static/dynamic disassembler implementation
    └── evidence-backed report and regression
```

## B. Master Summary

Reverse engineering is constrained inference. Begin with binary identity and architecture, define the question, map the executable and observable behavior, then move from stable anchors—imports, strings, entry points, error messages, known APIs—to internal functions. Every name, type, structure, or algorithm begins as a hypothesis. Static analysis supplies path breadth; dynamic analysis supplies exact state for executed paths. Cross-check them.

At the machine level, meaning emerges from widths, signedness, calling convention, data flow, control flow, and memory lifetime. Registers are temporary storage, not variables. Decompiler output is editable analysis, not original source. Structure fields become credible when the same offsets have consistent roles across functions, allocations, and runtime observations.

Applied reversing connects code to external representations. For undocumented APIs, combine several functions to recover one shared contract. For file formats and protocols, create controlled samples, correlate file/network offsets with runtime buffers, and build a bounds-safe parser. For vulnerabilities, prove an attacker-controlled source, transformation chain, missing invariant, first invalid instruction, reachability, and impact. For malware, contain first, then reconstruct installation, persistence, communication, dispatch, capabilities, and cleanup.

Protection and antireversing techniques raise cost by removing names, delaying plaintext, detecting observation, confusing instruction discovery, or transforming control/data. They cannot remove the runtime need for usable code and state. Find invariant exposure boundaries, map sensor-to-consequence dependencies, and normalize equivalent semantics.

Managed code retains metadata and stack-based IL, improving decompilation. Native decompilation requires a pipeline: decode, lift to explicit IR, construct CFG, compute data flow/SSA, infer variables and types, recover structured control, and emit cautious pseudocode. Semantic differential testing—not prettiness—validates the result.

## C. Essential Definitions

| Term | Definition |
|---|---|
| ABI | binary contract for calls, registers, stack, return, and data layout |
| basic block | maximal straight-line sequence with one entry and terminal control transfer |
| CFG | graph of basic blocks and possible control-flow edges |
| calling convention | ABI rules for parameters, returns, preserved registers, and stack cleanup |
| RVA | address relative to an image/module base |
| VA | runtime virtual address |
| inference | explanation supported by observations but not directly observed |
| invariant | property that must hold for correct/security-safe behavior |
| backward slice | instructions/data influencing a chosen value or decision |
| data flow | movement and transformation of values through definitions and uses |
| SSA | IR where every definition has a unique version; merges use φ nodes |
| splay tree | search tree rotating accessed nodes toward root |
| OEP | original program entry after an unpacking layer |
| polymorphism | changing encoding/decryptor with broadly stable decoded payload |
| metamorphism | semantics-preserving rewriting of executable body |
| opaque predicate | condition with predetermined result hidden by complex expression |
| verifier | stored/derived value used to accept or reject a secret/input |
| class break | one bypass that scales across many protected instances |
| IL | .NET stack-based intermediate language |
| metadata token | managed reference into type/member/string metadata tables |
| lifter | translator from machine instructions to analysis IR |

## D. Formula and Address Sheet

### RVA/VA

\[
RVA = VA - imageBase
\]

\[
runtimeVA = runtimeModuleBase + RVA
\]

### PE raw offset

\[
rawOffset = section.PointerToRawData + (RVA - section.VirtualAddress)
\]

Use only for an RVA inside the section’s raw-backed region.

### Array address

\[
address = base + index \times elementSize
\]

### Row-major 2D array

\[
address = base + (row \times columnCount + column) \times elementSize
\]

### Unsigned fixed-width arithmetic

\[
stored = mathematicalResult \bmod 2^w
\]

### Safe multiplication

```c
if (count > SIZE_MAX / element_size) fail();
bytes = count * element_size;
```

### Safe range

```c
if (offset > total) fail();
if (length > total - offset) fail();
```

## E. Process and Workflow Sheet

### Unknown binary

1. Hash and preserve sample.
2. Identify format, architecture, endianness, compiler/runtime, mitigations.
3. Map sections, entry, imports/exports, resources, strings.
4. Run controlled baseline behavior.
5. Choose an anchor connected to the question.
6. Build call/data/CFG slices.
7. Recover ABI, parameters, structures, and algorithm.
8. Validate in GDB/pwndbg with opposite-path test vectors.
9. Return confirmed types/names/edges to Ghidra.
10. Report facts, inferences, uncertainties, and reproducible evidence.

### Vulnerability

1. Identify untrusted source.
2. Annotate widths, signedness, units, encoding, lifetime.
3. Follow transformations into allocation/copy/index/call.
4. State required safety invariant.
5. Find the missing/invalid check.
6. Stop at first invalid access with a benign marker/watchpoint.
7. Assess reachability, controllability, privilege, and mitigations.
8. Fix root cause and test adjacent boundaries.

### File format

1. Create differential specimens.
2. Record sizes/hashes and diff offsets.
3. Trace I/O APIs to buffers.
4. Trace decrypt/decode/parse.
5. infer fields from uses.
6. write bounds-safe dumper.
7. test valid, boundary, and malformed corpus.

### Malware

1. Isolate and simulate network.
2. Static triage and packing assessment.
3. Capture post-unpacking state.
4. Reconstruct install/persistence.
5. Recover protocol and dispatch.
6. Map capabilities and cleanup.
7. produce behavior/indicator/confidence tables.
8. eradicate every persistence edge.

## F. Comparison Tables

### Static versus dynamic

| Feature | Static | Dynamic |
|---|---|---|
| coverage | discovered paths | executed path only |
| values | inferred/ranged | concrete |
| hidden runtime code | limited | visible when exposed |
| environment effects | indirect | observable |
| main risk | false code/types/edges | incomplete coverage/debugger effects |

### Stack versus heap overflow

| Feature | Stack | Heap |
|---|---|---|
| object origin | frame-local | allocator |
| layout driver | compiler/ABI | allocator/order |
| common adjacent state | locals/cookie/control metadata | objects/allocator metadata |
| proof | frame capacity + first crossing store | allocation range + first crossing store |

### Signed versus unsigned

| Evidence | Signed | Unsigned |
|---|---|---|
| extension | MOVSX | MOVZX |
| less branch | JL | JB |
| greater branch | JG | JA |
| overflow concern | OF | CF |

### Ghidra versus GDB/pwndbg

| Task | Ghidra | GDB/pwndbg |
|---|---|---|
| complete static CFG | primary | one trace |
| types/structures | persistent markup | validate addresses/values |
| runtime indirect target | hypothesis | exact target |
| memory map under ASLR | static image | runtime `vmmap` |
| first mutation | inferred store | watchpoint |
| final workflow | hypothesis database | experiment engine |

## G. Common Mistakes

- Trusting decompiler types or source syntax.
- Naming from one observation.
- Confusing runtime VA with file offset.
- Treating registers as stable variables.
- Ignoring signedness, width, units, and encoding.
- Following only success paths.
- Calling a crash an exploit.
- Treating packing as proof of malware.
- Removing an antidebug branch without tracking key/state use.
- Parsing untrusted formats without checked arithmetic.
- Completing labs by copying commands instead of predicting state.

## H. Important Examples

- Generic table: cross-function recovery of structures/callbacks/invariants.
- Cryptex: controlled specimens plus runtime I/O/decryption correlation.
- IIS case: representation/length contract mismatch.
- Backdoor.Hacarmy.D: unpacking-to-capability reconstruction.
- Defender: interdependent timing, keys, encrypted functions, and threads.
- .NET list: evaluation-stack and object-field recovery.
- SSA example: reused register becomes unique logical definitions.

## I. If You See This, Think This

| Observation | Consider |
|---|---|
| fixed pointer adjustment before return | hidden node header/subobject |
| repeated offsets across functions | shared structure |
| indirect call through object/table | callback/vtable/dispatcher |
| `MOVSX` then size API | signed-to-size conversion risk |
| multiply then allocation | integer overflow and units |
| decode after filter | canonicalization bypass |
| memory becomes executable after writes | unpacked/generated code |
| manual loader/export traversal | hidden API resolution |
| repeated central switch/state | flattened control/VM |
| decompiler condition conflicts with branch mnemonic | type/signedness error |
| pointer used after free call | lifetime violation |
| changed code makes later decrypt fail | checksum/key dependency |
| IL merge has incompatible stacks | CFG/tool/obfuscation problem |

## J. Final Mastery Gate

You are ready for unfamiliar binaries when you can:

- [ ] predict machine state before debugger confirmation;
- [ ] recover an ABI contract from stripped code;
- [ ] reconstruct structures across multiple functions;
- [ ] reverse a format into a safe independent parser;
- [ ] prove and fix vulnerability invariants;
- [ ] analyze contained malware into behavior graphs;
- [ ] normalize anti-reversing without losing semantics;
- [ ] trace IL and native IR/SSA;
- [ ] implement and test static/dynamic disassembler components;
- [ ] write a report where every important claim has evidence and a falsification test.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]], the three mentor-code volumes, and [[Reversing - Complete Practice Workbooks]] together.
