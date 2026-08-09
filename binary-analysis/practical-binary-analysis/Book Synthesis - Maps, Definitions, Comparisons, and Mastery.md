---
tags: [binary-analysis, revision, concept-map, question-bank]
---

# Book Synthesis — Maps, Definitions, Comparisons, and Mastery

## A. Complete concept map

```text
Program semantics
├── represented by executable formats
│   ├── headers/tables
│   ├── code/data/symbols/relocations
│   └── runtime mappings and dynamic resolution
├── recovered by analysis
│   ├── static decoding → CFG → data flow
│   └── dynamic execution → observed targets/values/coverage
├── changed/observed by instrumentation
│   ├── patch/interpose/inject
│   └── static trampoline or dynamic code cache
└── reasoned about automatically
    ├── taint: provenance/influence on one execution
    └── symbolic: constraints representing sets of inputs/paths
         └── solver models → concrete replay
```

## B. Master summary

Binary analysis begins below source names. Executable formats record architecture, entry, mappings, code/data, symbols, and relocation relationships. A loader normalizes these bytes; a disassembler proposes instruction boundaries and control flow; data-flow analysis connects definitions to uses. Dynamic traces confirm executed code and concrete targets but cover only exercised states.

Modification and instrumentation turn hypotheses into measurements. Static rewriting must preserve file layout, addressability, ABI state, and relocated semantics. DBI instead translates execution and inserts callbacks, trading transparency/performance for flexible observation.

DTA tracks source labels to sinks under a propagation policy and concrete path. Symbolic execution builds expressions and path constraints, using bitvector solvers to find new inputs. Both are models with explicit false-positive/negative boundaries. Security work connects them to a precise violated invariant and demonstrates a constrained primitive before claiming impact.

## C. Essential definitions

| Term | Definition |
|---|---|
| object file | relocatable machine code/data plus symbols/relocations |
| symbol | named addressable entity described in metadata |
| relocation | rule for fixing a location when a symbol/layout becomes known |
| section | linker/analysis-oriented content region |
| segment | runtime mapping unit described by program header |
| VMA/VA | address in virtual memory model/runtime |
| file offset | byte position in stored file |
| RVA | PE image-relative virtual address |
| basic block | single-entry straight-line instruction sequence ending at transfer |
| CFG | blocks and possible control-flow edges |
| IR | normalized semantic representation of instructions |
| DBI | runtime translation/insertion of analysis behavior |
| taint source/sink | origin of labels/security-relevant place checked |
| shadow memory | metadata mapping parallel to application memory |
| path constraint | conjunction of branch predicates for a symbolic path |
| bitvector | fixed-width modular machine-integer value |
| primitive | demonstrated capability such as controlled read/write/leak/control |

## D. Formula sheet

### ELF VA to file offset

```text
offset = p_offset + (VA - p_vaddr)
```

Only for a chosen `PT_LOAD` and `VA` inside its file-backed interval.

### PE RVA to file offset

```text
offset = PointerToRawData + (RVA - Section.VirtualAddress)
```

Only for a file-backed location in the containing section.

### Relative branch/call displacement

```text
disp = target - address_after_instruction
```

Must fit encoded signed width.

### Overflow-safe range

```text
offset ≤ size AND length ≤ size - offset
```

### Allocation multiplication

```text
count ≤ SIZE_MAX / element_size
```

before `count * element_size`.

### Reaching definitions

```text
IN[B]  = ⋃ OUT[pred]
OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
```

### Runtime module offset

```text
mapping_file_offset + (runtime_address - mapping_start)
```

then relate through the image’s load mapping.

## E. Workflow sheet

### Unknown binary

```text
authorize/isolate → hash/identify → headers/mappings/mitigations
 → imports/strings → static entry/CFG → controlled runtime trace
 → focused data flow → validate hypotheses → report unknowns
```

### Vulnerability

```text
source → validation → transformation → sink
 → first violated invariant → control → primitive
 → mitigations/environment → benign proof → repair/regression
```

### Tool development

```text
define property → normalized model → correct semantics
 → explicit approximation policy → hostile tests → differential validation
 → performance measurement → document limits
```

## F. Comparison tables

### Static versus dynamic

| Feature | Static | Dynamic |
|---|---|---|
| coverage potential | all modeled paths/bytes | executed paths only |
| concrete values | approximated | observed |
| generated code | hard before execution | visible when executed |
| indirect targets | approximate | concrete for run |
| environment risk | low if parser safe | executes target |

### Taint versus symbolic

| Feature | Taint | Symbolic |
|---|---|---|
| central question | did source influence sink? | which values satisfy/reach path? |
| value representation | concrete + labels | concrete and/or expressions |
| branching | follows concrete run unless extended | forks/negates constraints |
| main risk | over/undertaint | path explosion/model mismatch |

### Bug, primitive, impact

| Layer | Example |
|---|---|
| bug | copy can exceed 32-byte buffer |
| control | input predictably overwrites saved word |
| primitive | saved return target controlled |
| impact | benign `win()` reached under exact lab protections |

## G. Common mistakes across the book

1. File offset, static VA, and runtime VA conflation.
2. Section names trusted over mappings and references.
3. Decompiled output treated as source truth.
4. One trace treated as complete.
5. One decoder failure “repaired” silently.
6. Labels/solver models treated as reality beyond policy.
7. Mitigations inferred rather than measured.
8. Crash equated with exploitable impact.
9. Tool output collected without a question.
10. Exact binary/library/environment omitted from reports.

## H. If you see this, think this

| Observation | Investigate |
|---|---|
| `p_memsz > p_filesz` | zero-fill/BSS-like memory |
| `ET_DYN` executable | likely PIE; determine runtime base |
| indirect jump after bounds check | jump table/switch |
| tiny imports + high entropy + write→execute | packer or generated code |
| `movzx` then unsigned branch | unsigned width semantics |
| input controls length | validate against actual source and destination sizes |
| stale pointer after `free` | lifetime aliases and reuse |
| tainted sink | influence proven under policy; validate security invariant |
| solver says `sat` | model has candidate; replay concretely |
| many valid decodings | boundary ambiguity, inline data, obfuscation |

## I. Cumulative mastery questions

1. A stripped PIE opens a file, decrypts bytes into an anonymous mapping, calls `mprotect`, then jumps there. Design a complete analysis plan from ELF metadata through unpacked CFG recovery.
2. A parser checks a 32-bit count, stores it in 16 bits, allocates, and loops using the original value. Explain static evidence, DTA policy, symbolic goal, primitive, and repair.
3. Design a custom disassembler that consumes dynamic traces without treating observed targets as the complete CFG.
4. Compare an ELF GOT import and PE IAT import at file, relocation, runtime, and hardening levels.
5. A DTA detector reports secret-file color in TLS ciphertext. What is proven, what is not, and how would policy/context reduce false alarms?
6. A symbolic engine says a branch is unreachable, but fuzzing reaches it. List model failures in debugging order.
7. Explain how injecting a trampoline can break RIP-relative code and how to validate the repair.
8. Given a crash after `free`, distinguish heap overflow, UAF, double free, and allocator misuse using temporal evidence.
9. Build an exploitability argument for partial pointer overwrite under ASLR without overstating reliability.
10. Explain why section headers can be useless while program headers still allow execution and dynamic tracing.

## J. Cumulative solutions

1. Hash/isolate; inspect load/interpreter/entry/mitigations; trace mappings/writes/protection changes; record transfer into written range; dump mapping and loader state; normalize runtime addresses; seed static recursive analysis with observed entry/targets; retain unknown/unexecuted edges; reconstruct imports if a runnable file is needed.
2. Recover widths/instructions and allocation/copy loop; taint count source into allocation/addresses; symbolize count to reach first OOB write using bitvectors; prove only the actual write primitive; repair with one `size_t`, checked multiplication, and maximum; regression-test boundaries.
3. Store static candidate edges and observed edges with separate confidence/provenance. Trace seeds generated code/indirect targets; recursive analysis still explores direct alternatives; unresolved edges remain explicit.
4. Both enable imported-address resolution, but ELF uses dynamic symbols/relocations and GOT/PLT conventions while PE uses import descriptors/thunks/IAT. Loader algorithms, base relocations, lazy binding, and protection flags differ.
5. Under the explicit policy/run, secret-derived labels reached bytes passed to network output. It does not prove unauthorized destination or plaintext recovery. Add allowed destination/process/context, correct crypto propagation expectations, and descriptor identity.
6. Verify exact binary/input; unsupported instruction; stale syscall/memory model; wrong width/signedness; overconstraint from old path; concretization; environment/ASLR; threads/signals/self-modification; solver result interpretation.
7. Relative operands encode from original location. Decode displaced instructions, compute semantic targets, re-encode at trampoline or synthesize absolute sequence, then disassemble and single-step with state comparison.
8. Watch first invalid transition: prior OOB write corrupts later allocator; UAF accesses after one valid free; double free ends same allocation twice; misuse passes non-allocation/interior pointer. Allocation-generation timelines distinguish them.
9. State exact low bytes controlled, stable page offsets, randomized unknown bits, attempts/restart control, crash effect, and measured success probability across clean runs; do not label deterministic RCE without evidence.
10. Kernel maps using program headers. Section tables are for linking/analysis and may be absent/corrupt. Once mapped, dynamic tracing observes executed addresses/bytes independently of section names.

## Final mastery checklist

- [ ] Explain the whole path from C source to executed instruction.
- [ ] Parse and compare ELF/PE address models.
- [ ] Recover CFG/data flow while labeling uncertainty.
- [ ] Build both static and dynamic disassembler prototypes.
- [ ] Instrument blocks and detect written-then-executed code.
- [ ] Design taint sources/sinks/policies with false-result analysis.
- [ ] Solve and replay bitvector path constraints.
- [ ] Analyze vulnerabilities from invariant to mitigation-aware benign proof.
