---
tags: [binary-analysis, capstone, disassembler, rop, chapter-notes]
chapter: 8
---

# Chapter 8 — Customizing Disassembly with Capstone

## Chapter overview

General disassemblers cannot anticipate every research question or obfuscation. This chapter uses Capstone as a decoder, implements linear and recursive passes, and builds a ROP-gadget scanner. The broader lesson is architectural: **decoding is a component, not the whole disassembler.**

## 8.1 Why customize?

Custom passes let you:

- incorporate target-specific entry points and data knowledge;
- skip known bogus paths or inline data;
- annotate domain-specific instructions;
- emit machine-readable IR/CFGs;
- measure or search instruction sequences;
- combine decoder output with runtime traces.

Obfuscation may create opaque predicates, junk bytes, misleading fall-through, overlapping streams, or indirect dispatch. A custom pass encodes a justified analysis policy, but it must label assumptions rather than silently forcing a preferred answer.

## 8.2 Capstone

Capstone converts bytes at a supplied address into decoded instruction objects. Configure architecture, mode, syntax, and detailed operand metadata.

Conceptual C flow:

```c
csh handle;
cs_insn *insn = NULL;
cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
size_t n = cs_disasm(handle, bytes, size, base, 0, &insn);
for (size_t i = 0; i < n; i++) {
    /* use address, size, bytes, id, mnemonic, operands */
}
cs_free(insn, n);
cs_close(&handle);
```

### Linear pass

Decode an entire candidate region. On failure, choose an explicit policy: stop, emit data byte, or resynchronize. Continuing one byte later improves coverage but can manufacture code.

### Recursive pass

Maintain a worklist and visited-address/block sets. Classify decoded terminators:

| Instruction | Successors |
|---|---|
| ordinary | next instruction |
| direct call | callee plus fall-through (policy-dependent) |
| conditional branch | target and fall-through |
| unconditional direct jump | target |
| return | none intraprocedurally |
| indirect jump/call | resolved target set or unresolved marker |

Never recursively follow a direct target outside mapped executable ranges without a reason. Split blocks when a newly discovered target lands inside a previously decoded block.

## 8.3 ROP gadget scanning

Return-oriented programming chains short sequences ending in a control-transfer such as `ret`. The book scans backward from return opcodes because gadgets may begin at instruction offsets not chosen by ordinary function disassembly.

Authorized defensive scanner logic:

1. enumerate executable file-backed ranges;
2. locate candidate terminator bytes;
3. for each maximum backward length, decode from candidate starts;
4. accept only sequences whose final decoded instruction ends exactly at the terminator boundary;
5. constrain gadget length/instruction count;
6. deduplicate by bytes/address/semantics;
7. annotate side effects and unusable operations.

Why decode backward candidates rather than reverse-decode x86? x86 has no unique backward instruction boundary. Try possible starts and accept forward decodings that align exactly.

### Gadget quality

`pop rdi; ret` changes `rdi` and `rsp`; it also consumes stack bytes. A useful gadget must be evaluated for:

- changed registers/flags/memory;
- stack delta and alignment;
- memory dereferences that can fault;
- bad-byte address constraints;
- PIE/ASLR address availability;
- control-flow protections.

The scanner finds sequences; it does not prove a viable exploit chain.

## Added worked recursive example

```asm
1000: cmp edi, 3
1003: ja  1010
1005: call 1100
100a: jmp 1020
1010: xor eax,eax
1012: ret
1020: add eax,1
1023: ret
```

Seed `1000`. The conditional discovers `1010` and `1005`; the call records `1100` and continues at `100a`; the jump discovers `1020`. Function policy decides whether `1100` belongs to a separate CFG. The result cannot be obtained safely by merely decoding sequentially through address gaps.

## Common mistakes

- Treating Capstone as a binary loader or CFG recovery engine.
- Omitting detail mode and parsing operand text strings.
- Following branch targets outside validated executable mappings.
- Failing to split blocks on interior targets.
- Scanning gadgets only from ordinary instruction boundaries.
- Reporting gadgets without side effects or mitigation context.

## Practice questions

1. What responsibilities remain after Capstone decodes instructions?
2. Why must recursive traversal store unresolved indirect edges?
3. How do overlapping streams affect visited-address logic?
4. Why does backward gadget search require forward validation?
5. Design a semantic deduplication key for gadgets.
6. Explain how a runtime trace can improve a custom disassembler without becoming complete.

## Solutions

1. File loading, code/data selection, seeds, CFG/function recovery, target resolution, error policy, annotations, and output.
2. Dropping them falsely claims no successor; retaining unknown edges preserves an explicit analysis limitation.
3. One address can begin a valid alternate stream; a policy that marks every covered byte visited may hide it. Track starts/streams and document overlap policy.
4. x86 variable-length encoding lacks a unique predecessor instruction; only decoding from a proposed start proves exact alignment to the terminator.
5. Normalize instruction IDs/operand effects, stack delta, clobbers, memory effects, and terminal behavior; keep addresses as occurrences.
6. Observed targets and generated code are valid seeds for those runs, but unexecuted states can still have other targets/code.

## Mastery checklist

- [ ] Use Capstone detail metadata rather than parsing text.
- [ ] Implement worklist recursive traversal and block splitting.
- [ ] Preserve unresolved targets and confidence labels.
- [ ] Explain/implement bounded gadget discovery on a toy binary.
