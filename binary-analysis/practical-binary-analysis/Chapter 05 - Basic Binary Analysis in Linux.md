---
tags: [binary-analysis, linux, triage, gdb, chapter-notes]
chapter: 5
---

# Chapter 5 — Basic Binary Analysis in Linux

## Chapter overview

This chapter combines ordinary GNU/Linux tools into an investigation. The important lesson is not memorizing commands; each tool answers a different question, and conclusions become reliable when independent views agree.

```text
identity → dependencies → raw bytes → structured metadata
 → symbols/strings → external behavior → instructions → runtime memory
```

## 5.1 `file` — identify before interpreting

```bash
file ./sample
```

It may report container, architecture, endianness, bitness, linking, interpreter, stripping, and sometimes build identifiers. This selects the correct decoder and environment.

**Limits:** signatures and metadata can be malformed or deceptive. Confirm important claims with `readelf`, magic bytes, and a format-aware parser.

## 5.2 `ldd` — dependencies, with a safety warning

```bash
ldd ./trusted-sample
readelf -dW ./unknown-sample | rg NEEDED
```

`ldd` shows how dependencies resolve in the current environment. Resolution can change with interpreter, RPATH/RUNPATH, environment, cache, architecture, and working context.

> [!warning] Unknown binaries
> Do not casually run `ldd` or the program on a hostile sample. Use static dynamic-section inspection first and work in an isolated VM. The general rule is to avoid analysis steps that can invoke target-controlled behavior outside containment.

What dependency data tells you: available APIs and runtime assumptions. What it does not prove: that every imported routine executes or that libraries are benign.

## 5.3 `xxd` — preserve the byte-level truth

```bash
xxd -g1 -l 128 ./sample
xxd -g1 -s 0x1000 -l 64 ./sample
```

A hex dump verifies magic, headers, embedded data, padding, and patches. Always label file offsets separately from virtual addresses.

## 5.4 `readelf` — parse ELF structures

```bash
readelf -hW sample       # ELF header
readelf -lW sample       # segments
readelf -SW sample       # sections
readelf -Ws sample       # symbols
readelf -rW sample       # relocations
readelf -dW sample       # dynamic tags
readelf -x .rodata sample
```

Ask one question per view: Where is entry? What becomes executable memory? Which imports require relocation? Which initialization routines run before `main`?

## 5.5 `nm` — symbols

```bash
nm -an sample
nm -D sample
nm -C cpp-sample
```

Letter codes summarize defined/undefined and rough section/class. `-D` uses dynamic symbols; `-C` demangles C++ names. A lowercase/uppercase code often encodes local/global distinctions, but consult the tool semantics instead of guessing.

## 5.6 `strings` — leads, not behavior

```bash
strings -a -n 4 -t x sample
strings -a -el sample          # UTF-16LE-like strings when supported
```

High-value clues include usage text, errors, paths, URLs, formats, protocol markers, keys/labels, and compiler artifacts. Follow cross-references. A string can be dead, encrypted only at runtime, split across buffers, or a deliberate decoy.

## 5.7 `strace` and `ltrace` — external behavior

```bash
strace -f -s 256 -yy -o trace.log -- ./authorized-sample arg
ltrace -f -s 256 -o calls.log -- ./authorized-sample arg
```

`strace` observes the process/kernel interface: files, memory, processes, signals, and network syscalls. `ltrace` observes many dynamically linked library calls. Neither automatically explains causation; neither guarantees complete coverage.

### Worked interpretation

```text
openat(..., "config.bin", O_RDONLY) = 3
read(3, "PBA\1...", 64) = 32
write(2, "bad version\n", 12) = 12
```

Facts: a path was opened, 32 bytes were read, and an error was written. Hypothesis: a field in those bytes failed a version check. Next test: change one controlled version byte and break at the comparison.

## 5.8 `objdump` — instruction-level view

```bash
objdump -d -Mintel sample
objdump -drwC -Mintel object.o
objdump -s -j .rodata sample
```

Use relocation-aware output for object files. Examine call arguments using the ABI, not just function names. A call to `memcmp` matters only after discovering both buffers and length.

## 5.9 GDB — dump data at the moment meaning appears

The chapter demonstrates recovering a dynamically constructed string. The general pattern is:

1. find a call that consumes the buffer;
2. break just before/at that call;
3. inspect argument registers;
4. dump the buffer according to its type;
5. repeat with controlled inputs.

```gdb
set disassembly-flavor intel
break puts
run
x/s $rdi
x/32bx $rdi
bt
```

For System V AMD64 integer/pointer arguments: `rdi, rsi, rdx, rcx, r8, r9`; return value `rax`. Validate mappings before dereferencing an inferred pointer.

## Complete triage workflow

```bash
sha256sum sample
file sample
readelf -hW sample
readelf -lW sample
readelf -dWrWs sample
strings -a -n 4 -t x sample
objdump -d -Mintel sample
```

Only inside authorization/containment:

```bash
strace -f -s 256 -yy -o strace.log -- ./sample test
gdb -q ./sample
```

Record facts, inference, hypothesis, next test. Do not dump output without interpreting it.

## Tool comparison

| Tool | View | Strong at | Blind spot |
|---|---|---|---|
| `file` | identity | fast classification | spoofed/ambiguous metadata |
| `readelf` | structure | exact ELF tables | behavior |
| `nm` | symbols | name/address inventory | stripped code |
| `strings` | byte patterns | fast semantic leads | reachability/context |
| `strace` | syscalls | OS-visible effects | internal computation |
| `ltrace` | library calls | arguments to dynamic APIs | inline/static/direct calls |
| `objdump` | instructions | static code view | runtime values/coverage |
| GDB | live state | causal focused tests | only exercised execution |

## Practice questions

1. Why should `readelf -d` precede `ldd` for an unknown sample?
2. A URL appears in `strings`; list three tests before claiming network behavior.
3. `strace` shows `read` returning 12. Which register contains the return value on AMD64?
4. How would you capture a buffer passed to `write(fd, buf, count)`?
5. Why can `ltrace` miss a comparison visible in disassembly?
6. Design a five-step test for a suspected file-format magic check.

## Solutions

1. Static metadata inspection reduces execution risk; `ldd` reflects current runtime resolution and historically can be unsafe on hostile inputs.
2. Find xrefs, prove reachable code uses it, trace/observe the relevant connect/send path in isolation, and vary inputs/configuration.
3. `rax`; negative kernel-style values are interpreted by the libc wrapper as appropriate.
4. Break at the call/syscall boundary, read `rsi` as address and `rdx` as length, dump bounded bytes, and confirm `rdi` channel identity.
5. It may be inlined, statically linked, hidden, implemented directly, or not executed in that run.
6. Locate candidate bytes/string, find xref, identify comparison and length, test exact/one-byte-wrong/truncated inputs, and observe branch outcome dynamically.

## Mastery checklist

- [ ] Choose tools by analytical question.
- [ ] Separate file offsets, static VAs, and runtime addresses.
- [ ] Interpret traces as evidence, not automatic explanations.
- [ ] Recover one dynamically built buffer in GDB.
- [ ] Produce a reproducible triage report.

## Extended chapter synthesis

**Key idea:** each tool is a lens over identity, structure, bytes, symbols, external behavior, instructions, or live state; confidence comes from correlated lenses.

**Key process:** hash/identify → parse without executing → collect semantic leads → isolate and trace → disassemble focused paths → inspect decisive runtime values → report facts/inferences.

**Common confusion:** an import/string/trace event is evidence of capability/data/one execution, not a complete behavioral explanation.

**You should be able to solve:** unknown-ELF triage, address-space translation, import/string xrefs, syscall-to-call-site correlation, and dynamic-buffer recovery.

Full 48-question set with worked solutions: [[Workbooks/Chapter 05 - Practice and Complete Solutions]].
