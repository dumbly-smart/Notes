# Binary Loading and Linux Analysis

This note transitions from understanding executable formats to building and using analysis infrastructure.

---

## Topic 9 — Designing a binary loader with libbfd

### What “binary loader” means in this context

Here, a binary loader is an analysis component that opens an executable and converts its format-specific details into a convenient in-memory representation. It is not the operating-system loader that creates a running process.

The book uses **libbfd**, the Binary File Descriptor library from GNU binutils. It provides a common interface over multiple object and executable formats.

### Why use an abstraction?

Without a library, an ELF parser must:

1. read and validate the ELF header;
2. account for 32-bit versus 64-bit layouts;
3. account for endianness;
4. locate and parse section headers;
5. resolve names through string tables;
6. parse symbols and relocations;
7. perform careful bounds checking;
8. repeat similar work for PE or another format.

libbfd handles much of this format-specific parsing. Our analysis code can work with higher-level concepts such as sections and symbols.

### Core data model

A useful simplified design has three classes or structures:

```text
Binary
├── filename
├── type / architecture / bit width
├── entry point
├── sections[]
└── symbols[]

Section
├── name
├── type
├── virtual address
├── size
├── raw bytes
└── flags: code/data/read/write/execute

Symbol
├── name
├── type
└── address
```

This representation will later feed disassembly and other custom analysis passes.

### Loader pipeline

```text
Open file with BFD
      ↓
Verify recognized object format
      ↓
Determine architecture and bit width
      ↓
Read entry point
      ↓
Enumerate sections and copy relevant bytes
      ↓
Read static and/or dynamic symbols
      ↓
Normalize into our Binary representation
```

### Address lookup

The loader should support operations such as:

- find a section by name;
- find the section containing a virtual address;
- find a symbol by name;
- find the nearest symbol to an address;
- translate a section-relative offset into a virtual address.

These helpers prevent later tools from repeatedly reimplementing address logic.

### Trust boundary

Binary parsers process attacker-controlled data. A robust loader must distrust:

- offsets outside the file;
- integer overflow in offset-plus-size calculations;
- impossible entry counts;
- overlapping ranges;
- unterminated strings;
- inconsistent architecture or format fields.

libbfd reduces parsing work but does not eliminate the need to validate assumptions and handle errors.

### Abstraction cost

A common-format API can hide details unique to ELF or PE. Therefore:

- use the abstraction for common analysis;
- retain raw format-specific access when necessary;
- understand the underlying format before trusting a library's interpretation.

### Check

1. How does an analysis loader differ from the operating system's loader?
2. What information should a `Section` object expose to a disassembler?
3. What format-specific detail might be lost through a common abstraction?

---

## Topic 10 — Basic Linux binary-analysis workflow

The important skill is not memorizing commands. It is asking progressively better questions while minimizing assumptions.

### Safe first-pass workflow

```text
Identify
   ↓
Inspect metadata
   ↓
Inspect human-readable clues
   ↓
Inspect symbols and dependencies
   ↓
Disassemble
   ↓
Observe behavior in isolation
   ↓
Debug specific hypotheses
```

Never execute an untrusted binary directly on the host. Use an isolated environment designed for analysis.

### 1. Identify with `file`

```bash
file ./target
```

It may reveal:

- ELF or PE format;
- architecture and bit width;
- endianness;
- executable, shared object, or relocatable object;
- static or dynamic linking;
- whether symbols appear stripped.

This creates initial hypotheses; it is not proof that the file is honest or safe.

### 2. Inspect raw bytes with `xxd`

```bash
xxd -l 128 ./target
xxd ./target | less
```

Use this to:

- verify magic bytes;
- inspect exact encodings;
- correlate parsed fields with file offsets;
- compare a file before and after modification.

### 3. Parse ELF metadata with `readelf`

```bash
readelf -h ./target
readelf -S ./target
readelf -l ./target
readelf -s ./target
readelf -r ./target
readelf -d ./target
```

These answer different questions:

| Option | Question |
|---|---|
| `-h` | What kind of ELF is this? |
| `-S` | Which sections exist? |
| `-l` | How will it be mapped into memory? |
| `-s` | Which symbols are recorded? |
| `-r` | Which locations require relocation? |
| `-d` | What dynamic-linking metadata exists? |

### 4. Inspect symbols with `nm`

```bash
nm ./target
nm -D ./target
nm -C ./target
```

- `-D` shows dynamic symbols;
- `-C` demangles C++ names.

Symbols can reveal major functions and dependencies, but stripped binaries provide much less information.

### 5. Search strings

```bash
strings -a -n 5 ./target
```

Strings may reveal:

- paths;
- URLs and domains;
- error messages;
- command names;
- configuration keys;
- compiler or packer clues.

Strings are clues, not confirmed behavior. A string can be unused, misleading, encoded, encrypted, or constructed at runtime.

### 6. Inspect dependencies

For a trusted binary:

```bash
ldd ./target
```

For static inspection:

```bash
readelf -d ./target
objdump -p ./target
```

Dependencies suggest available capabilities but do not prove how a library is used.

### 7. Disassemble with `objdump`

```bash
objdump -d -M intel ./target
objdump -D -M intel ./target
```

- `-d` disassembles expected code sections;
- `-D` attempts to disassemble all sections and can interpret data as code.

Focus on questions such as:

- where does control flow begin?
- which external functions are called?
- where are comparisons and branches?
- which strings or global objects are referenced?

### 8. Trace behavior

`strace` observes system calls:

```bash
strace -f -o trace.txt ./target
```

It can reveal file access, process creation, memory mappings, networking, and other kernel interactions.

`ltrace` attempts to observe dynamic-library calls:

```bash
ltrace ./target
```

Neither provides the whole program. Internal computation may not cross either boundary, and programs can detect or resist tracing.

### 9. Debug a hypothesis with `gdb`

```bash
gdb ./target
```

Useful initial commands:

```gdb
set disassembly-flavor intel
break main
run
info registers
disassemble
x/16gx $rsp
```

The debugger is most effective when used to test a specific idea:

> “I think this branch checks the password result; I will stop before it and inspect the operands.”

Stepping aimlessly through every instruction scales poorly.

### Evidence ladder

Different observations support different strengths of claim:

| Observation | Reasonable conclusion |
|---|---|
| A URL appears in `strings` | The bytes representing a URL exist in the file |
| The URL is referenced in disassembly | Some code can access it |
| A traced call receives the URL | It is used during this observed execution |
| A network syscall connects to its address | A connection was attempted in this execution |

Binary analysis improves when findings are expressed at the strength actually supported by the evidence.

### First-pass report template

```markdown
## Identity
- Format:
- Architecture:
- Bit width:
- Endianness:
- Linking:
- Stripped:

## Structure
- Entry point:
- Important sections:
- Load segments and permissions:
- Security-relevant properties:

## Static clues
- Imports:
- Symbols:
- Strings:
- Suspicious or important code regions:

## Dynamic observations
- Files:
- Processes:
- Network:
- Memory behavior:

## Hypotheses
1.
2.

## Uncertainties and next experiments
1.
2.
```

### Check

Suppose `strings` shows `/etc/passwd`. Which statement is justified immediately?

1. The program definitely opens `/etc/passwd`.
2. The program contains those bytes somewhere.
3. The program steals passwords.

Explain what additional evidence would justify a stronger conclusion.

---

## Combined practical exercise

Create a small harmless C program that:

- prints a constant message;
- calls one libc function;
- contains one global initialized integer;
- contains one uninitialized global buffer;
- contains one function besides `main`.

Then:

1. compile it to an object file and executable;
2. identify both with `file`;
3. inspect the ELF header, sections, segments, symbols, and relocations;
4. locate the message with `strings` and `xxd`;
5. compare object-file and executable disassembly;
6. create a stripped copy and compare the available evidence;
7. explain where each source-level element appears—or why optimization removed it.

Do not merely save outputs. Write one conclusion for each tool and state how strongly the evidence supports it.

