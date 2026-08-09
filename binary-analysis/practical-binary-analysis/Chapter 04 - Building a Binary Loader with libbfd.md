---
tags: [binary-analysis, libbfd, binary-loader, cpp, chapter-notes]
chapter: 4
---

# Chapter 4 — Building a Binary Loader with libbfd

## Chapter overview

The book now converts format knowledge into a reusable software abstraction. Its “binary loader” is an **analysis loader**: it opens an object/executable and normalizes sections, symbols, architecture, type, bit width, and entry point. It is not the kernel component that creates a process.

```text
format-specific bytes
      ↓ libbfd
normalized Binary
├── metadata
├── Section[]
└── Symbol[]
      ↓
disassembler / CFG / scanner / instrumentation tools
```

### Chapter roadmap

```text
Analysis loader
├── libbfd abstraction and trust boundary
├── Binary / Section / Symbol model
├── open and identify
├── load properties, symbols, and sections
└── validate with friendly and hostile fixtures
```

## 4.1 What libbfd provides

The Binary File Descriptor library is part of GNU binutils. It abstracts many object formats behind one API. This reduces format-specific parsing but introduces API complexity, global initialization concerns, and dependency/version coupling.

**What it solves:** opening formats, identifying targets/architecture, enumerating sections, retrieving content, reading symbol tables.

**What it does not solve:** deciding what bytes are code, recovering all functions, validating your higher-level assumptions, or making hostile parsing automatically safe.

## 4.2 Interface design

The book models three entities.

```cpp
struct Symbol {
    enum Type { SYM_TYPE_UKN, SYM_TYPE_FUNC } type;
    std::string name;
    uint64_t addr;
};

struct Section {
    enum Type { SEC_TYPE_NONE, SEC_TYPE_CODE, SEC_TYPE_DATA } type;
    std::string name;
    uint64_t vma;
    uint64_t size;
    uint8_t *bytes;
};

struct Binary {
    std::string filename;
    BinaryType type;
    std::string type_str;
    Arch arch;
    std::string arch_str;
    unsigned bits;
    uint64_t entry;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
};
```

This simplified sketch illustrates separation of concerns; production C++ should use RAII containers such as `std::vector<std::byte>` rather than owning a raw `uint8_t*`.

### Invariants

- a loaded `Binary` has a known file identity;
- every section byte range has been checked and owned safely;
- addresses use a width capable of representing the target;
- unknown types remain explicitly unknown rather than guessed;
- failed loads leave no partially valid object exposed.

## 4.3 Implementation pipeline

### Step 1 — initialize and open

Conceptually:

```text
bfd_init
 → bfd_openr(filename, target=null)
 → bfd_check_format(..., bfd_object)
 → reject unrecognized/ambiguous inputs cleanly
```

Use RAII for the `bfd*` so every error path closes it. Do not use the input filename as a shell command. Report libbfd’s specific error text alongside your contextual message.

### Step 2 — basic properties

Recover:

- target/flavour to classify ELF/PE-like input;
- architecture and machine subtype;
- 32/64-bit address size;
- start/entry address;
- file flags relevant to object/executable status.

Never infer bitness from the host application. A 64-bit loader may inspect a 32-bit target.

### Step 3 — symbols

Typical logic:

1. ask for storage required by static symbol table;
2. allocate pointer table safely;
3. canonicalize symbols;
4. repeat/fallback for dynamic symbols when appropriate;
5. filter/normalize useful function and object symbols;
6. compute symbol value using the API’s section/value conventions;
7. copy the name before releasing BFD-owned memory.

Static symbols may be absent in stripped files; that is a normal state, not necessarily an error. Dynamic symbols can still exist.

### Step 4 — sections

For every BFD section:

1. inspect flags to decide allocated/code/data relevance;
2. obtain name, VMA, and size;
3. validate that size fits your address space/container;
4. allocate owned storage;
5. request section contents;
6. classify conservatively;
7. retain empty/zero-fill semantics separately if your analyses need them.

Do not expect file bytes for a zero-fill section. Do not equate `SEC_CODE` with reachable instructions.

### Error-safe pseudocode

```cpp
std::optional<Binary> load_binary(const std::filesystem::path& path) {
    BfdHandle abfd{bfd_openr(path.c_str(), nullptr)};
    if (!abfd) return error("open failed");
    if (!bfd_check_format(abfd.get(), bfd_object)) return error("not object");

    Binary out;
    if (!load_properties(abfd.get(), out)) return std::nullopt;
    load_symbols_if_present(abfd.get(), out);
    if (!load_sections(abfd.get(), out)) return std::nullopt;
    return out;
}
```

The important feature is transactional construction: publish `out` only after required invariants hold.

## 4.4 Testing strategy

The book tests against known binaries. A stronger added matrix includes:

| Dimension | Cases |
|---|---|
| format | ELF relocatable, executable, shared object; PE if supported |
| architecture | x86-32, x86-64, another available target |
| symbols | debug, stripped, dynamic-only |
| linking | static, dynamic, PIE |
| sections | empty, zero-fill, unusual names |
| invalid input | truncated header/table, huge counts, bad strings, random file |

Cross-check output with independent tools:

```bash
readelf -hSWs test
objdump -h test
nm -an test
```

Differential agreement increases confidence but does not prove both tools are correct. Unit-test address containment, range arithmetic, and ownership separately.

## Worked example — address lookup

Given sections:

```text
.text   VMA 0x401000 size 0x500
.rodata VMA 0x402000 size 0x180
```

To find the section for address `0x4012f0`, test without overflow:

```text
address ≥ vma AND address - vma < size
```

The address belongs to `.text` at section offset `0x2f0`. Address `0x401600` belongs to neither. The subtraction form avoids overflow in `vma + size`.

## Design comparison

| Approach | Advantage | Limitation |
|---|---|---|
| libbfd | broad binutils format support | API/version complexity |
| direct ELF parser | complete control, small dependency | one must securely implement details |
| modern parsing library | ergonomic typed API | its supported formats/features define limits |
| shelling out to tools | rapid prototype | fragile parsing, injection/process overhead |

## Common mistakes

- Confusing analysis loader with OS loader.
- Treating absence of symbols as fatal.
- Keeping pointers into BFD-owned storage after close.
- Storing target addresses in host-sized `unsigned long` assumptions.
- Using `start + size` without overflow-safe range logic.
- Classifying all executable-section bytes as instructions.
- Testing only one friendly compiler output.

## Practice questions

1. Why normalize format-specific structures before disassembly?
2. What ownership bug can occur with symbol names?
3. Why should section classification include `unknown`?
4. Design an overflow-safe containment function.
5. How do stripped and zero-fill cases change loader behavior?
6. Which properties belong in `Binary`, `Section`, and `Symbol`?
7. Explain transactional construction and why it matters.
8. Propose five malformed inputs for parser testing.

## Solutions

1. Downstream analyses can operate on consistent sections/symbols/addresses without duplicating ELF/PE parsing.
2. A copied structure may retain a pointer owned by libbfd; closing the handle makes it dangling. Copy the string into owned storage.
3. Forced classification converts uncertainty into false facts and can make disassembly unsafe or misleading.
4. Require `addr >= base && addr - base < size`; define half-open ranges and handle zero size.
5. Stripped files normally produce no static symbols; zero-fill sections need size/address metadata but no file-content read.
6. Binary: file-wide format/arch/entry/collections. Section: named range, bytes, flags/type. Symbol: name, address, semantic type/binding if retained.
7. Build a private result, clean up on every failure, and expose it only when invariants hold; callers never receive half-loaded state.
8. Truncated header; offset past EOF; count multiplication overflow; bad string offset/no NUL; overlapping sections; impossible alignment; huge content size; inconsistent class.

## Mastery checklist

- [ ] Explain libbfd’s boundary and limitations.
- [ ] Design owned, width-safe normalized structures.
- [ ] Load properties, symbols, and sections with normal absence handling.
- [ ] Cross-check friendly outputs and reject malformed cases.
- [ ] Provide lookup helpers with explicit half-open range semantics.

## Extended chapter synthesis

### Key ideas

- Normalize format details once so downstream analyses use a stable model.
- Ownership, integer width, and failure-state invariants are first-class parser requirements.
- No static symbols is a valid stripped-binary state.
- libbfd reduces format work but does not eliminate untrusted-input risk.
- Independent-tool comparison and hostile mutation test different failure modes.

### Key definitions

analysis loader, canonical symbol table, VMA, owned storage, RAII, transactional construction, half-open range, normalization.

### Key process

```text
open → verify object → properties → symbols if present → sections/content
 → validate normalized invariants → publish complete result
```

### What you should be able to solve

- [ ] Design width-safe `Binary/Section/Symbol` objects.
- [ ] Prevent dangling library-owned names and bytes.
- [ ] Handle stripped and zero-fill cases.
- [ ] Create malformed fixtures for every range calculation.

Full 48-question set with worked solutions: [[Workbooks/Chapter 04 - Practice and Complete Solutions]].
