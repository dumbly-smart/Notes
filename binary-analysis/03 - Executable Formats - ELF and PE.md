# Executable Formats — ELF and PE

This note groups the major subject of executable-file formats. It covers the structure required to understand loading, linking, inspection, and later binary modification.

## First mental model

An executable format is a contract between several participants:

```text
Compiler and assembler
        ↓ produce structured objects
Linker
        ↓ produces executable metadata
Operating-system loader
        ↓ maps and starts the program
Dynamic linker
        ↓ resolves shared dependencies
Debugger / analyst
        ↓ interprets the same structures
```

The file contains machine code, but machine code alone is insufficient. The system also needs to know the architecture, entry point, mappings, permissions, dependencies, and other organizational details.

---

## Topic 4 — The ELF executable header

ELF means **Executable and Linkable Format**. It is used for executables, relocatable object files, shared libraries, and core dumps on Linux and many Unix-like systems.

Every ELF begins with an executable header. It acts as the file's root description and tells parsers where other major tables are located.

Inspect it with:

```bash
readelf -h ./example
```

### Important fields

| Field | Purpose |
|---|---|
| `e_ident` | Magic bytes, class, endianness, and ELF version |
| `e_type` | Relocatable, executable, shared object, or core file |
| `e_machine` | Target instruction-set architecture |
| `e_entry` | Virtual address where execution begins |
| `e_phoff` | File offset of the program-header table |
| `e_shoff` | File offset of the section-header table |
| `e_flags` | Architecture-specific flags |
| `e_ehsize` | Size of the ELF header |
| `e_phentsize`, `e_phnum` | Program-header entry size and count |
| `e_shentsize`, `e_shnum` | Section-header entry size and count |
| `e_shstrndx` | Index of the section-name string table |

### Magic and identity

The first four bytes are:

```text
7f 45 4c 46
```

The final three bytes spell `ELF` in ASCII. Later identity bytes specify 32-bit versus 64-bit and little-endian versus big-endian encoding.

### Why offsets matter

ELF is not parsed by assuming every table always begins at a fixed position. The header provides offsets and entry sizes:

```text
ELF header
  ├─ e_phoff ──→ program-header table
  └─ e_shoff ──→ section-header table
```

This allows tools to locate structures systematically.

### Check

If `e_entry` is `0x401040`, what does that value describe: a byte's file offset, a source line, or a virtual address used when execution starts?

---

## Topic 5 — ELF sections and section headers

Sections organize a binary mainly for linking and analysis. Every section header describes one section's name, type, location, size, flags, alignment, and relationships.

Inspect them with:

```bash
readelf -S ./example
objdump -h ./example
```

### Common sections

| Section | Typical content |
|---|---|
| `.text` | Executable machine code |
| `.rodata` | Read-only constants and strings |
| `.data` | Initialized writable global/static data |
| `.bss` | Zero-initialized or uninitialized global/static data |
| `.symtab` | Full symbol table |
| `.strtab` | Strings used by `.symtab` |
| `.dynsym` | Symbols needed for dynamic linking |
| `.dynstr` | Strings for dynamic symbols |
| `.rela.*` / `.rel.*` | Relocation records |
| `.init_array` | Functions called during initialization |
| `.fini_array` | Functions called during termination |

### Important section-header fields

| Field | Meaning |
|---|---|
| `sh_name` | Index into the section-name string table |
| `sh_type` | Kind of contents or role |
| `sh_flags` | Writable, allocated, executable, and other properties |
| `sh_addr` | Virtual address when loaded, if applicable |
| `sh_offset` | Beginning of the section in the file |
| `sh_size` | Section size |
| `sh_link`, `sh_info` | Relationships whose meaning depends on section type |
| `sh_addralign` | Required alignment |
| `sh_entsize` | Size of fixed-size entries, when applicable |

### Why `.bss` is special

`.bss` represents zero-initialized storage. Recording thousands of literal zero bytes in the executable would waste disk space. ELF can record the required memory size and let the loader provide zero-filled memory.

### Sections are not the loader's primary view

Section headers matter greatly to linkers and analysis tools, but a program can often execute without them. The loader primarily uses **program headers and segments**, covered next.

### Check

What is the difference between `sh_offset` and `sh_addr`?

---

## Topic 6 — ELF program headers and segments

Program headers describe the process image—the portions of the file that must be mapped into memory and how they should be treated.

Inspect them with:

```bash
readelf -l ./example
```

### Sections versus segments

```text
Linking/analysis view              Runtime/loader view

.text ───────┐
.rodata ─────┼──────→ read/execute or read-only LOAD segment
.eh_frame ───┘

.data ───────┐
.bss ────────┼──────→ read/write LOAD segment
.got ────────┘
```

A segment can contain several sections. Sections organize content by logical purpose; segments group it according to runtime mapping and permissions.

### Common program-header types

| Type | Purpose |
|---|---|
| `PT_LOAD` | Bytes mapped into process memory |
| `PT_INTERP` | Path of the dynamic interpreter |
| `PT_DYNAMIC` | Dynamic-linking metadata |
| `PT_PHDR` | Location of the program-header table in memory |
| `PT_NOTE` | Auxiliary note information |
| `PT_GNU_STACK` | Requested stack permissions |
| `PT_GNU_RELRO` | Region made read-only after relocation |

### Important mapping fields

- `p_offset` — segment's location in the file;
- `p_vaddr` — intended virtual address;
- `p_filesz` — number of bytes supplied by the file;
- `p_memsz` — number of bytes occupied in memory;
- `p_flags` — read, write, and execute permissions;
- `p_align` — alignment requirement.

When `p_memsz > p_filesz`, the remaining memory is zero-filled. This commonly accommodates `.bss`.

### Security connection

Separating writable and executable segments supports **W^X**: memory should generally be writable or executable, but not both. Program headers also reveal properties related to a non-executable stack and RELRO.

### Check

Why does the operating-system loader care more about segments than source-oriented concepts such as functions?

---

## Topic 7 — Dynamic linking through the GOT and PLT

A dynamically linked executable may call a library function whose final address is not known when the executable is created. ELF uses several coordinated structures to make these calls possible.

### Main participants

- `.dynsym` and `.dynstr` identify imported and exported dynamic symbols;
- relocation entries specify locations that require runtime fixing;
- the **Global Offset Table (GOT)** stores runtime-resolved addresses;
- the **Procedure Linkage Table (PLT)** supplies call stubs for external functions;
- the dynamic linker locates libraries and resolves symbols.

### Simplified first call

```text
program calls printf@plt
          ↓
PLT consults printf's GOT entry
          ↓ unresolved initially
dynamic linker searches for printf
          ↓
address is written into the GOT
          ↓
real printf executes
```

Later calls can use the cached address in the GOT. This is **lazy binding**. A system may instead resolve symbols eagerly at startup.

### Position-independent code

Shared libraries can be loaded at different virtual addresses. Position-independent code avoids depending on one fixed load address and often accesses external data or functions indirectly through tables such as the GOT.

### Security connection

Because the GOT influences indirect control transfers, overwriting GOT entries has historically been useful in exploitation. RELRO hardens relocation-related regions:

- partial RELRO provides limited protection;
- full RELRO resolves entries early and then makes the relevant GOT region read-only.

### Check

Why does the program call a PLT stub instead of embedding one permanent address for `printf`?

---

## Topic 8 — The PE format and comparison with ELF

PE means **Portable Executable** and is the primary executable format used by Windows. The book covers it briefly so that ELF knowledge can be transferred across platforms.

### High-level PE structure

```text
MS-DOS header and stub
        ↓ points through e_lfanew
PE signature
COFF file header
Optional header
Section table
Section contents
```

Despite its name, the **optional header** is required for executable PE images. It contains essential loading information, including the entry point, image base, alignment, image size, and data-directory locations.

### Common PE sections

| PE section | Rough role |
|---|---|
| `.text` | Executable code |
| `.rdata` | Read-only data |
| `.data` | Initialized writable data |
| `.bss` | Uninitialized data, when represented separately |
| `.idata` | Import-related information |
| `.edata` | Export information |
| `.rsrc` | Resources such as icons and dialogs |
| `.reloc` | Base relocations |

Names are conventional rather than a complete guarantee of content.

### Important differences in vocabulary

| ELF | PE |
|---|---|
| ELF header | DOS header + PE/COFF headers |
| Program headers | Loading information in optional header and section table |
| `.dynsym`, GOT, PLT, relocations | Import/export tables, IAT, and base relocations |
| Shared object `.so` | Dynamic-link library `.dll` |
| File offset and virtual address | File offset, RVA, and virtual address |

An **RVA** is a relative virtual address measured from the image base:

```text
virtual address = image base + RVA
```

### Transferable principle

Do not memorize only field names. In either format, ask:

1. How is the architecture identified?
2. Where is the entry point?
3. Which bytes become memory mappings?
4. What permissions do those mappings receive?
5. How are imported functions represented?
6. How are relocations described?

### Check

If a PE image base is `0x140000000` and an RVA is `0x1000`, what virtual address does it describe before relocation?

---

## Format-level mastery check

Without consulting the tables above, explain:

1. why an executable needs metadata in addition to machine code;
2. the difference between an ELF section and a segment;
3. how file offsets differ from virtual addresses;
4. why `.bss` can occupy more memory than file space;
5. how an external library call can be resolved at runtime;
6. one conceptual similarity and one structural difference between ELF and PE.

