---
tags: [binary-analysis, elf, linking, loading, chapter-notes]
chapter: 2
---

# Chapter 2 — The ELF Format

## Chapter overview

ELF is the contract connecting producers (compiler, assembler, linker), consumers (kernel and dynamic loader), and analysis tools. This chapter moves from the ELF header to section headers/sections and finally program headers/segments.

```text
ELF header
├── points to section-header table → linker/analysis view
└── points to program-header table → runtime loader view

sections are grouped into segments; the mapping is not one-to-one
```

After this chapter you should be able to validate an ELF, locate its tables, translate an address to a file offset through a load segment, explain dynamic linking metadata, and distrust malformed metadata safely.

## 2.1 Executable header

Inspect:

```bash
readelf -hW ./a.out
xxd -g1 -l 64 ./a.out
```

### `e_ident`

The identification bytes contain magic (`7f 45 4c 46`), class (32/64-bit), byte order, ELF version, and ABI-related identification.

**Why class and endianness come first:** the parser needs them before interpreting multibyte fields in the rest of the file.

### Core fields

| Field | Meaning | Common mistake |
|---|---|---|
| `e_type` | relocatable, executable, shared object, core | interpreting every `ET_DYN` as a library; PIE is commonly `ET_DYN` |
| `e_machine` | target ISA | assuming x86-64 from host machine |
| `e_version` | ELF structure version | confusing with program version |
| `e_entry` | initial virtual address | treating as file offset |
| `e_phoff` | file offset to program headers | adding image base |
| `e_shoff` | file offset to section headers | assuming section headers are required at runtime |
| `e_flags` | architecture-specific flags | giving generic meaning |
| `e_ehsize` | ELF-header size | ignoring during validation |
| `e_*entsize`, `e_*num` | table entry sizes/counts | unchecked multiplication overflow |
| `e_shstrndx` | section-name string-table index | confusing with ordinary symbol string table |

### Robust parsing rule

Before reading a table, establish:

```text
offset ≤ file_size
entry_size is valid for class
count ≤ (file_size - offset) / entry_size
```

This subtraction/division form avoids overflow in `offset + count * entry_size`.

## 2.2 Section headers

Each section-header entry describes a logical region.

```bash
readelf -SW ./a.out
objdump -h ./a.out
```

| Field | Purpose |
|---|---|
| `sh_name` | offset into section-name string table |
| `sh_type` | content/semantic kind |
| `sh_flags` | writable, allocated, executable, strings, TLS, etc. |
| `sh_addr` | runtime virtual address if allocated |
| `sh_offset` | file offset of bytes |
| `sh_size` | size; may describe zero-fill for `NOBITS` |
| `sh_link`, `sh_info` | relationship whose meaning depends on type |
| `sh_addralign` | required alignment |
| `sh_entsize` | fixed record size, or zero if not a table |

**Difficult point:** `sh_name` is not a pointer. It is an integer offset into `.shstrtab`. The parser obtains `name = shstrtab_bytes + sh_name` only after validating both range and terminating NUL.

> [!deep-dive] Section names are advisory
> Normal toolchains use conventional names, but loaders care mainly about segments. A hostile binary may rename, omit, overlap, or corrupt section metadata. Analyze flags, types, references, and program headers instead of trusting names such as `.text`.

## 2.3 Important sections

### Lifecycle and code/data

| Section | Meaning |
|---|---|
| `.init`, `.fini` | legacy initialization/finalization code |
| `.text` | ordinary executable code |
| `.rodata` | read-only constants |
| `.data` | initialized writable objects |
| `.bss` | zero-initialized storage; `SHT_NOBITS` consumes memory, usually no file payload |
| `.init_array`, `.fini_array` | arrays of function pointers called around `main`/termination |

The distinction between `.data` and `.bss` explains `p_memsz > p_filesz`: the loader maps file-backed bytes and provides additional zeroed memory.

### Dynamic linking: PLT and GOT

Conceptual first call with lazy binding:

```text
caller → PLT stub → GOT slot initially points to resolver path
                    ↓
             dynamic linker finds symbol
                    ↓
             GOT slot updated with real address
                    ↓
later call → PLT stub → resolved function
```

The exact modern layout varies by architecture, linker options, and hardening. `.got` and `.got.plt` names describe typical organization; relocation tables and program metadata are the authority.

**Lazy binding:** delay function resolution until first use.

**Why:** faster startup and no cost for unused imports.

**Tradeoff:** first-call overhead and historically writable resolution state; `BIND_NOW`/full RELRO changes this.

### Relocations

`.rel.*` entries encode relocation target/type/symbol with an addend stored at the target. `.rela.*` carries an explicit addend in the relocation entry. x86-64 conventionally uses RELA.

Relocation meaning is type-specific:

```text
result = symbol value + addend - place       # representative PC-relative form
```

Do not apply this generically; consult the ABI’s relocation definition.

### Dynamic and symbol/string tables

`.dynamic` contains tagged records such as dependencies, string/symbol table locations, relocation tables, and binding flags. `.dynsym/.dynstr` support runtime symbols; `.symtab/.strtab` hold fuller link-time symbols. `.shstrtab` names sections.

## 2.4 Program headers and segments

Inspect:

```bash
readelf -lW ./a.out
```

| Field | Meaning |
|---|---|
| `p_type` | loadable mapping, interpreter, dynamic metadata, note, TLS, etc. |
| `p_flags` | runtime R/W/X permissions |
| `p_offset` | file offset |
| `p_vaddr` | virtual address relative to image placement |
| `p_paddr` | physical-address field, generally irrelevant to user-space loading |
| `p_filesz` | bytes present in file |
| `p_memsz` | bytes in memory; must be at least `p_filesz` for loadable data |
| `p_align` | alignment/congruence requirement |

### Address-to-offset formula

For a virtual address `VA` inside a specific `PT_LOAD`:

```text
file_offset = p_offset + (VA - p_vaddr)
```

Conditions:

```text
p_vaddr ≤ VA < p_vaddr + p_filesz
```

If `VA` falls only in the extra `p_memsz - p_filesz` range, it has no corresponding stored byte; it is zero-filled memory.

**Worked example:** a segment has `p_offset=0x2000`, `p_vaddr=0x402000`, `p_filesz=0x800`. Address `0x4025a0` maps to `0x2000 + 0x5a0 = 0x25a0`. Address `0x402900` is outside the file-backed range.

### Alignment

For load segments, file offset and virtual address are typically congruent modulo alignment:

```text
p_vaddr mod p_align = p_offset mod p_align
```

This enables page-oriented mappings. Misunderstanding it causes broken injected segments.

## Sections versus segments

| Feature | Section | Segment |
|---|---|---|
| Primary consumer | linker, debugger, analyst | kernel/runtime loader |
| Described by | section header | program header |
| Unit | semantic content | mapped memory range |
| Needed to run | often not | yes for normal loading |
| Relationship | several sections can share segment | one segment can span several sections/padding |

Plain language: sections explain *what bytes mean to tools*; segments explain *how bytes become memory*.

## Safe ELF triage lab

```bash
printf 'int g; const char s[]="hi"; int main(void){return s[0]+g;}\n' > tiny.c
gcc -g -fPIE -pie tiny.c -o tiny
readelf -hSWlrd tiny
```

Tasks:

1. Locate `.text`, `.rodata`, `.data`, and `.bss`.
2. Use “Section to Segment mapping” to identify their load segments.
3. Find the entry point and map it to a file offset.
4. Identify the interpreter and required shared libraries.
5. Explain which bytes/storage disappear if section headers are stripped.

## Common mistakes

- Treating virtual addresses as file offsets.
- Assuming section and segment boundaries match.
- Reading `.bss` bytes from the file.
- Trusting names/offsets from an unvalidated sample.
- Assuming GOT/PLT behavior is identical under all linker/hardening configurations.
- Forgetting PIE runtime relocation/base.

## Practice questions

1. Why must `e_ident` be interpreted before most other fields?
2. How can an ELF execute without useful section headers?
3. Explain the roles of `.shstrtab`, `.strtab`, and `.dynstr`.
4. Why can `p_memsz` exceed `p_filesz`?
5. What conditions make the address-to-offset formula valid?
6. A `PT_LOAD` is R-X. What can and cannot be concluded about a section inside it?
7. Explain lazy binding and how eager binding changes it.
8. Design three validations for a hostile section-header table.

## Solutions

1. It declares class and byte order needed to decode multibyte layouts correctly.
2. The kernel uses program headers to map runtime segments; section metadata chiefly serves linking/analysis.
3. `.shstrtab` names sections, `.strtab` serves full static symbols, `.dynstr` serves runtime dynamic records/symbols.
4. Zero-initialized storage needs memory but no equivalent payload bytes, saving file space.
5. The chosen `VA` must lie in the specific segment’s file-backed range, arithmetic must not overflow, and the metadata must be valid.
6. It will inherit executable/readable mapping permissions, but its name and purported section type alone do not prove every byte is reachable code.
7. Lazy binding resolves a function on first call and caches it; eager binding resolves relevant symbols during startup.
8. Validate offset, entry size, count multiplication/range, string indices, alignments, and type-specific links; any three with precise bounds are valid.

## Mastery checklist

- [ ] Parse the header and both major tables conceptually.
- [ ] Explain common sections and dynamic-link flow.
- [ ] Translate valid addresses and explain zero-fill exceptions.
- [ ] Compare sections and segments without conflating them.
- [ ] Identify malformed-metadata trust boundaries.
