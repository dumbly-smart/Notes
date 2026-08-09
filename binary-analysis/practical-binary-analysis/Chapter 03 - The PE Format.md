---
tags: [binary-analysis, pe, windows, executable-format, chapter-notes]
chapter: 3
---

# Chapter 3 — The PE Format

## Chapter overview

The book gives a deliberately brief PE introduction so the reader can recognize Windows executables and map familiar ELF ideas to a different format. PE is built on COFF and begins with compatibility structures before its modern headers.

```text
MS-DOS header (`MZ`)
└── e_lfanew ─→ PE signature (`PE\0\0`)
                 ├── COFF file header
                 ├── optional header (actually required for images)
                 │    └── data directories
                 └── section-header table
                      └── section raw bytes
```

## 3.1 MS-DOS header and stub

The first two bytes are `MZ`. The key field `e_lfanew` gives the file offset of the PE signature. A DOS stub commonly prints a compatibility message if run under DOS.

Robust parser logic:

1. verify file is large enough for the DOS header;
2. verify `MZ`;
3. read `e_lfanew` with correct little-endian interpretation;
4. validate it is within the file and leaves room for the PE/COFF headers;
5. verify `PE\0\0`.

Never scan for `PE\0\0` and accept the first occurrence; payload data could contain the bytes.

## 3.2 Signature, file header, and optional header

### PE signature

The four bytes identify the modern header. They are followed by a COFF file header.

### File header

Important fields describe machine architecture, number of sections, timestamp, optional-header size, and characteristics such as executable or DLL status.

**Security note:** timestamps are easy to alter and are clues, not trustworthy provenance.

### Optional header

Despite the name, this header is required for executable images. Its `Magic` distinguishes PE32 from PE32+; this changes field widths and layout.

Important concepts:

| Field/concept | Meaning |
|---|---|
| Address of entry point | RVA where initial code begins |
| Image base | preferred virtual load base |
| Section/file alignment | memory versus disk layout constraints |
| Size of image/headers | loader range expectations |
| subsystem | console, GUI, driver, etc. |
| DLL characteristics | ASLR, DEP/NX compatibility and other flags |
| data directories | RVA/size pairs locating imports, exports, relocations, resources, TLS, exceptions, etc. |

**RVA:** relative virtual address, normally an offset from the loaded image base.

```text
VA = actual_image_base + RVA
```

ASLR may change the actual base. The preferred image base is not a guaranteed runtime address.

## 3.3 Section-header table

Each section header contains a name, virtual size/address, raw-data size/file pointer, relocation-related fields, and characteristics.

### RVA to file offset

Find the section satisfying the relevant RVA range, then:

```text
file_offset = PointerToRawData + (RVA - VirtualAddress)
```

Do not assume `VirtualSize == SizeOfRawData`. Memory may include zero-fill; disk content may include alignment padding.

**Example:** section RVA begins at `0x2000`, raw file bytes at `0x600`. RVA `0x2340` maps to `0x600 + 0x340 = 0x940`, provided that delta is file-backed.

## 3.4 Sections

Conventional names include `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`, `.edata`, and `.idata`, but names are not authoritative.

- `.edata` commonly supports exports.
- `.idata` commonly supports imports.
- code sections can contain alignment padding; interpreting every byte as reachable code causes false disassembly.

Imports are structured through descriptors, thunk tables, and names/ordinals. At load time, the loader fills the Import Address Table with resolved addresses. Conceptually it plays a role similar to ELF dynamic symbol/relocation/GOT machinery, but field layout and resolution rules differ.

## ELF versus PE

| Feature | ELF | PE |
|---|---|---|
| Initial magic | `7f ELF` | `MZ`, then `PE\0\0` through `e_lfanew` |
| Runtime mapping | program headers/segments | section headers plus optional-header image data |
| Relative address term | virtual addresses/image-relative under PIE | RVA is explicit common concept |
| Dynamic dependency data | `.dynamic`, dynsym, relocations, GOT/PLT | import directory, thunks/IAT |
| Exports | dynamic symbols | export directory |
| Relocation for base change | dynamic relocations | base relocation directory |

Both formats describe architecture, layout, entry, permissions, dependencies, and relocation; the concrete encoding differs.

## Added practical triage

On Linux, use format-aware static tools without executing:

```bash
file sample.exe
objdump -x sample.exe
objdump -p sample.exe
```

In a Windows analysis VM, tools such as PE-bear, dumpbin, WinDbg, Ghidra, or appropriate libraries can inspect the same structures. Execution belongs in an isolated Windows environment if the binary is unknown.

## Common mistakes

- Treating `e_lfanew` or an RVA as a direct pointer/file offset.
- Assuming “optional” means absent in an executable image.
- Applying PE32 field offsets to PE32+.
- Trusting timestamps or section names as facts.
- Assuming raw and virtual section sizes are equal.
- Running a sample merely to learn its imports.

## Practice questions

1. Why are both `MZ` and `PE\0\0` checked?
2. Explain RVA, preferred image base, and actual VA.
3. Why is the optional header’s `Magic` security-critical to parsing?
4. How do raw size and virtual size create a non-file-backed range?
5. Compare the IAT with ELF GOT/relocation behavior without claiming they are identical.
6. Why are section names and timestamps weak evidence?

## Solutions

1. `MZ` identifies the DOS-compatible beginning; `e_lfanew` then locates and the signature verifies the modern PE header. Either alone is insufficient validation.
2. RVA is image-relative. The preferred base is a requested/default placement. Runtime VA equals the actual chosen base plus RVA.
3. It selects PE32/PE32+ layout and widths; using the wrong structure misreads later fields and can cause unsafe offsets.
4. If virtual size exceeds raw size, the additional memory is typically zero-filled and has no raw file byte. Padding can create the reverse discrepancy on disk.
5. Both hold/enable resolved external addresses used by calls, but their descriptors, relocation mechanisms, and loader contracts differ.
6. Producers or attackers can choose names and alter timestamps; corroborate with structure, code references, signatures, and behavior.

## Mastery checklist

- [ ] Navigate from DOS header to PE headers safely.
- [ ] Explain PE32/PE32+, RVA, image base, and entry point.
- [ ] Translate a file-backed RVA through a section.
- [ ] Identify imports/exports and explain padding.
- [ ] Compare PE and ELF at the conceptual level.
