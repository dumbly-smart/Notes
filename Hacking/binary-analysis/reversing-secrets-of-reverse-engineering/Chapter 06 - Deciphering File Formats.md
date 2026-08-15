# Chapter 6 — Deciphering File Formats

> [!workthroughs] Complete tool-backed labs: [[Walkthroughs - Chapter 06 - Fifteen Complete Analyses]]

> [!source]
> **From the book:** the Cryptex `.crx` case study, including password verification, directory reconstruction, and extraction.
> **Added explanation:** the experiment matrix, schemas, validation checklist, and exercises.

## Chapter Overview

This chapter reconstructs a proprietary archive format without source or format documentation. Cryptex stores multiple files in an encrypted archive using 3DES. The author combines black-box experiments, imported-API clues, debugger breakpoints, data-flow tracing, and small dump utilities to recover the format.

The transferable lesson is that a file format is not discovered by staring at bytes. It is discovered by connecting **on-disk regions** to the code that reads, transforms, validates, and uses them.

```text
controlled sample archives
│
├── byte-level differences
├── I/O API breakpoints
├── password transformation and hash
├── decrypted directory records
└── extraction/decryption/hash verification
```

## 6.1 Cryptex and Its Observable Interface

Cryptex is a console archive utility with four principal operations: add, extract, list, and delete. Archives use a `.crx` extension, accept a password, and hold multiple named files. The program applies triple-DES encryption.

### Why begin by using the program?

The command-line interface reveals the format’s behavioral contract:

- which operations require a password;
- whether listing requires decryption;
- how duplicate names and wildcards behave;
- whether archive size changes in blocks;
- which errors occur before any file data is accessed.

Black-box behavior constrains later static hypotheses.

## 6.2 Designing Controlled Samples

### Core Idea

Create archives that differ in exactly one controlled property. A useful corpus includes:

| Sample | Controlled change | What it can reveal |
|---|---|---|
| A | one tiny known file | baseline overhead and known plaintext |
| B | same file, different password | password-dependent regions |
| C | same password, different contents | content-dependent regions |
| D | add a second file | directory-entry growth |
| E | long filename | fixed versus variable name storage |
| F | empty file | metadata size independent of payload |
| G | payload across block boundary | cipher padding/block behavior |

### Step-by-step experiment

1. Create a text file containing a conspicuous pattern, such as repeated `*` bytes.
2. Archive it under a known password.
3. Record archive length and a hash of the entire archive.
4. View the archive in a hex editor and search for the original filename and plaintext.
5. Repeat while changing only one variable.
6. Diff the resulting archives by offset.
7. Log which ranges remain constant, move, or become pseudorandom.

### Interpretation discipline

An unchanged prefix may be a header—but could also be fixed ciphertext. A 16-byte changing region may be a hash—but could also be an IV or encrypted header. Labels remain hypotheses until the reading code confirms them.

## 6.3 Establishing an Execution Map

Imported functions provide landmarks. File-open/read/seek functions identify I/O boundaries; cryptographic calls or arithmetic-heavy internal routines identify transformations; string/output functions lead to error paths.

```text
command parser
   ↓
open archive
   ↓
read verification material → transform password → compare
   ↓ success
read/decrypt directory → select entry
   ↓
read/decrypt payload → verify integrity → write output
```

## 6.4 The Password Verification Process

### Catching the “Bad Password” message

The book starts from a stable observation: an incorrect password produces a recognizable message. Rather than searching blindly for cryptography, locate the message or break on the output routine, then walk backward to the conditional branch that selected the failure path.

### Backward-slicing procedure

1. Trigger the wrong-password path.
2. Break where the message is emitted.
3. Identify the immediately controlling conditional branch.
4. Trace the compared values backward.
5. Mark where archive bytes enter one side of the comparison.
6. Mark where password-derived bytes enter the other.
7. Continue backward until input password characters first enter the transformation.

This is a **backward slice**: retain only instructions that influence the decision of interest.

### Password transformation algorithm

The password is not necessarily used directly as a cipher key. The program transforms it into fixed-size material suitable for later cryptographic operations. In the disassembly, loops, constants, buffer writes, and repeated mixing reveal the transformation’s phases.

Do not label a transformation “encryption” merely because its output looks random. Ask:

- Is it reversible?
- Is output length fixed?
- Is it compared rather than decrypted?
- Does the same input always produce the same output?
- Does another routine consume it as a key?

### Hashing the password

Password verification usually compares a stored verifier with a digest derived from the supplied password. Conceptually:

```text
password text
   ↓ normalization/transformation
key or intermediate bytes
   ↓ hash/mixing
candidate verifier
   ↓ compare with archive field
accept / reject
```

The reverse engineer’s task is to recover the exact bytes at every boundary: character encoding, terminator inclusion, fixed-length padding, byte order, and digest length.

> [!deep dive]
> A verifier lets the program reject an incorrect password before decrypting all content. It also creates an offline password-checking surface. That is a design consequence, not proof that a specific historical scheme is weak; strength depends on derivation cost, salt, digest construction, and password entropy.

### Worked example — distinguishing verifier and IV

**Situation:** a 16-byte archive field changes when the password changes.

1. Create two archives with identical content and password. If the field changes, randomness may be involved.
2. Create two archives with different content but the same password. If it stays fixed, it is password-related.
3. Break at the comparison on a wrong-password path. If this field is directly compared with computed bytes, it is a verifier candidate.
4. Patch only the field in a disposable copy. Observe whether failure happens at password checking or later decryption.

No single experiment is conclusive; their intersection is.

## 6.5 The Directory Layout

### Core Idea

An archive needs metadata that maps a logical filename to stored payload location, sizes, and integrity information. The chapter traces the listing operation because it must parse directory records without necessarily extracting a file.

### Analyzing directory-processing code

1. Use the list command with a valid password.
2. Break on the first archive read after password acceptance.
3. Record file offset and byte count.
4. Follow the buffer through any decryption/transformation.
5. Find the loop that advances from one entry to the next.
6. Infer record stride from pointer increments.
7. Correlate fields with printed filename, sizes, and payload seeks.

### Conceptual directory schema

```text
ARCHIVE
├── verification/header region
├── encrypted directory region
│   ├── entry count or terminator
│   ├── FILE_ENTRY 0
│   ├── FILE_ENTRY 1
│   └── ...
└── encrypted file-data regions

FILE_ENTRY (semantic, not exact source declaration)
├── filename or filename reference
├── stored offset
├── original length
├── encrypted/stored length
└── integrity value
```

### How to infer each field

| Behavior in code | Likely meaning |
|---|---|
| passed to string comparison/printing | name |
| passed to seek API | archive offset |
| bounds output allocation/write | original length |
| controls archive read or cipher blocks | stored length |
| compared after decryption | hash/check value |

### Analyzing a file entry

Follow one entry end-to-end. Name a field only after you observe its use. If `[entry+0x24]` is loaded into a seek call, call it `candidate_data_offset`; if it also aligns with the location found in your hex dump, confidence becomes high.

### Fixed vs variable-length entries

To distinguish them:

1. create archives with very short and very long names;
2. compare entry-to-entry pointer increments;
3. watch whether code advances by a constant or a decoded length;
4. check alignment rounding such as `(length + 3) & ~3`.

## 6.6 Dumping the Directory Layout

The book emphasizes turning hypotheses into a small parser/dumper. A dumper is valuable because it forces every offset, type, and boundary assumption to become executable.

### Safe parser workflow — added explanation

```text
read fixed prefix
  ↓ validate minimum size and magic/version candidates
derive/decrypt directory
  ↓ validate decrypted length
for each entry
  ├── check record lies inside directory
  ├── validate name termination/length
  ├── validate offset + stored_size inside file
  └── print fields without extracting
```

Use checked arithmetic. For example, validate `offset <= file_size` and `stored_size <= file_size - offset`; do not validate only `offset + stored_size <= file_size`, because addition can overflow.

### Example output

```text
entry[0]
  name: asterisks.txt
  data_offset: 0x....
  original_size: 1000
  stored_size: ...
  integrity: ...
```

The actual values come from the sample. The important point is that the output can be compared against Cryptex’s own list command.

## 6.7 The File Extraction Process

### Scanning the file list

Extraction first locates the requested entry, typically by iterating decoded directory records and comparing names. This confirms directory stride/name fields and reveals case-sensitivity behavior.

### Decrypting the file

Once the entry is selected, its offset and stored length control archive reads. Key material originates in the password path. Observe block size, buffer size, final-block handling, and whether decrypted bytes are written immediately or retained for verification.

### The floating-point sequence

The book encounters a floating-point computation inside the extraction logic. Its presence is a warning against assuming every arithmetic-heavy region is cryptography. Recover it as an expression:

1. label each load with its source;
2. simulate the x87 register stack after every instruction;
3. collapse instructions into expression-tree nodes;
4. identify where the final integer/byte sequence is consumed;
5. test the expression independently with captured inputs.

```text
machine sequence → stack states → algebraic expression → semantic role
```

### Why x87 code is confusing

The x87 uses a stack of registers (`ST(0)`, `ST(1)`, …). Instructions can pop, exchange, or implicitly address the top. A wrong stack-state assumption corrupts the entire reconstructed formula. Write the stack after every instruction.

### The decryption loop

Reduce the loop to four questions:

- Which bytes enter each iteration?
- What state persists between iterations?
- How many output bytes are produced?
- What terminates or special-cases the final block?

Avoid copying instruction syntax into pseudocode. Express input, state transition, output, and termination.

### Verifying the hash value

After decryption, Cryptex checks an integrity value. This separates two questions:

- **Confidentiality:** can the payload be read without the key?
- **Integrity:** did the recovered plaintext match what the archive recorded?

Trace the hash input range precisely. Does it include padding? filename? original length? only plaintext? An off-by-one mistake may produce a plausible but incompatible parser.

## 6.8 The Big Picture

```text
supplied password
├── derive key material ───────────────┐
└── compute verifier → compare header  │
                                      │
valid password                         │
   ↓                                  │
decrypt directory ◄───────────────────┘
   ↓ choose file entry
seek to stored offset
   ↓
decrypt stored blocks
   ↓ trim to original length
verify integrity value
   ↓
write recovered file
```

### Cross-validation matrix

| Recovered fact | Static evidence | Dynamic evidence | File evidence |
|---|---|---|---|
| verifier location | comparison data flow | wrong-password breakpoint | controlled password diff |
| directory stride | loop increment | addresses per iteration | archive growth |
| data offset | value passed to seek | observed seek | hex location |
| original size | output bound | write length | known sample size |
| integrity field | final compare | mutation causes failure | entry bytes differ with content |

## 6.9 Digging Deeper

Once compatibility is achieved, deeper questions remain:

- Are offsets absolute or relative?
- How are deleted entries represented?
- Is ordering significant?
- Can malformed counts produce out-of-bounds access?
- Are filename lengths bounded before copying?
- Does integer multiplication overflow during allocation?
- Is the password derivation salted and deliberately expensive?
- Is integrity cryptographically bound to metadata?

These questions connect format reversing to vulnerability research.

## Common Mistakes

**Mistake:** beginning with a large real-world archive.
**Correction:** create tiny controlled samples with known plaintext.

**Mistake:** assuming high-entropy bytes are encrypted payload.
**Correction:** correlate them with reads, decryption, and later use.

**Mistake:** reading only the successful path.
**Correction:** error paths often expose verification boundaries and assumptions.

**Mistake:** declaring the format solved when one sample parses.
**Correction:** test empty files, long names, multiple entries, boundaries, and corrupted fields.

**Mistake:** writing an unsafe parser for an untrusted format.
**Correction:** bounds-check before every read, allocation, seek, and addition.

## Chapter Synthesis

### Key Processes

1. Build controlled specimens.
2. Map observable behavior.
3. Use output/error paths to locate decisions.
4. Correlate file offsets with runtime buffers.
5. Reconstruct fields from use, not appearance.
6. Implement a read-only dumper.
7. Validate across a matrix of valid and malformed samples.

### What You Should Be Able to Explain

- [ ] Why differential samples outperform an arbitrary hex dump.
- [ ] How to backward-slice from “Bad Password.”
- [ ] How directory pointer increments reveal record layout.
- [ ] Why seek arguments are strong evidence for offset fields.
- [ ] How confidentiality and integrity checks differ.

### What You Should Be Able to Do

- [ ] Design a sample corpus that isolates one variable at a time.
- [ ] Convert x87 instructions into an expression using stack-state notes.
- [ ] Write a bounds-safe directory dumper from a tentative schema.
- [ ] Validate each field with static, dynamic, and on-disk evidence.

## Practice Questions

1. Why should two baseline archives be created with identical inputs?
2. What experiment distinguishes an absolute offset from a directory-relative offset?
3. How can you tell whether the password is used directly as the cipher key?
4. Why is listing the archive an ideal path for reconstructing the directory?
5. Which observations reveal cipher block padding?
6. Design five archives that distinguish fixed-length from variable-length directory entries.
7. A parser checks `offset + size <= file_size`. Explain the flaw and repair it.
8. What evidence would show that an integrity value covers metadata as well as plaintext?

## Practice Question Solutions

1. Nondeterministic fields—random salts, IVs, timestamps—will change even when semantic inputs do not; this prevents misattributing those bytes to the controlled variable.
2. Move or enlarge the preceding region while keeping an entry’s payload unchanged, then observe whether the stored value changes by the same delta; confirm how code combines the base and field.
3. Trace password bytes to fixed key material and inspect intervening normalization/derivation. Capturing both password and key buffers demonstrates whether they differ.
4. Listing must decode every metadata entry but can avoid payload extraction, isolating the directory-processing layer.
5. Archive-size steps at block boundaries, fixed-size loop iterations, final-block branches, and stored-size versus original-size differences.
6. Use short/long names, equal names with different content, multiple entries of mixed lengths, an empty name if accepted, and names crossing likely alignment boundaries; compare stride and total growth.
7. Addition can wrap. First require `offset <= file_size`, then require `size <= file_size - offset`.
8. Mutate only a decoded/re-encoded metadata field while preserving payload and observe verification; statically confirm that metadata bytes enter the hash computation.

---

Previous: [[Chapter 05 - Beyond the Documentation]]
Next: [[Chapter 07 - Auditing Program Binaries]]

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs II - Formats Vulnerabilities and Malware]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
