# Module 6 — Deciphering File Formats and Protocols

## Purpose

The Cryptex case study teaches password-path tracing, directory-entry reconstruction, extraction, transformation/decryption loops, and integrity checks. Generalize it into format/protocol recovery.

```text
sample corpus → parser entry → field reads → bounds/branches
→ structure hypothesis → independent parser → differential tests
```

Start from user-visible errors and I/O boundaries. Record every field as offset, width, byte order, meaning, constraints, references, and confidence. Separate password transformation, hashing, directory layout, file-entry traversal, payload transformation, and hash verification.

### Lab

Create five archives with controlled differences: empty, one file, two names, altered password, corrupted length/hash. Diff bytes, trace parser/extractor, infer header/entry layout, implement a read-only parser, and predict outcomes for unseen edge cases before testing.

### Mastery gate

- [ ] Produce a complete bounded binary-format specification.
- [ ] Explain transformations step by step, including integrity checks.
- [ ] Parse malformed cases without crashes or silent truncation.
