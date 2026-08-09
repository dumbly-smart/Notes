# Module 11 — Authorized Protection Analysis

## Purpose

The book’s Defender case study combines patching, key-generation reasoning, encrypted functions, anti-debugging threads, manual API resolution, runtime keys, and heavy inlining. Treat it as a historical study of layered analysis resistance—not a recipe for bypassing commercial licensing.

Authorized methodology: create an equivalent toy protector, document initialization, locate decryption boundary, dump only your process, reconstruct API resolution, identify anti-debug thread, model key dependencies, and redirect success only to `LAB_SUCCESS`. Compare patching with algorithm/specification recovery and explain evidence each provides.

### Mastery gate

- [ ] Trace initialization across threads and decrypted regions.
- [ ] Recover a toy validation algorithm without claiming original source.
- [ ] Explain how layers multiply analyst cost but do not prove security.
