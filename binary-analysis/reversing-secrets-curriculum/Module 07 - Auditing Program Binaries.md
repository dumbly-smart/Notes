# Module 7 — Auditing Program Binaries

## Purpose

Study stack/heap overwrites, filters, integer overflow, and conversion errors, then reconstruct the IIS Indexing Service case study’s vulnerable input flow. Use current mitigations as additions, not retroactive claims about the historical target.

```text
untrusted source → representation changes → validation → allocation/copy/index
→ first violated invariant → primitive → actual mitigations → impact
```

For every candidate, track width, signedness, unit, capacity, lifetime, and error behavior. A dangerous API is a lead; a crash is a symptom; a finding requires reachability and root cause.

### Lab

Audit self-built stack, heap, integer-truncation, and URL-decoding toys under ASan and hardened builds. Minimize inputs, locate first corrupting instruction, demonstrate only benign `LAB_SUCCESS`, fix the invariant, and add boundary regressions. Cross-link [[../practical-binary-analysis/Authorized Binary Exploitation Guide]].

### Mastery gate

- [ ] Distinguish bug, control, primitive, and impact.
- [ ] Explain every mitigation against the exact primitive.
- [ ] Deliver a root-cause fix and regression corpus.
