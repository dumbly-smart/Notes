# Module 13 — Decompilation Theory and Practice

## Purpose

Understand why exact native-source recovery is generally impossible and how real decompilers build useful equivalent programs through front end, IR, CFG, semantic analysis, SSA/data flow, propagation, register-variable recovery, type inference, control structuring, library recognition, and a language back end.

```text
bytes → decode/lift → CFG → SSA/data flow → types/structures
→ control-flow structuring → expressions → high-level output
```

### Lab

Choose ten tiny functions. Compare source, optimized instructions, raw decompiler output, and corrected semantic model. For each invented name/type/control construct, cite evidence or downgrade confidence. Manually perform SSA renaming and constant/copy propagation on one diamond and loop.

### Mastery gate

- [ ] Explain front end, analysis middle, and back end.
- [ ] Compute SSA/use-def relationships on small CFGs.
- [ ] Critique decompiler output without dismissing or trusting it blindly.
