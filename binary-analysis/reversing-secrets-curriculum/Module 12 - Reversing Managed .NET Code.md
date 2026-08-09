# Module 12 — Reversing Managed .NET Code

## Purpose

Learn managed assemblies, metadata, CTS, IL evaluation stack, activation records, high-level decompilation, renaming/control-flow obfuscation, native images, and encrypted assemblies.

Managed metadata often preserves richer types/names/control relationships than native binaries, making decompilation stronger—but obfuscation, reflection, dynamic loading, interop, and JIT code still require multiple views.

### Lab

Build C# examples for counting, linked lists, exceptions, generics, async, reflection, and P/Invoke. Inspect IL stack effects, decompile, rename every inferred role, then compare obfuscated and native/JIT behavior. Verify security-relevant branches in IL and runtime.

### Mastery gate

- [ ] Simulate IL evaluation stack through a method.
- [ ] Map metadata tokens/types/calls to decompiled constructs.
- [ ] Explain managed obfuscation and native interop limits.
