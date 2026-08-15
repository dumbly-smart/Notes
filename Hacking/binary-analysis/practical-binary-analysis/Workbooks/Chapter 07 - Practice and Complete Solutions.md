# Chapter 7 Workbook — ELF Code Injection

Return to [[../Chapter 07 - ELF Code Injection]]. Authorized lab copies only.

# Chapter Practice Set

## Recall Questions — 10
1. Define an off-by-one.
2. Why record original/patched hashes?
3. What does `LD_PRELOAD` change?
4. What is interposition?
5. Why is a new section not automatically mapped?
6. What does `e_entry` control?
7. What are init/fini arrays?
8. What does a GOT-like slot hold?
9. What is a trampoline?
10. Give the x86 relative-displacement formula.

## Conceptual Questions — 10
11. Why recover signedness before patching a branch?
12. Why re-disassemble after a byte patch?
13. Why can an interposer recurse?
14. Why does static/internal calling bypass some interposition?
15. Why must injected code be covered by `PT_LOAD`?
16. Why is RWX avoidable and dangerous?
17. Compare entry, constructor, GOT/PLT, and call-site redirection.
18. Why are RIP-relative displaced instructions hard to relocate?
19. Why does stack alignment matter in a hook?
20. Why is behavior change insufficient patch validation?

## Application Problems — 10
21. Patch `jle` to `jl`: what invariant must first be proven?
22. Map injected VA to appended file bytes through a new segment.
23. Compute call displacement from `0x401000` length 5 to `0x402000`.
24. A target is beyond signed rel32 reach. What architecture is needed?
25. A `malloc` hook logs with `fprintf` and loops. Fix design.
26. Appended bytes appear in section table but segfault on jump. Diagnose.
27. Constructor hook runs twice. What evidence/state should be inspected?
28. Full RELRO blocks a runtime GOT write. What remains conceptually possible in authorized rewriting?
29. A trampoline overwrites 7 bytes with 5-byte jump. What happens to extra bytes/semantics?
30. Patched PIE works once but not after restart. Diagnose.

## Multi-Step Problems — 5
31. Perform a safe hex branch repair experiment.
32. Design a robust allocation/copy interposition monitor.
33. Append and map position-independent code in an ELF copy.
34. Build a trampoline preserving displaced instructions.
35. Compare five redirection methods for one instrumentation goal.

## Challenging Problems — 5
36. Extend a load segment without exposing writable data as executable.
37. Relocate a RIP-relative load and short conditional branch into a trampoline.
38. Handle multithreaded interposition initialization safely.
39. Explain how lazy binding and RELRO alter a GOT/PLT experiment.
40. Prove a patch preserves all tested non-target behavior.

## Trick / Misconception Questions — 5
41. True or false: changing `jle` to `jl` always fixes off-by-one.
42. True or false: executable section flag makes bytes runtime executable.
43. True or false: `LD_PRELOAD` intercepts every function with that name.
44. True or false: copied displaced instruction bytes mean copied semantics.
45. True or false: a successful run proves an injected binary is correct.

## Case-Based Questions — 3
46. Add a call counter to an authorized stripped PIE while preserving behavior.
47. A patch works on one libc/linker configuration but not another. Diagnose assumptions.
48. A security team wants persistent instrumentation but forbids W+X. Design it.

# Complete Solutions

## Recall solutions
1. Boundary logic allows/omits exactly one element/iteration beyond intended limit; identify invariant, not only symptom.
2. They bind evidence to exact versions and allow rollback/reproduction.
3. Dynamic loader symbol search order by adding a preloaded shared object, subject to security/linking constraints.
4. Substituting/wrapping a symbol resolution so calls reach analysis code.
5. Kernel maps program-header segments; section table alone is not loading authority.
6. Initial control-transfer virtual address.
7. Function-pointer arrays invoked during initialization/finalization phases.
8. A relocated/resolved address or related dynamic data, depending slot/layout.
9. Redirected code that performs analysis/original displaced semantics then returns to continuation.
10. `disp = target - address_after_instruction`, fitted to encoded signed width.

## Conceptual solutions
11. `jl/jle` are signed while `jb/jbe` unsigned; equality may be valid. Wrong patch creates a different bug.
12. Confirm exact instruction boundary/encoding and surrounding bytes were not corrupted.
13. Resolver/logging may allocate or call the hooked API before real pointer/bootstrap is ready.
14. No dynamic symbol lookup occurs for inlined, static, hidden, direct syscall, or bound internal calls.
15. Only a load mapping makes stored bytes available with runtime permissions.
16. It violates write-xor-execute defense and enlarges code-injection risk; separate writable construction from executable final mapping.
17. Entry is earliest/global; constructor is lifecycle-based; GOT/PLT affects imported path; direct-site affects selected call. Requirements/scope/hardening differ.
18. Encoded displacement is relative to original RIP; copying bytes changes effective target.
19. Called routines assume ABI alignment and preserved registers; violations crash or corrupt state.
20. Other inputs, initialization, destructors, exceptions, ASLR, threads, and state may be broken. Regression and invariants matter.

## Application solutions
21. Prove intended continuation is signed `i < bound`, equality is invalid, and operands/types match; test boundaries.
22. Choose aligned appended `p_offset`/`p_vaddr` congruent modulo `p_align`; set `p_filesz/p_memsz` to cover bytes and R-X flags; validate no overlap.
23. Next address `0x401005`; displacement `0x402000-0x401005=0xffb`.
24. Nearby trampoline reachable by rel32, which then uses an absolute/indirect sequence or different encoding to far target.
25. Use recursion guard and allocation-free low-level bootstrap logging; resolve real function safely once, preserve errno/thread safety.
26. No covering executable `PT_LOAD`, wrong VA/offset/alignment/sizes, or permissions. Inspect program headers/mappings.
27. Loader lifecycle, duplicate array entry, fork/dlopen, multiple modules, reentrancy; log module/return address/thread and guard intended scope.
28. File-time relocation/code rewrite, call-site/PLT changes, constructor/entry or DBI—all with exact format semantics. RELRO specifically protects runtime relocation regions.
29. Relocate all whole overwritten instructions totaling ≥5 bytes, pad original remainder appropriately, and resume after entire displaced span. Splitting instruction is invalid.
30. Hard-coded runtime address ignored PIE/ASLR. Use image-relative placement/relocation or compute load base legitimately.

## Multi-step solutions
31. Hash/copy; recover branch/invariant/types; map VA via segment; record bytes; patch same-size encoding; disassemble; boundary input matrix; compare traces/outputs; retain rollback.
32. Interpose alloc/free/copy APIs; bootstrap without recursion; thread-safe object map; use actual allocation sizes and copy lengths; handle realloc/aliases/errors; report bounds, then validate arbitrary writes require DBI.
33. Find/add program-header capacity safely; append aligned payload; choose nonoverlapping VA congruent with offset; create R-X load; optional section/name updates; use PIC; redirect and return; validate readelf/mappings/tests.
34. Decode whole instructions covering branch patch; compute each original semantic target; emit relocated equivalents at new address; save live state/alignment; call analysis; execute displaced semantics; jump continuation; single-step state comparison.
35. Compare lifecycle timing, coverage, persistence, file changes, ABI risk, RELRO/PIE, performance, and reversibility for entry, constructor, GOT/PLT, call-site, and DBI.

## Challenging solutions
36. Put injected R-X bytes in a separate page-aligned segment or extend only an executable mapping without crossing writable section pages; inspect page-rounded overlap and final `/proc/maps` permissions.
37. Recompute RIP load target and encode new displacement if reachable, otherwise synthesize address. Expand short branch to suitable long form/inverted condition + absolute jump while preserving flags/fall-through.
38. Use one-time atomic initialization plus thread-local recursion flag, minimal bootstrap syscalls, no locks/functions that recurse before real pointer, and correct shutdown ordering.
39. Lazy slot initially routes resolver; first call mutates it. `BIND_NOW` resolves at startup; full RELRO then makes region read-only. Observe slot at correct lifecycle and choose non-GOT method if writing later.
40. Define input/environment matrix and invariants; capture outputs/syscalls/files/performance before/after; differential tests, clean restarts, stress threads/errors; acknowledge untested paths rather than claiming universal equivalence.

## Misconception solutions
41. False: signedness and intended equality decide.
42. False: program mapping/permissions decide.
43. False: only eligible dynamic resolutions.
44. False: relative semantics change with location.
45. False: it proves one path/run only.

## Case solutions
46. Prefer DBI for nonpersistent measurement; if persistent, map a PIC R-X trampoline, patch selected direct/indirect sites using module-relative offsets, preserve ABI, and validate across ASLR/threads.
47. Inspect symbol versioning, PLT/GOT layout, lazy/eager flags, RELRO, PIE, ABI, linker relaxation, and library behavior. Remove hard-coded layout assumptions and bind exact target versions.
48. Add separate page-aligned R-X payload/translated code; writable metadata stays RW/NX. Construct offline or write then change to RX before execution, never simultaneous W+X, and validate page-rounded mappings.
