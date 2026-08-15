# Chapter 11 Workbook — Practical DTA with libdft

Return to [[../Chapter 11 - Practical Taint Analysis with libdft]].

# Chapter Practice Set

## Recall Questions — 10
1. What foundation does libdft use in the book?
2. What is tagmap state?
3. Why capture syscall arguments at entry?
4. Why use syscall return at exit?
5. What does a tainted indirect target indicate?
6. What is fd provenance?
7. Why track `close`?
8. Why track `dup`?
9. What is scatter/gather output?
10. What is per-thread syscall context?

## Conceptual Questions — 10
11. Why taint actual received bytes only?
12. Why is a tainted `execve` argument context-sensitive?
13. Why does target taint strengthen control-hijack evidence?
14. Why does it not prove reliable RCE?
15. Why can implicit flow evade libdft policy?
16. Why are descriptor numbers insufficient identity?
17. Why can `sendmsg` evade a simple `send` hook?
18. Why does encrypted output complicate exfiltration policy?
19. Why do framework/API versions matter?
20. Why should reports include concrete event plus tag provenance?

## Application Problems — 10
21. `recv(buf,100)` returns 17. Mark interval.
22. `recv` returns `-1`. Mark what?
23. fd 3 secret closes, then public file reuses 3. Required state changes?
24. `dup2(3,7)` succeeds. Propagate what?
25. One thread enters read while another exits. Prevent context mix.
26. Check taint on `execve(path,argv,envp)` safely.
27. Check a return target tag.
28. `write` sends only half buffer. Inspect what?
29. `sendmsg` has three iovecs. Inspect what?
30. `mmap` reads secret file. What model extension?

## Multi-Step Problems — 5
31. Build remote-control detector.
32. Build secret-file exfiltration detector.
33. Test descriptor reuse and duplication.
34. Add provenance-rich deduplicated reports.
35. Validate policy with positive/negative toy cases.

## Challenging Problems — 5
36. Model fork/exec descriptor inheritance.
37. Handle asynchronous signals during syscalls.
38. Track taint through partial-register instructions.
39. Reduce false positives for approved backups.
40. Detect explicit-flow evasion via control encoding.

## Trick / Misconception Questions — 5
41. True or false: requested read length should all be tainted.
42. True or false: fd number permanently identifies a file.
43. True or false: tainted `execve` argument is always command injection.
44. True or false: one global pending syscall record works with threads.
45. True or false: hooking `send` covers all network output.

## Case-Based Questions — 3
46. Detector reports secret color after fd reuse. Diagnose.
47. Return target is controlled through an implicit bit-building loop but untainted. Explain.
48. A multithreaded service yields nondeterministic labels. Build repair plan.

# Complete Solutions

## Recall solutions
1. Intel Pin DBI in the book’s implementation context.
2. Shadow tags associated with application memory/registers.
3. Entry provides pointers, descriptors, requested lengths before kernel operation.
4. Exit supplies success and actual bytes/effects.
5. Policy-labeled source data influenced the executed target value under that run.
6. Association between descriptor/open-file identity and source color/trust metadata.
7. Remove association before number is reused.
8. New descriptor can reference same open file/provenance.
9. Output from multiple buffers described by iovec-like arrays.
10. Saved entry arguments/event state keyed to the correct thread until exit.

## Conceptual solutions
11. Kernel defines only returned range; tagging request overmarks untouched memory and causes false flows.
12. User-supplied argument can be intended; command policy/validation/privilege determines vulnerability.
13. It connects attacker source bytes to security-sensitive control data directly.
14. Mitigations, address knowledge, transformations, crashes, and constraints may prevent stable objective.
15. Default explicit propagation does not label constants chosen by tainted branches.
16. Numbers are process-local and reused; identity/lifetime/duplication matter.
17. Data lives in nested iovecs and a different syscall/API path.
18. Secret-derived ciphertext is expected to leave; policy must distinguish approved encryption/destination from unauthorized plaintext flow.
19. Book-era interfaces/build assumptions change; port architecture/policy to supported framework rather than copy code blindly.
20. It makes claim reproducible: site, target/bytes, source event/color, thread/time, and limitations.

## Application solutions
21. `[buf,buf+17)` only, after validating positive result and arithmetic.
22. Nothing; error wrote no received payload under ordinary semantics.
23. Remove secret association on close; create new public association/none on new open; never inherit by numeric coincidence.
24. Replace fd 7’s old association and copy/share fd 3’s open-file provenance, handling `3==7` and errors.
25. Store entry state in thread-local map keyed by TID/syscall nesting model.
26. Bounded-read pointer and each NUL-terminated string/array with mapping limits; check path and actual argument/environment bytes; handle invalid pointers.
27. Before executed `ret`, identify target source (stack/memory), query all bytes forming pointer tag, record concrete target and source provenance.
28. Only actual positive return count from beginning of buffer (or syscall semantics), not requested whole buffer.
29. Validate msghdr/iovec count/pointers/lengths, walk bounded iovecs, and map actual transmitted byte count across them.
30. Associate mapped file pages with source provenance on successful mapping/page population according to model, including offsets and shared/private behavior.

## Multi-step solutions
31. Initialize framework; per-thread syscall context; tag actual recv/read; propagate; instrument indirect calls/jumps/returns and exec arguments; report; test safe/overflow/implicit cases.
32. Resolve allowed secret paths/handles; manage open/dup/close; tag read/mmap results; identify socket destinations; inspect write/send/sendmsg actual bytes; context allowlist and provenance.
33. Script open secret→dup→close originals→reuse numbers→reads; assert colors follow open-file identity and vanish on final close; include errors and concurrent operations.
34. Key duplicate reports by image offset/sink/source/color/code version while counting occurrences; include first/representative concrete event, stack/module and policy version.
35. Positive explicit leak/control toys; safe bounded user input; approved secret flow; short/error reads; fd reuse; implicit flow expected miss; assert both alerts and nonalerts.

## Challenging solutions
36. Model inherited open descriptions/colors in child; copy state on fork according to semantics, handle exec retaining non-CLOEXEC descriptors, close-on-exec, and process identity in reports.
37. Correctly pair restarted/interrupted syscalls, preserve thread context, observe return codes, avoid tagging before completion, and model handler reads/writes separately.
38. Use architecture-correct byte tags for subregister reads/writes, zero-extension on 32-bit writes, high-byte registers, and instruction semantics; differential unit tests.
39. Add process role, approved path/destination, encryption/backup operation and policy scope; retain audit provenance instead of clearing tags early.
40. Add control/PC taint or specialized pattern detector, compare branch-condition dependencies, or use symbolic/backward slice; report performance/overtaint cost.

## Misconception solutions
41. False: actual returned bytes only.
42. False: reuse and process scope.
43. False: influence can be legitimate.
44. False: races mix arguments/results.
45. False: write/sendto/sendmsg and other paths exist.

## Case solutions
46. Missing/incorrect close/reuse/dup state. Reconstruct fd timeline, clear on successful close, assign on successful open, add regression.
47. Input controls branches that write untainted constants; explicit DTA loses provenance. Add control tracking or specialized analysis and state original policy limit.
48. Audit TLS versus shared tag state, syscall pairing, fd-map locking, event ordering, code versions, and framework thread callbacks; reproduce with deterministic workload then stress.
