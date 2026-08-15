---
tags: [reverse-engineering, labs, assessment, curriculum]
---

# Reversing — 100 Lab Mastery Roadmap

## Rules

Every lab uses software you built, an authorized challenge, or a deliberately safe corpus. For each lab submit: hash/environment, question, facts/hypotheses, annotated addresses, reconstructed model, tests, and unknowns. A lab is incomplete if you only found a flag.

## Labs 1–10 — representation and ABI

1. Trace one C expression through preprocessing, assembly, object relocation, executable, and runtime.
2. Compare static and dynamic linking.
3. Reverse five calling conventions/ABI patterns.
4. Recover stack arguments and locals without frame pointer.
5. Recover signed versus unsigned boundaries.
6. Explain partial-register writes.
7. Recover a variadic call.
8. Recover a tail call.
9. Recover position-independent data access.
10. Explain one exception/unwind path.

## Labs 11–20 — control structures

11. `if/else` diamond; 12. nested conditions; 13. short circuit; 14. counted loop; 15. sentinel loop; 16. do-while; 17. dense switch; 18. sparse switch; 19. recursion; 20. state machine.

## Labs 21–30 — data structures

21. byte/word/dword array; 22. padded structure; 23. union; 24. C string; 25. wide string; 26. singly linked list; 27. doubly linked list; 28. binary tree; 29. vtable object; 30. callback registry.

## Labs 31–40 — compiler transformations

31. constant folding; 32. inlining; 33. outlining; 34. loop unrolling; 35. strength reduction; 36. constant division; 37. branchless conditional; 38. vectorized loop; 39. LTO; 40. dead/tail merging.

## Labs 41–50 — formats and interfaces

41. ELF parser; 42. PE parser; 43. import/export map; 44. relocation walk; 45. undocumented API signature; 46. callback contract; 47. binary file header; 48. variable records; 49. checksum; 50. request/response protocol state machine.

## Labs 51–60 — dynamic analysis

51. syscall-to-call-site; 52. buffer construction watchpoint; 53. indirect target trace; 54. thread timeline; 55. exception path; 56. loader/TLS initialization; 57. self-modifying toy; 58. unpacking transition; 59. coverage diff; 60. record/replay debugging.

## Labs 61–70 — security auditing

61. stack bound; 62. heap bound; 63. OOB read; 64. integer wrap; 65. truncation; 66. signedness; 67. format string; 68. UAF; 69. double free; 70. logic/auth ordering. For each: root cause → primitive → hardened comparison → fix/regression.

## Labs 71–80 — hostile analysis

71. stripped symbols; 72. encoded strings; 73. debugger check; 74. timing check; 75. checksum; 76. opaque predicate; 77. jump-over-data; 78. flattened state machine; 79. API hashing toy; 80. multi-stage packed toy.

## Labs 81–90 — automation

81. ELF loader; 82. Capstone linear pass; 83. recursive CFG; 84. DOT export; 85. jump-table recovery; 86. ptrace dynamic decoder; 87. DBI block profiler; 88. taint policy; 89. symbolic branch generator; 90. decompiler-output verifier.

## Labs 91–96 — managed and cross-platform

91. IL evaluation stack; 92. .NET metadata/tokens; 93. managed obfuscation; 94. P/Invoke boundary; 95. ARM calling/branch pattern; 96. firmware container/static triage.

## Capstones 97–100

97. Recover and implement an undocumented file-format parser.
98. Analyze an isolated malware-simulation sample from installation to local protocol.
99. Audit an unseen parser and deliver fixed regression suite.
100. Reverse an unseen optimized stripped application and deliver component map, data model, algorithms, dynamic evidence, security assessment, automation, and executive report.

## Scoring rubric (100 points per capstone)

| Area | Points |
|---|---:|
| exact identity, scope, reproducibility | 10 |
| external behavior/system model | 10 |
| CFG/function recovery | 15 |
| data structures/types/invariants | 15 |
| algorithm/interface reconstruction | 15 |
| dynamic causal tests | 10 |
| security reasoning | 10 |
| automation and artifacts | 5 |
| uncertainty/alternative hypotheses | 5 |
| clarity and peer reproducibility | 5 |

Passing is 80 with no zero in scope, reproducibility, or uncertainty. “Best” is not a one-time score: redo capstones on new architectures, compilers, operating systems, and optimization/obfuscation families.


> [!integration]
> Perform these exercises with [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] and the paired mentor-code volumes. A lab is complete only when static predictions agree with dynamic evidence.
