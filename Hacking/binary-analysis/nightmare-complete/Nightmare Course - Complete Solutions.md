---
title: "Nightmare Course - Complete Solutions"
aliases:
  - Nightmare Course
  - Nightmare CTF Solutions
tags:
  - binary-analysis/nightmare
  - index
---

# Nightmare — Complete Binary Exploitation and Reverse Engineering Solutions

> [!info] What this contains
> A complete Obsidian edition of the Nightmare course: **133 detailed notes** across **52 modules**. The original walkthroughs are retained in full, including commands, disassembly, debugger sessions, calculations, exploit scripts, and validation output.

> [!warning] Use responsibly
> Run the techniques only against these supplied CTF binaries or systems you are authorized to test.

## How to study each solution

1. Read the initial binary triage and predict the likely bug before reading ahead.
2. Reproduce the static and dynamic analysis locally.
3. Calculate offsets, addresses, constraints, and mitigations yourself.
4. Build the exploit incrementally and inspect the process after each primitive works.
5. Compare your exploit with the walkthrough, then explain why every payload field exists.
6. Re-run from a clean process and record environmental differences such as libc, ASLR, or stack alignment.

## Complete module map

| Module | Topic | Notes |
|---:|---|---:|
| 00 | [[Hacking/binary-analysis/nightmare-complete/00-intro/00-intro - Module Index|Intro]] | 1 |
| 01 | [[Hacking/binary-analysis/nightmare-complete/01-intro_assembly/01-intro_assembly - Module Index|Intro Assembly]] | 2 |
| 02 | [[Hacking/binary-analysis/nightmare-complete/02-intro_tooling/02-intro_tooling - Module Index|Intro Tooling]] | 3 |
| 03 | [[Hacking/binary-analysis/nightmare-complete/03-beginner_re/03-beginner_re - Module Index|Beginner Reverse Engineering]] | 4 |
| 04 | [[Hacking/binary-analysis/nightmare-complete/04-bof_variable/04-bof_variable - Module Index|BOF Variable]] | 3 |
| 05 | [[Hacking/binary-analysis/nightmare-complete/05-bof_callfunction/05-bof_callfunction - Module Index|BOF Callfunction]] | 3 |
| 5.1 | [[Hacking/binary-analysis/nightmare-complete/5.1-mitigation_aslr_pie/5.1-mitigation_aslr_pie - Module Index|Mitigation Aslr Pie]] | 1 |
| 06 | [[Hacking/binary-analysis/nightmare-complete/06-bof_shellcode/06-bof_shellcode - Module Index|BOF Shellcode]] | 3 |
| 6.1 | [[Hacking/binary-analysis/nightmare-complete/6.1-mitigation_nx/6.1-mitigation_nx - Module Index|Mitigation Nx]] | 1 |
| 07 | [[Hacking/binary-analysis/nightmare-complete/07-bof_static/07-bof_static - Module Index|BOF Static]] | 3 |
| 7.1 | [[Hacking/binary-analysis/nightmare-complete/7.1-mitigation_canary/7.1-mitigation_canary - Module Index|Mitigation Canary]] | 1 |
| 7.2 | [[Hacking/binary-analysis/nightmare-complete/7.2-mitigation_relro/7.2-mitigation_relro - Module Index|Mitigation Relro]] | 1 |
| 08 | [[Hacking/binary-analysis/nightmare-complete/08-bof_dynamic/08-bof_dynamic - Module Index|BOF Dynamic]] | 5 |
| 09 | [[Hacking/binary-analysis/nightmare-complete/09-bad_seed/09-bad_seed - Module Index|Bad Seed]] | 3 |
| 10 | [[Hacking/binary-analysis/nightmare-complete/10-fmt_strings/10-fmt_strings - Module Index|Format String Strings]] | 4 |
| 11 | [[Hacking/binary-analysis/nightmare-complete/11-index/11-index - Module Index|Index]] | 4 |
| 12 | [[Hacking/binary-analysis/nightmare-complete/12-z3/12-z3 - Module Index|Z3]] | 3 |
| 13 | [[Hacking/binary-analysis/nightmare-complete/13-angr/13-angr - Module Index|Angr]] | 3 |
| 14 | [[Hacking/binary-analysis/nightmare-complete/14-ret_2_system/14-ret_2_system - Module Index|Ret 2 System]] | 3 |
| 15 | [[Hacking/binary-analysis/nightmare-complete/15-partial_overwrite/15-partial_overwrite - Module Index|Partial Overwrite]] | 3 |
| 16 | [[Hacking/binary-analysis/nightmare-complete/16-srop/16-srop - Module Index|SROP]] | 4 |
| 17 | [[Hacking/binary-analysis/nightmare-complete/17-stack_pivot/17-stack_pivot - Module Index|Stack Pivot]] | 4 |
| 18 | [[Hacking/binary-analysis/nightmare-complete/18-ret2_csu_dl/18-ret2_csu_dl - Module Index|Ret2 Csu Dl]] | 2 |
| 19 | [[Hacking/binary-analysis/nightmare-complete/19-shellcoding_pt1/19-shellcoding_pt1 - Module Index|Shellcoding Pt1]] | 3 |
| 20 | [[Hacking/binary-analysis/nightmare-complete/20-patching_and_jumping/20-patching_and_jumping - Module Index|Patching And Jumping]] | 3 |
| 21 | [[Hacking/binary-analysis/nightmare-complete/21-dot_net/21-dot_net - Module Index|Dot .NET]] | 3 |
| 22 | [[Hacking/binary-analysis/nightmare-complete/22-movfuscation/22-movfuscation - Module Index|Movfuscation]] | 3 |
| 23 | [[Hacking/binary-analysis/nightmare-complete/23-custom_architecture/23-custom_architecture - Module Index|Custom Architecture]] | 4 |
| 24 | [[Hacking/binary-analysis/nightmare-complete/24-heap_overflow/24-heap_overflow - Module Index|Heap Overflow]] | 3 |
| 25 | [[Hacking/binary-analysis/nightmare-complete/25-heap/25-heap - Module Index|Heap]] | 1 |
| 26 | [[Hacking/binary-analysis/nightmare-complete/26-heap_grooming/26-heap_grooming - Module Index|Heap Grooming]] | 3 |
| 27 | [[Hacking/binary-analysis/nightmare-complete/27-edit_free_chunk/27-edit_free_chunk - Module Index|Edit Free Chunk]] | 3 |
| 28 | [[Hacking/binary-analysis/nightmare-complete/28-fastbin_attack/28-fastbin_attack - Module Index|Fastbin Attack]] | 3 |
| 29 | [[Hacking/binary-analysis/nightmare-complete/29-tcache/29-tcache - Module Index|tcache]] | 3 |
| 30 | [[Hacking/binary-analysis/nightmare-complete/30-unlink/30-unlink - Module Index|Unlink]] | 3 |
| 31 | [[Hacking/binary-analysis/nightmare-complete/31-unsortedbin_attack/31-unsortedbin_attack - Module Index|Unsortedbin Attack]] | 3 |
| 32 | [[Hacking/binary-analysis/nightmare-complete/32-largebin_attack/32-largebin_attack - Module Index|Largebin Attack]] | 2 |
| 33 | [[Hacking/binary-analysis/nightmare-complete/33-custom_misc_heap/33-custom_misc_heap - Module Index|Custom Misc Heap]] | 3 |
| 34 | [[Hacking/binary-analysis/nightmare-complete/34-emulated_targets/34-emulated_targets - Module Index|Emulated Targets]] | 3 |
| 35 | [[Hacking/binary-analysis/nightmare-complete/35-integer_exploitation/35-integer_exploitation - Module Index|Integer Exploitation]] | 3 |
| 36 | [[Hacking/binary-analysis/nightmare-complete/36-obfuscated_reversing/36-obfuscated_reversing - Module Index|Obfuscated Reversing]] | 3 |
| 37 | [[Hacking/binary-analysis/nightmare-complete/37-fs_exploitation/37-fs_exploitation - Module Index|Fs Exploitation]] | 1 |
| 38 | [[Hacking/binary-analysis/nightmare-complete/38-grab_bad/38-grab_bad - Module Index|Grab Bad]] | 4 |
| 39 | [[Hacking/binary-analysis/nightmare-complete/39-house_of_spirit/39-house_of_spirit - Module Index|House Of Spirit]] | 2 |
| 40 | [[Hacking/binary-analysis/nightmare-complete/40-house_of_lore/40-house_of_lore - Module Index|House Of Lore]] | 1 |
| 41 | [[Hacking/binary-analysis/nightmare-complete/41-house_of_force/41-house_of_force - Module Index|House Of Force]] | 2 |
| 42 | [[Hacking/binary-analysis/nightmare-complete/42-house_of_einherjar/42-house_of_einherjar - Module Index|House Of Einherjar]] | 1 |
| 43 | [[Hacking/binary-analysis/nightmare-complete/43-house_of_orange/43-house_of_orange - Module Index|House Of Orange]] | 1 |
| 44 | [[Hacking/binary-analysis/nightmare-complete/44-more_tcache/44-more_tcache - Module Index|More tcache]] | 2 |
| 45 | [[Hacking/binary-analysis/nightmare-complete/45-automatic_exploit_generation/45-automatic_exploit_generation - Module Index|Automatic Exploit Generation]] | 1 |
| — | [[Hacking/binary-analysis/nightmare-complete/next/next - Module Index|Next]] | 1 |
| — | [[Hacking/binary-analysis/nightmare-complete/references/references - Module Index|References]] | 1 |

## Practical solve loop

```text
identify format/architecture → inspect mitigations → map input paths
→ locate the bug → prove control/read/write primitive → choose a strategy
→ calculate exact payload → test locally → account for environment → validate
```

## Source and scope

Imported from the local `nightmare/modules` course tree. Explanatory chapters, mitigation notes, tooling notes, references, and challenge solutions are all included so the collection remains self-contained as a learning route.
