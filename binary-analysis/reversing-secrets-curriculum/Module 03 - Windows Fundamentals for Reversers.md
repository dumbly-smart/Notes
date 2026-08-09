---
tags: [reverse-engineering, windows-internals, curriculum]
source_chapter: 3
---

# Module 3 — Windows Fundamentals for Reversers

## Module overview

The book supplies the operating-system model needed to interpret Windows binaries: virtual memory, paging/working sets, user/kernel split, section objects/VADs, handles, processes/threads, synchronization, APIs/system calls, PE loading, I/O, and structured exceptions.

## Runtime model

```text
process
├── virtual address space
│   ├── image/DLL mappings
│   ├── heaps/stacks
│   └── private/shared section-backed regions
├── handle table → kernel objects
└── threads → registers, stack, scheduling state
```

**Virtual memory:** per-process address abstraction translated through paging. A page fault is not automatically a crash; it may trigger demand paging, copy-on-write, stack growth, or exception if invalid.

**Handle:** process-local reference to a kernel-managed object. The numeric value alone does not identify object type across processes/runs.

## API layers

Win32 APIs provide documented application interfaces. Native APIs are lower-level user/kernel interfaces used by subsystems and system libraries. System calls transition to kernel services. Names/implementation paths change across versions, so verify exact build.

## Processes, threads, and synchronization

A process owns address-space/resource context; threads execute within it. Context switches save/restore thread state. Events, mutexes, semaphores, and other objects coordinate order. Race analysis needs thread and synchronization timelines, not a single linear trace.

## PE and loading connection

Image sections become mapped memory; imports resolve DLL dependencies; relocations account for changed base; entry/TLS/initialization paths begin execution. Link this module with [[../practical-binary-analysis/Chapter 03 - The PE Format]].

## Structured exception handling

Exceptions redirect control according to handlers/unwind metadata and runtime rules. They can implement normal error paths or anti-analysis tricks. A CFG that ignores exception edges is incomplete.

## Modernization note

The book’s exact Windows internal structures and syscall mechanisms are historical. Preserve concepts, then verify current Microsoft symbols/documentation and observed behavior in a disposable VM.

## Lab

1. Build a Windows toy that allocates memory, creates a worker thread/event, loads a DLL, and raises a handled exception.
2. Record process modules, mappings, handles, threads, and API events.
3. Break at documented API and lower-level transition.
4. Correlate PE sections to runtime mappings.
5. Draw the exception and synchronization control paths.

## Mastery gate

- [ ] Explain VA translation/page faults without equating them with crashes.
- [ ] Correlate handles with object operations and lifetimes.
- [ ] Distinguish process, thread, user API, native API, and kernel service.
- [ ] Include initialization and exception edges in analysis.
