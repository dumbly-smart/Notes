---
tags: [reverse-engineering, windows-internals, pe, chapter-notes]
chapter: 3
---

# Chapter 3 — Windows Fundamentals

## Chapter overview

This chapter gives the operating-system model needed to interpret Windows binaries: architecture, virtual memory/paging, process address spaces, section objects/VADs, handles/objects, processes/threads/synchronization, Win32 and Native APIs, system calls, PE loading, I/O, and structured exceptions.

The specific Windows versions and implementation details are historical. The durable objective is to ask: **which component owns this state, which boundary is crossed, and which runtime object/mapping makes the instruction meaningful?**

### Chapter roadmap

```text
Windows execution
├── memory manager
│   ├── virtual pages, faults, working sets
│   ├── user/kernel address spaces
│   └── sections, VADs, allocations
├── object manager
│   └── named kernel objects and per-process handles
├── scheduler/execution
│   └── processes, threads, context switches, synchronization
├── API boundary
│   └── Win32 → Native API → system call → kernel
├── image loader
│   └── PE sections, DLLs, headers, imports/exports/directories
└── I/O and structured exceptions
```

## Components and basic architecture

Windows separates user-mode applications/subsystems from privileged kernel components. Hardware architectures and Windows versions affect address layout, calling conventions, system-call entry, mitigations, and internal structures.

**User mode:** restricted execution where applications cannot directly access kernel memory/privileged operations.

**Kernel mode:** privileged OS/driver execution. A user-to-kernel transition does not grant the application kernel privileges; the kernel performs validated service work.

## Memory management

### Virtual memory and paging

Each process sees a virtual address space. Page tables map virtual pages to physical frames or encode nonresident/invalid states.

```text
virtual address
├── virtual page number → page-table translation/protection
└── page offset         → offset within physical page
```

A page fault means translation/protection could not immediately complete. The OS may load a file-backed page, allocate zero page, perform copy-on-write, grow stack, or raise an exception for invalid access.

**Common misunderstanding:** page fault is not synonymous with application crash.

### Working sets

The working set approximates pages resident for a process at a time. Residency changes performance and observation, not the logical virtual allocation.

### Kernel and user memory

Historical 32-bit Windows divided virtual space between user and kernel ranges. Exact split varies by configuration/version; modern x64 layout differs. Reversers should inspect actual mappings and symbols rather than memorize one boundary.

### Section objects

A Windows section object represents memory that can be mapped into one or more address spaces, often backed by a file/image or page file. It underlies shared memory and executable image mapping.

**Do not confuse:** Windows kernel section object with a PE section header. They relate during image mapping but live at different abstraction layers.

### VAD trees

Virtual Address Descriptors track allocated/mapped address ranges and properties. The book’s details are historical; the concept explains how the OS represents sparse regions and why debuggers enumerate allocations.

### User-mode allocations and APIs

Heap allocators request/manage address ranges; `VirtualAlloc`-like APIs reserve/commit pages; mapped files/sections create shared or file-backed views. For a pointer, determine mapping, permissions, backing, allocation origin, and lifetime.

## Objects and handles

The object manager provides named/unnamed kernel objects: files, events, mutexes, processes, threads, sections, registry-related objects, and more.

**Handle:** process-local value indexing/referencing an object with granted access.

**In simple words:** a ticket used by one process to ask the kernel to operate on an object.

Properties:

- a handle value is not a raw kernel pointer;
- the same number can refer to different objects in different processes/times;
- duplication/inheritance changes handle relationships;
- closing ends one reference, not necessarily object lifetime if others remain;
- access rights constrain allowed operations.

### Named objects

Names allow discovery/sharing across processes within namespaces. Malware, installers, and single-instance applications may use a named mutex/event as an existence marker; the name alone does not establish intent.

## Processes and threads

### Processes

A process is a resource/protection container: virtual address space, handle table, security context, modules, and one or more threads.

### Threads

A thread is an execution context: instruction pointer, registers, stacks, scheduling and thread-local state. Multiple threads share process memory, which introduces races and synchronization dependencies.

### Context switching

The scheduler saves one thread’s architectural context and restores another. A debugger stop shows a point in one schedule; different interleavings can alter concurrency bugs.

### Synchronization objects

Events, mutexes, semaphores, critical sections and waits coordinate state. To reverse a thread relationship, create a timeline:

```text
T1 writes state → signals event
T2 wakes → reads state → resets/signals next stage
```

### Process initialization

Conceptually:

1. create process/address-space/kernel objects;
2. map executable and required runtime components;
3. establish initial thread/stack/environment;
4. loader maps DLLs/resolves imports/runs initialization/TLS callbacks;
5. transfer through runtime startup to application entry.

Callbacks/initializers may execute before the apparent `main`/entry routine an analyst first inspects.

## APIs and system calls

### Win32 API

Documented application interface exposed by system DLLs. One Win32 call can validate/transform arguments and call several lower-level routines.

### Native API

Lower-level interfaces historically exported by `ntdll` and used by subsystem/runtime components to request kernel services. Exact functions/contracts may be undocumented and version-dependent.

### System-call mechanism

User stubs arrange syscall identifier/arguments and execute architecture/version-specific transition. The kernel validates and dispatches. Hard-coding syscall numbers/mechanisms across Windows versions is brittle.

| Layer | Analyst learns |
|---|---|
| Win32 | application intent and friendly parameters |
| Native API | lower-level object/memory/I/O contract |
| syscall | actual kernel boundary and concrete service |
| kernel implementation | validation, object manager, drivers, final effects |

## Executable formats

The chapter introduces PE image sections, alignment, DLLs, headers, imports/exports, and directories. Detailed format notes: [[../practical-binary-analysis/Chapter 03 - The PE Format]].

### Basic mapping model

PE raw sections are mapped at image-relative virtual addresses with virtual protections/alignment. Imports become IAT-resolved addresses; exports advertise callable entities; data directories locate structured tables such as relocations, resources, TLS, exceptions, and imports.

```text
runtime VA = actual image base + RVA
```

ASLR changes actual base. Normalize debugger addresses to module+RVA.

## Input and output

The I/O manager coordinates requests through files/devices/drivers, often asynchronously. Win32 subsystems expose higher-level object and I/O semantics. A call returning does not always mean all physical I/O completed; examine synchronous/asynchronous contract, status, buffers, and completion.

## Structured exception handling

SEH routes faults/software exceptions to registered/table-based handlers and unwind logic. Exceptions can represent errors, language constructs, control-flow obfuscation, or debugger detection.

### Reversing an exception path

1. identify fault/raise site and exception code;
2. enumerate handler/unwind metadata for exact architecture;
3. observe dispatch and handler decision;
4. reconstruct state restoration/unwind;
5. add exception edges to CFG;
6. test handled and unhandled cases.

## Worked example — connect a file handle to a memory mapping

**Situation:** a process opens a file, creates a mapping, then reads bytes without ordinary `ReadFile` calls.

1. Monitor open/create and capture handle/object identity.
2. Observe section/file-mapping creation from that handle.
3. Observe view mapping and returned virtual range.
4. Correlate memory reads to mapped range.
5. Translate offsets using view/file mapping information.
6. Confirm cleanup through unmap/handle closes.

**Key lesson:** absence of read syscalls does not imply file contents are unused; memory mapping changes the I/O path.

## Common mistakes

- Treating a handle as a pointer or permanent object identity.
- Assuming one historical user/kernel split/current syscall number.
- Ignoring TLS callbacks and DLL initialization before entry.
- Calling every page fault a crash.
- Reading PE section layout as identical to runtime allocation objects.
- Building single-thread causal stories without waits/signals.

## Chapter synthesis

### Chapter in one view

```text
PE image + process creation
 → virtual mappings and loader resolution
 → threads execute via APIs/syscalls
 → handles refer to kernel objects
 → I/O, synchronization, and exceptions shape behavior
```

### Key definitions

virtual memory, page, page fault, working set, section object, VAD, object, handle, process, thread, context switch, synchronization, Win32 API, Native API, syscall, DLL, IAT, SEH.

### What you should be able to explain

- [ ] Map a virtual address to its process/module/allocation context.
- [ ] Explain handle/object identity and lifetime.
- [ ] Trace Win32 through native/system boundary.
- [ ] Include threads, initialization, I/O and exceptions in behavior.

### What you should be able to solve

- [ ] Correlate a system-monitor event with runtime code.
- [ ] Normalize ASLR addresses to module RVAs.
- [ ] Reconstruct a process/thread/synchronization timeline.
- [ ] Analyze mapped-file and exception-driven behavior.

Practice and solutions: [[Reversing - Complete Practice Workbooks#Chapter 3 — Windows Fundamentals]].

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs I - Foundations Through Tools]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
