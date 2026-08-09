---
tags: [binary-analysis, dynamic-disassembly, ptrace, dbi, build-guide]
---

# Build Guide — Your Own Dynamic Disassembler

## Goal

Build a Linux x86-64 authorized-lab tracer that records actually executed instruction addresses/bytes, module-relative offsets, branch transitions, and code changes. Begin with `ptrace` single stepping for correctness, then evolve toward breakpoints or DBI for performance.

```text
launch tracee → stop → read registers/memory → decode current instruction
 → record event → advance one instruction → repeat → normalize/report
```

## Safety model

Tracing executes the target. Use only trusted lab binaries or an isolated VM with resource limits, no secrets, controlled filesystem, and disabled/simulated network. A tracer is not a sandbox.

## Stage 1 — event schema

```cpp
struct ExecEvent {
    uint64_t sequence;
    pid_t tid;
    uint64_t runtime_pc;
    std::string module;
    uint64_t module_offset;
    std::array<uint8_t, 15> bytes;
    uint8_t size;
    std::optional<uint64_t> next_pc;
    std::string kind;
};
```

Record module load/unload and mapping permissions so runtime addresses remain interpretable.

## Stage 2 — controlled child launch

Conceptual child:

```c
ptrace(PTRACE_TRACEME, 0, 0, 0);
raise(SIGSTOP);
execve(path, argv, clean_env);
```

Parent waits using `waitpid`, sets ptrace options, then continues through the exec event. Handle every return/error and distinguish stop, signal, exit, and ptrace event.

Use an explicitly constructed environment rather than inheriting analysis secrets.

## Stage 3 — single-step loop

For one thread:

1. wait until stopped;
2. obtain registers (`PTRACE_GETREGS` on appropriate platform API);
3. read up to 15 bytes at `rip` using safe word reads/process VM API;
4. decode one instruction with Capstone at the runtime address;
5. normalize address against `/proc/<pid>/maps` plus ELF load offsets;
6. request `PTRACE_SINGLESTEP`;
7. wait for next stop;
8. record resulting `rip` as actual successor;
9. deliver or suppress pending signals according to transparent policy;
10. stop on exit/budget.

### Why read before stepping?

The bytes at current RIP define the instruction about to execute. Reading afterward sees the successor and can miss self-modification at the old location.

## Stage 4 — mapping runtime addresses

Parse mappings into half-open ranges:

```text
start-end perms file_offset ... path
```

For a mapped file page, relate runtime address to file/image offset using mapping start and file offset. PIE module “base” is not always simply the first executable mapping because that mapping may start at nonzero file offset.

Store:

```text
module_file_offset = mapping_file_offset + (pc - mapping_start)
```

Then relate to static ELF VAs through its load segments.

## Stage 5 — branches and blocks

Decode instruction flow before step; compare observed successor after step:

- conditional: observed taken/fall-through;
- indirect: concrete target discovered;
- call: callee target plus return-site relation;
- return: concrete popped target;
- ordinary: expected fall-through.

Group consecutive events into dynamic basic blocks. An executed trace is a sequence, so repeated loop blocks remain repeated in raw trace; aggregate separately for coverage.

## Stage 6 — threads and processes

Enable clone/fork/vfork/exec options. Maintain per-TID state and wait with thread-aware semantics. Newly created tracees arrive stopped; add them to the scheduler. Do not assume events alternate predictably.

Policy choices:

- trace only original process or descendants;
- serialize threads for determinism (changes races);
- preserve approximate scheduling (harder);
- record signals and syscall boundaries.

## Stage 7 — signals

Not every `SIGTRAP` is your single-step trap: exec, breakpoints, ptrace events, or target-generated traps may use it. Inspect event/status metadata. Suppressing a real target signal changes semantics; reinject signals appropriately.

## Stage 8 — self-modifying code

Hash/cache bytes per executed address. If the same address later decodes from different bytes, emit a code-version event and invalidate cached block data.

For better unpacking detection, observe memory writes through DBI/hardware/page-protection strategies, then report first execution of written bytes. `ptrace` single-step alone sees byte changes but not necessarily the writer efficiently.

## Stage 9 — performance upgrade

Single-step incurs a stop/context switch per instruction and is extremely slow.

Upgrade options:

1. software breakpoints at basic-block leaders; manage original byte and instruction-pointer correction;
2. hardware breakpoints for a few focused sites;
3. `perf`/hardware branch tracing where available;
4. DynamoRIO/Pin/Frida DBI for translated blocks and callbacks;
5. emulator for maximum state control.

Maintain the same event schema so the analysis/output layer survives backend changes.

## Stage 10 — DBI backend architecture

Implement callbacks for:

- image load/unload;
- basic-block execution;
- indirect transfer target;
- syscall entry/exit;
- memory writes if unpacking is required.

Use thread-local buffers and batch output. Emit image offset instead of only raw address. Never perform complex allocation/logging in a hot callback if the framework documents restrictions.

## Test program

```c
#include <stdio.h>
static int f(int x) { return x > 3 ? x * 2 : x + 1; }
int main(int argc, char **argv) {
    int x = argc > 1 ? argv[1][0] - '0' : 0;
    printf("%d\n", f(x));
}
```

Build `-O0`, `-O2`, PIE, and non-PIE. Verify:

- same input gives same module-relative control-flow edges;
- different branch inputs differ at the predicate;
- runtime addresses vary under PIE/ASLR while offsets remain stable;
- loop counts aggregate correctly;
- signals and clean exit are preserved.

## Common failures

| Failure | Correction |
|---|---|
| tracer hangs | inspect wait status/TID/event and pending signal policy |
| bytes unreadable | mapping changed, target exited, cross-page read; bounded reads |
| wrong successor | syscall/signal/event or decode-width error |
| target behaves differently | timing/signal/env instrumentation effect |
| enormous logs | aggregate blocks, buffer binary events, add budgets |
| wrong PIE offset | incorporate mapping file offset and ELF segment relation |

## Completion gate

- [ ] Trace sequence matches a manual GDB walk on toy cases.
- [ ] Direct and indirect observed edges are recorded.
- [ ] PIE normalization is stable across five runs.
- [ ] Threads/exits/signals do not deadlock simple fixtures.
- [ ] Code-byte changes create new versions.
- [ ] Resource/time/event limits terminate hostile loops safely.
- [ ] DBI backend produces the same normalized schema.

## GDB/pwndbg and Ghidra Integration

Use [[../reversing-secrets-of-reverse-engineering/Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] as the reference debugger workflow.

1. Manually trace each toy fixture in GDB/pwndbg before implementing the tracer.
2. Log `PC`, raw bytes, decoded instruction, module identity, RVA, thread, event, and code-version hash.
3. Compare single-step sequences with `x/i`, `disassemble /r`, `context`, and `vmmap`.
4. Use conditional breakpoints/watchpoints to validate memory-write and self-modifying-code events.
5. Import the same fixture into Ghidra; overlay observed blocks/edges on the static CFG.
6. Preserve three states: statically predicted, dynamically observed, and unresolved.
7. Test PIE across repeated runs by verifying stable RVAs despite different runtime VAs.
8. Cross-check indirect calls with pwndbg `xinfo` and return confirmed module/RVA/type annotations to Ghidra.
9. Compare thread/fork/signal behavior against a manual GDB transcript.
10. Treat debugger-induced timing, software-breakpoint bytes, and coverage gaps as explicit limitations.
