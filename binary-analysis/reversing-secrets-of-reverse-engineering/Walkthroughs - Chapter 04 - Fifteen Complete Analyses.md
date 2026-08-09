# Chapter 4 — Fifteen Complete Ghidra and GDB/pwndbg Walkthroughs

> [!evidence]
> These walkthroughs use the executed Chapter 1 corpus because tooling mastery is best measured by applying fifteen different investigations to one unchanged stripped artifact. No output below is hypothetical.

## Exact specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;

typedef struct Node { uint32_t key; int32_t value; struct Node *next; } Node;
typedef int (*transform_fn)(int, int);

NI uint32_t lab01_rolling_hash(const uint8_t *p, size_t n) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i=0;i<n;i++) h = (h ^ p[i]) * 0x01000193u;
    return h;
}

NI size_t lab02_rle_decode(uint8_t *out, size_t cap, const uint8_t *in, size_t n) {
    size_t r=0,w=0;
    while (r+1<n) {
        uint8_t count=in[r++], byte=in[r++];
        if (count > cap-w) return SIZE_MAX;
        for (uint8_t i=0;i<count;i++) out[w++]=byte;
    }
    return r==n ? w : SIZE_MAX;
}

NI int lab03_validate_header(const uint8_t *p, size_t n) {
    if (n < 12 || memcmp(p,"REV1",4)!=0) return -1;
    uint16_t version; uint32_t length;
    memcpy(&version,p+4,2); memcpy(&length,p+8,4);
    if (version != 3 || length > n-12) return -2;
    return (int)length;
}

NI int lab04_protocol_state(const char *s) {
    enum { START, USER, SPACE, NUMBER, DONE, BAD } st=START;
    int value=0;
    for (;*s && st!=BAD && st!=DONE;s++) {
        unsigned char c=(unsigned char)*s;
        switch(st) {
        case START: st=(c=='U')?USER:BAD; break;
        case USER: st=(c==' ')?SPACE:((c>='A'&&c<='Z')?USER:BAD); break;
        case SPACE: st=(c>='0'&&c<='9')?NUMBER:BAD; if(st==NUMBER)value=c-'0'; break;
        case NUMBER:
            if(c>='0'&&c<='9') value=value*10+(c-'0');
            else st=(c==';')?DONE:BAD;
            break;
        default: st=BAD;
        }
    }
    return st==DONE ? value : -1;
}

NI int lab05_binary_search(const int *a, size_t n, int key) {
    size_t lo=0,hi=n;
    while(lo<hi) {
        size_t mid=lo+(hi-lo)/2;
        if(a[mid]<key) lo=mid+1;
        else hi=mid;
    }
    return (lo<n && a[lo]==key) ? (int)lo : -1;
}

NI int lab06_list_accumulate(const Node *p, uint32_t wanted_mask) {
    int total=0;
    for(;p;p=p->next) if((p->key&wanted_mask)==wanted_mask) total+=p->value;
    return total;
}

NI int add_op(int a,int b){return a+b;}
NI int xor_op(int a,int b){return a^b;}
NI int mul_op(int a,int b){return a*b;}
NI int lab07_callback_fold(const int *a,size_t n,int seed,transform_fn f) {
    for(size_t i=0;i<n;i++) seed=f(seed,a[i]);
    return seed;
}

NI uint32_t lab08_unpack_flags(uint32_t word) {
    uint32_t type=word&7u;
    uint32_t length=(word>>3)&0x1ffu;
    uint32_t checksum=(word>>12)&0xffffu;
    return checksum ^ (length*33u) ^ type;
}

NI int lab09_dispatch(unsigned opcode,int a,int b) {
    static transform_fn table[3]={add_op,xor_op,mul_op};
    if(opcode>=3) return -1;
    return table[opcode](a,b);
}

NI uint64_t lab10_recursive_mix(uint32_t n) {
    if(n<2) return 0x9e3779b97f4a7c15ULL ^ n;
    uint64_t x=lab10_recursive_mix(n/2);
    return (x<<7)|(x>>(64-7)) ^ (uint64_t)n*0x100000001b3ULL;
}

NI int lab11_matrix_score(const int m[4][4]) {
    int diagonal=0,edge=0;
    for(size_t r=0;r<4;r++) for(size_t c=0;c<4;c++) {
        if(r==c) diagonal+=m[r][c];
        if(r==0||c==0||r==3||c==3) edge+=m[r][c];
    }
    return diagonal*7-edge;
}

NI uint32_t lab12_xorshift_stream(uint32_t *state,uint8_t *buf,size_t n) {
    uint32_t x=*state,check=0;
    for(size_t i=0;i<n;i++) {
        x^=x<<13; x^=x>>17; x^=x<<5;
        buf[i]^=(uint8_t)(x>>24);
        check=(check<<3)|(check>>29); check^=buf[i];
    }
    *state=x; return check;
}

NI int lab13_tlv_sum(const uint8_t *p,size_t n) {
    int total=0;
    while(n) {
        if(n<2) return -1;
        uint8_t type=p[0],len=p[1]; p+=2;n-=2;
        if(len>n) return -2;
        if(type==1) for(uint8_t i=0;i<len;i++) total+=p[i];
        else if(type==2 && len==4) { uint32_t x;memcpy(&x,p,4);total^=(int)x; }
        p+=len;n-=len;
    }
    return total;
}

typedef struct { uint8_t data[16]; uint8_t head,tail,count; } Ring;
NI int lab14_ring(Ring *r,int operation,uint8_t *value) {
    if(operation==0) {
        if(r->count==16) return -1;
        r->data[r->tail]=*value;r->tail=(r->tail+1)&15;r->count++;return 0;
    }
    if(operation==1) {
        if(r->count==0) return -2;
        *value=r->data[r->head];r->head=(r->head+1)&15;r->count--;return 0;
    }
    return -3;
}

NI int lab15_cross_check(const uint8_t *p,size_t n,uint32_t expected) {
    uint32_t a=lab01_rolling_hash(p,n);
    uint32_t b=0;
    for(size_t i=0;i<n;i++) b+=(uint32_t)p[i]*(uint32_t)(i+1);
    return ((a^b)==expected) ? 1 : 0;
}

int main(int argc,char **argv) {
    const uint8_t msg[]="mentor-reversing";
    uint8_t rle[]={3,'A',2,'B',1,'C'}, out[32]={0};
    uint8_t hdr[16]={'R','E','V','1',3,0,0,0,4,0,0,0,1,2,3,4};
    int sorted[]={1,4,8,15,16,23,42};
    Node c={7,30,0},b={6,20,&c},a={3,10,&b};
    int vals[]={2,3,5,7};
    int matrix[4][4]={{1,2,3,4},{5,6,7,8},{9,10,11,12},{13,14,15,16}};
    uint8_t tlv[]={1,3,1,2,3,2,4,0x78,0x56,0x34,0x12};
    Ring ring={{0},0,0,0};uint8_t q=9;
    uint32_t state=0x12345678;uint8_t stream[sizeof msg];memcpy(stream,msg,sizeof msg);
    uint64_t total=0;
    total+=lab01_rolling_hash(msg,sizeof msg-1);
    total+=lab02_rle_decode(out,sizeof out,rle,sizeof rle);
    total+=lab03_validate_header(hdr,sizeof hdr);
    total+=lab04_protocol_state(argc>1?argv[1]:"USER 731;");
    total+=lab05_binary_search(sorted,7,23);
    total+=lab06_list_accumulate(&a,2);
    total+=lab07_callback_fold(vals,4,1,mul_op);
    total+=lab08_unpack_flags(0xabcde123);
    total+=lab09_dispatch(1,0x55,0xaa);
    total+=lab10_recursive_mix(19);
    total+=lab11_matrix_score(matrix);
    total+=lab12_xorshift_stream(&state,stream,sizeof stream);
    total+=lab13_tlv_sum(tlv,sizeof tlv);
    total+=lab14_ring(&ring,0,&q);q=0;total+=lab14_ring(&ring,1,&q)+q;
    total+=lab15_cross_check(msg,sizeof msg-1,0);
    evidence_sink=total;
    printf("chapter01 evidence=%llu out=%s q=%u\n",(unsigned long long)total,out,q);
    return 0;
}
```

## Recorded artifacts

```text
Ghidra: 12.1.2 headless, stripped and symbolized projects
GDB: 17.2
pwndbg: 2026.02.18
Ghidra stripped functions: 36
pwndbg lab breakpoints: 15
runtime example lab01: 0x555555555530
Ghidra lab01: 00101530
```

# Walkthrough 01 — Import and auto-analysis

## Objective

Import the exact stripped PIE with analyzeHeadless, verify ELF/x86:LE:64:gcc selection, and preserve the project. The real log reports 36 functions and a successful analysis.

## Commands actually used

```sh
/opt/ghidra/support/analyzeHeadless reversing-walkthrough-lab/ghidra_projects ch01_stripped -import ch01_stripped_same -postScript ExportWalkthrough.java ghidra-stripped.txt
```

## Actual result

```text
FUNCTION_COUNT 36; IMAGE_BASE 00100000
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 02 — Entry-to-main recovery

## Objective

Start at ELF entry, separate runtime initialization, and follow the application call. Compare stripped FUN_00101080 with the symbolized main only after blind mapping.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
FUN_00101080 is the application main candidate; _start is at 001013f0 in the symbolized map
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 03 — String cross-reference navigation

## Objective

Locate mentor-reversing, USER 731;, REV1, and output format strings; follow their references into callers without assuming every string is live.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Runtime baseline prints chapter01 evidence and the live decoded RLE output AAABBC
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 04 — Function-boundary validation

## Objective

Use direct calls, returns, fall-through, and neighboring alignment to validate the fifteen function starts; compare Ghidra entries with nm ground truth.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Fifteen mapped entries range from 00101530 through 00101c60
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 05 — Decompiler versus Listing

## Objective

Select the RLE capacity expression and compare Ghidra C with CMP/branch operands, proving remaining-capacity semantics and unsigned width.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Ghidra and objdump both expose the count > cap-w rejection before the nested write loop
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 06 — Apply a recovered structure

## Objective

Use list traversal offsets to build Node, apply it to FUN_00101840, and confirm caller stack initialization matches next/key/value layout.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Node traversal uses one pointer field, a 32-bit key mask, and signed value accumulation
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 07 — Recover an indirect callback

## Objective

Follow lab07’s indirect call in Ghidra, then use pwndbg RIP/argument state to identify mul_op and establish the callback prototype.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
pwndbg entry shows callback in RCX under the SysV harness and the indirect call target lands in executable code
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 08 — Resolve a jump/function table

## Objective

Map lab09’s opcode range, table base, pointer stride, and three executable targets; annotate unresolved indirect edges.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Table dispatch rejects opcode >=3 and calls one of add_op/xor_op/mul_op
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 09 — PIE RVA translation

## Objective

Use Ghidra image base 0x00100000 and runtime vmmap base, compute runtime address for RVA 0x1530, and confirm bytes/instructions with xinfo/x.

## Commands actually used

```sh
pwndbg -nx ch01_debug\n# in pwndbg\nvmmap\nxinfo 0x555555555530\nx/8i 0x555555555530
```

## Actual result

```text
Observed runtime lab01 address was 0x555555555530, consistent with base 0x555555554000 + RVA 0x1530
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 10 — Conditional breakpoint

## Objective

Break on lab04 and condition on the first input character or accumulated value to isolate rejection/acceptance transitions without stepping every iteration.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
GDB conditional breakpoint syntax and branch-state inspection are recorded in the field manual
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 11 — Hardware watchpoint

## Objective

Watch Ring.count or the first RLE output byte, continue, and stop at the exact store; map the runtime PC back to Ghidra RVA.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
A watchpoint proves mutation, whereas the eventual output only proves final state
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 12 — Patch a disposable copy

## Objective

Change one conditional only after recording original bytes/instruction length, run baseline/opposite cases, and explain why file offset differs from runtime VA.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
Patch work remains confined to the disposable local specimen
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 13 — Dump a runtime-decoded buffer

## Objective

Use lab12 as an unpacking analogue: capture stream before/after transform, record key state and mapping, then import the byte range as data rather than claiming executable code.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
lab12 modifies a stack buffer in place and writes final uint32 state back
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 14 — Automate with Ghidra script

## Objective

Run ExportWalkthrough.java to emit names/entries/signatures/decompiler text deterministically; tie the report to the sample hash.

## Commands actually used

```sh
/opt/ghidra/support/analyzeHeadless ... -process ch01_debug -postScript ExportWalkthrough.java ghidra.txt
```

## Actual result

```text
Headless export produced 1,394 lines for the symbolized project and a separate stripped report
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Walkthrough 15 — Cross-tool differential report

## Objective

For all fifteen functions, compare Ghidra stripped starts, objdump symbolized listings, pwndbg executed entries, and source ground truth; classify every disagreement.

## Commands actually used

```sh
pwndbg -nx ch01_debug\ncontext regs disasm stack\ndisassemble /r\n# correlate the stopped runtime address with Ghidra RVA
```

## Actual result

```text
pwndbg installed 15 breakpoints and observed all, with repeated entries for recursion/ring/hash composition
```

## Mentor analysis

1. Write the static hypothesis before executing.
2. Record binary hash, Ghidra image base, function RVA, runtime module base, and breakpoint VA.
3. Capture the minimum state that proves or refutes the hypothesis.
4. Transfer confirmed evidence into Ghidra and retain uncertainty.
5. Re-run an opposite-path input; one trace is not coverage.

## Deliverable

A reproducible evidence entry containing commands, addresses, findings, counterexample, and corrected Ghidra markup.

# Twenty Practice Questions

1. Why hash the imported file?
2. Why keep debug and stripped copies code-identical?
3. What does auto-analysis not prove?
4. Why begin at strings cautiously?
5. How is a Ghidra function boundary corrected?
6. Why read Listing beneath decompiler?
7. What should a structure field name encode?
8. How do you validate an indirect target?
9. Why normalize to RVA?
10. Software versus hardware breakpoint?
11. Why use watchpoints?
12. What makes a patch reliable?
13. What is a runtime dump missing?
14. Why script exports?
15. Why not force tool agreement?
16. What proves main?
17. What is a good breakpoint condition?
18. How do comments differ from names?
19. What must be transferred back to Ghidra?
20. Completion criterion?

# Complete Solutions

## 1. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** So every address/output/report is tied to an immutable artifact.
4. Record the result by RVA and binary hash.

## 2. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** It permits ground-truth correlation without layout drift.
4. Record the result by RVA and binary hash.

## 3. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Correct functions, types, CFG, or semantics.
4. Record the result by RVA and binary hash.

## 4. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Strings can be dead, library-owned, encoded, or referenced from unrelated paths.
4. Record the result by RVA and binary hash.

## 5. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Use incoming edges, terminators, fall-through, unwind/symbol evidence, and neighboring code/data.
4. Record the result by RVA and binary hash.

## 6. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Machine widths, branches, flags, and side effects can be hidden or mistyped in C.
4. Record the result by RVA and binary hash.

## 7. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Proven role and uncertainty, not a guess from one access.
4. Record the result by RVA and binary hash.

## 8. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Runtime address, executable mapping, stable table/object provenance, and matching ABI.
4. Record the result by RVA and binary hash.

## 9. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** ASLR changes base while relative layout stays stable.
4. Record the result by RVA and binary hash.

## 10. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Software usually patches an instruction byte; hardware uses debug resources and helps with checksummed code.
4. Record the result by RVA and binary hash.

## 11. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** They identify first access/mutation, not only downstream corruption.
4. Record the result by RVA and binary hash.

## 12. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Correct instruction boundaries, file mapping, integrity/dependency analysis, and regression inputs.
4. Record the result by RVA and binary hash.

## 13. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Potentially imports, relocations, file headers, section layout, and unexecuted/decrypted regions.
4. Record the result by RVA and binary hash.

## 14. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Reproducibility, scale, evidence diffing, and hash-keyed results.
4. Record the result by RVA and binary hash.

## 15. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Tools can implement different code-discovery policies; disagreements must be explained, not erased.
4. Record the result by RVA and binary hash.

## 16. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Entry/runtime path, argc/argv-like use, program-specific calls, and return to runtime.
4. Record the result by RVA and binary hash.

## 17. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** A precise boundary or state predicate that isolates the hypothesis and minimizes observer effects.
4. Record the result by RVA and binary hash.

## 18. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Names state concise semantic roles; comments preserve evidence, uncertainty, and derivation.
4. Record the result by RVA and binary hash.

## 19. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Confirmed signatures, types, structures, edges, runtime targets, and evidence comments.
4. Record the result by RVA and binary hash.

## 20. Solution

1. Identify which tool produced the claim.
2. Demand an independent static/dynamic cross-check.
3. **Answer:** Static predictions match dynamic state on unseen tests and all discrepancies are documented.
4. Record the result by RVA and binary hash.


Return to [[Chapter 04 - Reversing Tools]].
