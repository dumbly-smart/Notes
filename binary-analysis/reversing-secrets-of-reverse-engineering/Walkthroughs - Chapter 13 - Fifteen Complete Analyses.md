# Chapter 13 — Fifteen Complete Decompiler-Pipeline Walkthroughs

> [!evidence]
> The target is the Chapter 2 x86-64 ELF specimen, compiled as debug and stripped variants, executed, decompiled headlessly by Ghidra, disassembled by `objdump`, and traced in pwndbg. The observed run was `chapter02 evidence=1957969498`. Each walkthrough treats one function as a decompiler engineering test, not merely a source-reading exercise.

## Complete analysis target

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;
typedef struct { int16_t x,y; uint32_t flags; int64_t weight; } Record;
typedef union { uint32_t u; float f; uint8_t b[4]; } Word;
typedef int (*pred_fn)(int);
NI int lab01_signed_relations(int32_t a,int32_t b){return a<b?-1:(a>b?1:0);}
NI int lab02_unsigned_relations(uint32_t a,uint32_t b){return a<b?-1:(a>b?1:0);}
NI int lab03_dense_switch(unsigned x){switch(x){case 4:return 19;case 5:return 23;case 6:return 29;case 7:return 31;case 8:return 37;case 9:return 41;default:return-7;}}
NI int lab04_sparse_switch(unsigned x){switch(x){case 1:return 11;case 17:return 22;case 257:return 33;case 4096:return 44;case 65535:return 55;default:return-1;}}
NI int lab05_loop_strength(const int*a,size_t n){int total=0;for(size_t i=0;i<n;i++)total+=a[i]*10+(int)i;return total;}
NI uint32_t lab06_rotate_mix(uint32_t x,unsigned rounds){do{x=(x<<7)|(x>>25);x^=0x9e3779b9u;x+=rounds*33u;}while(rounds-->1);return x;}
NI uint64_t lab07_recursive_tree(uint32_t n){if(n<2)return n+1;return lab07_recursive_tree(n-1)+3*lab07_recursive_tree(n-2);}
NI uint64_t lab08_tail_accumulate(uint32_t n,uint64_t acc){if(n==0)return acc;return lab08_tail_accumulate(n-1,acc+(uint64_t)n*n);}
NI int64_t lab09_structure_array(const Record*r,size_t n,uint32_t mask){int64_t total=0;for(size_t i=0;i<n;i++)if((r[i].flags&mask)==mask)total+=(int64_t)r[i].x*r[i].y+r[i].weight;return total;}
NI uint32_t lab10_union_alias(uint32_t bits){Word w={.u=bits};uint32_t sign=w.b[3]>>7;w.b[0]^=w.b[2];return w.u^(sign*0xa5a5a5a5u);}
NI uint64_t lab11_add128_low(uint64_t alo,uint64_t ahi,uint64_t blo,uint64_t bhi,uint64_t*hi){uint64_t lo=alo+blo;*hi=ahi+bhi+(lo<alo);return lo;}
NI int lab12_saturating_sum(const int16_t*a,size_t n){int32_t total=0;for(size_t i=0;i<n;i++){total+=a[i];if(total>32767)total=32767;if(total<-32768)total=-32768;}return total;}
NI double lab13_floating_polynomial(double x,double a,double b,double c){return((a*x+b)*x+c)/(x*x+1.0);}
NI int positive(int x){return x>0;} NI int odd(int x){return(x&1)!=0;}
NI int lab14_callback_filter(const int*a,size_t n,pred_fn p){int total=0;for(size_t i=0;i<n;i++)if(p(a[i]))total+=a[i];return total;}
NI int lab15_variadic_checksum(unsigned count,...){va_list ap;va_start(ap,count);uint32_t h=0x13579bdf;for(unsigned i=0;i<count;i++){uint32_t x=va_arg(ap,uint32_t);h=(h<<5)|(h>>27);h^=x+i;}va_end(ap);return(int)h;}
```

## Pipeline used in every walkthrough

```text
ELF loader → bounded x86 decoder → explicit-effect IR → leaders/basic blocks
→ CFG edges → use/def + flags → SSA → propagation/types → structuring
→ C-like output → Ghidra comparison → pwndbg differential validation
```

# Walkthrough 01 — Signed relational recovery

`lab01` is the signedness unit test. Decode `cmp edi,esi`, then classify conditional opcodes from flag predicates: signed less is `SF≠OF`, signed greater is `ZF=0 ∧ SF=OF`. Lift flags explicitly rather than emitting a vague comparison. Build three return blocks and a join, then SSA-merge −1, 0, and 1. Type evidence is the signed conditional jump, not the register name. Run with `(INT_MIN,1)`, `(1,INT_MIN)`, and equality; an unsigned reconstruction fails the first two. Ghidra's anonymous stripped function at `0x1460` and pwndbg's arguments provide independent static/dynamic confirmation.

# Walkthrough 02 — Unsigned relational recovery

The machine registers are again EDI/ESI, but `jb/ja` use carry/zero flag predicates. Give the IR operands `u32` constraints and emit `a<b`/`a>b` only after solving those conditions. The crucial adversarial vector is `(0xffffffff,1)`: unsigned result is 1 while signed interpretation would be −1. This pair of functions proves why type propagation cannot be based solely on width and why a decompiler should retain signedness constraints until evidence converges.

# Walkthrough 03 — Dense-switch jump-table recovery

Start at the range check, identify index normalization (`x-4`), prove the unsigned upper bound, and only then read table entries from mapped read-only data. For every entry, validate the computed target lies in an executable segment and begins at a decoder-consistent boundary. Add case edges 4…9 plus default, including duplicate-target support. Do not follow arbitrary table-looking bytes without the guard. Structure the CFG as a switch and validate 3,4,7,9,10. Expected results are −7,19,31,41,−7.

# Walkthrough 04 — Sparse-switch decision structure

Sparse values encourage comparison trees rather than an indexed table. Recover equality tests and ordered partitions, then use dominators/postdominators to form one semantic switch even though the compiler emitted nested branches. Preserve unsigned constants, especially 65535. Build a case map from path constraints, not source-order guesses. Validate all five cases and near misses 0,2,16,18,256,258,4095,4097,65534,65536.

# Walkthrough 05 — Loop, induction variable, and strength-reduced arithmetic

Recognize the back edge, compute the natural loop from its header dominator, and identify the φ nodes `i=φ(0,i+1)` and `total=φ(0,total+term)`. Effective address `[base+i*4]` suggests four-byte elements; signed multiply/add usage suggests `int32_t`. `a[i]*10` may appear as LEA/shift combinations, so expression recovery must normalize arithmetic without claiming the author's syntax. The `(int)i` cast narrows from `size_t`; preserve it. Empty `n=0` proves the pretest nature.

# Walkthrough 06 — Rotate and do-while semantics

Match `(x<<7)|(x>>25)` only after proving 32-bit width and complementary shifts; alternatively recognize a `rol eax,7`. Model wraparound modulo `2^32`. The loop executes once before testing because the condition is at the tail. Carefully model postfix decrement: compare the old `rounds` with 1, then retain the decremented value. Test rounds 0,1,2,4 to distinguish a do-while from a pretested loop. Emit `rotl32` in IR until back-end rendering.

# Walkthrough 07 — Non-tail recursive call tree

Two self-call sites with arguments `n-1` and `n-2`, plus arithmetic combining both results, prove non-tail recursion. The call-clobber model must preserve the first result across the second call through a saved register/stack slot. Base block returns `n+1` for `n<2`; signedness is unsigned because `n` is `u32`. Rebuild the recurrence `F(n)=F(n-1)+3F(n-2)` and validate values 0 through 10, not just the specimen's 8.

# Walkthrough 08 — Tail recursion versus compiler-created loop

Optimizing compilers may replace the self-call with `n--`, `acc += n*n`, and a back edge. A decompiler cannot truthfully know whether the source used recursion or a loop; it should emit the clearest equivalent loop and annotate provenance if needed. SSA shows accumulator and counter φ nodes. The multiplication must widen before addition. Validate the invariant `acc + Σ(k²,1..n)` and boundary n=0. This walkthrough demonstrates semantic recovery rather than source-text recovery.

# Walkthrough 09 — Structure-array and field recovery

The stride is 16 bytes. Collect accesses across the loop: signed 16-bit loads at offsets 0 and 2, a 32-bit mask field at 4, and a signed 64-bit load at 8. The stride plus offsets implies padding/alignment and yields `Record`. Sign extensions on x/y are decisive. Use the mask condition `(flags&mask)==mask`, not merely nonzero. Apply the structure in Ghidra, check that pseudocode cleans up, then validate arrays where only one, all, or no records match.

# Walkthrough 10 — Union aliasing and endianness

Track the same four bytes through 32-bit and byte accesses. On little-endian x86-64, `b[3]>>7` extracts bit 31, while `b[0]^=b[2]` mutates bits 0…7 with bits 16…23. Express this first as byte-addressed IR; rendering a C union is a type hypothesis. For `0xbf800000`, verify each intermediate byte in pwndbg. Run on a big-endian model mentally to see why portable-looking pseudocode would be false.

# Walkthrough 11 — Multiword addition and carry

The low addition produces a carry detected by `lo<alo` or an x86 carry flag consumed by `adc`. Lift `adc` as `sum = a+b+CF`, with exact width. The function returns low 64 bits and stores high through a pointer. Recover the five-argument SysV ABI mapping: RDI,RSI,RDX,RCX,R8. Test `UINT64_MAX+7`: low wraps to 6 and high receives `ahi+bhi+1`. Mark the pointed store as a side effect so dead-code elimination cannot remove it.

# Walkthrough 12 — Saturation and signed halfwords

`movsx` from 16-bit memory constrains elements to `int16_t`; the accumulator is 32-bit. Identify two clamps after every addition, not only after the whole loop. The order matters: clamp above 32767, then below −32768. Convert conditional moves into min/max only when signed conditions and absence of side effects are proven. Use `[30000,10000,-32000,-3000]`: intermediate saturation is 32767, then 767, then −2233.

# Walkthrough 13 — Floating-point expression tree

Map XMM argument registers under SysV: x,a,b,c arrive in XMM0…XMM3. Construct use-def chains across `mulsd/addsd/divsd`; do not apply integer algebra rules. Recover numerator `((a*x+b)*x+c)` and denominator `x*x+1.0`. IEEE-754 rounding, NaNs, infinities, signed zero, and exception behavior constrain reordering. Compare raw output bits for edge tests, not formatted decimals alone.

# Walkthrough 14 — Indirect callback and dynamic target discovery

The indirect `call reg` cannot be resolved from the callee instruction alone. Propagate the function-pointer argument, mark an unresolved static call edge, and preserve call-clobbered registers. In pwndbg, run twice with `positive` and `odd`, record concrete targets, and union them as observed—not exhaustive—edges. The callback's return gates accumulation. For the array `[-5,2,7,11,19]`, positive and odd produce different coverage and sums.

# Walkthrough 15 — Variadic ABI and register-save area

Variadic functions are an ABI stress test. On SysV x86-64, unnamed integer arguments may begin in remaining general registers and spill to an overflow area. `va_start` initializes offsets/pointers into a register-save area; the loop selects the next uint32 value, rotates hash by five, and XORs `x+i`. Recovering it requires stack/register typing plus the known ABI, not treating every stack offset as a local. Test counts 0,1,4 and enough arguments to cross from register to stack delivery.

## Build-your-own static and dynamic disassembler integration

The runnable implementations and observed output are in [[../practical-binary-analysis/Complete Source - Static and Dynamic Disassemblers]], with extensions in [[../practical-binary-analysis/Build Guide - Static Disassembler]] and [[../practical-binary-analysis/Build Guide - Dynamic Disassembler]]. Use these 15 functions as acceptance tests. Static success means the ELF loader bounds every read, decoder emits typed operands, recursive traversal separates code/data, CFG exports correct edges, and unresolved indirect targets remain explicit. Dynamic success means ptrace records pre-step bytes/RIP, actual successor, module-relative address, thread/signal state, and code-version changes. Diff your static edges against dynamic observed edges; neither set alone is complete truth.

# Practice Questions

1. Which flag formula represents signed less-than?
2. Which vector best distinguishes signed from unsigned comparison?
3. What validates a candidate jump-table entry?
4. How do path constraints recover a sparse switch?
5. Write the two loop-header φ nodes for `lab05`.
6. Why can shift/or be rendered as rotate?
7. What proves `lab07` is not tail recursive?
8. Why may `lab08` legitimately decompile as a loop?
9. Derive the `Record` layout.
10. Explain the endian dependence of `b[3]>>7`.
11. Give the high/low result of `(4:UINT64_MAX)+(8:7)`.
12. Why must saturation occur after each element?
13. Why is algebraic floating-point reassociation unsafe?
14. Is a dynamically observed indirect target set exhaustive?
15. What makes variadic recovery ABI-dependent?
16. Contrast linear sweep and recursive traversal.
17. What must a safe decoder do at a truncated instruction?
18. How should a dynamic tracer handle a real signal?
19. How do you detect self-modifying code dynamically?
20. Define a sound decompilation validation procedure.

# Complete Solutions

## 1. Solution

After subtraction-style comparison, signed less is `SF != OF`; signed greater is `ZF==0 && SF==OF`. Carry belongs to unsigned ordering.

## 2. Solution

Use `0xffffffff` versus 1 at 32-bit width. Signed, the first is −1 and less; unsigned, it is 4294967295 and greater.

## 3. Solution

It must be selected by a proven bounded index, land within an executable mapped range, satisfy relocation/base rules, and decode consistently at a valid instruction boundary. Multiple corroborating xrefs strengthen confidence.

## 4. Solution

Propagate equality and ordered branch predicates down every CFG path, associate each returning leaf with its accumulated constraint, and merge leaves into cases/default. Source order is irrelevant.

## 5. Solution

`i0=φ(0,i_next)` and `total0=φ(0,total_next)`, where `i_next=i0+1` and `total_next=total0+a[i0]*10+(int)i0`.

## 6. Solution

At a fixed 32-bit width, left shift 7 OR logical right shift 25 moves every bit exactly once and the counts sum to 32. Masking/width must be proven before rewriting.

## 7. Solution

The first recursive result must survive while a second recursive call executes, and arithmetic combines both afterward. Therefore neither call's result is returned directly.

## 8. Solution

Tail-call elimination preserves behavior while erasing the recursive call. Exact original syntax is lost; a loop is a valid semantic reconstruction if widths, update order, and termination match.

## 9. Solution

Signed 16-bit fields occur at 0 and 2, uint32 mask at 4, int64 at 8, and successive records are 16 bytes apart. Thus `{int16 x,y; uint32 flags; int64 weight;}` with natural alignment.

## 10. Solution

Little-endian byte 3 contains bits 24–31, so its high bit is integer bit 31. On big-endian storage the same byte index refers to the least-significant byte, changing meaning.

## 11. Solution

Low is `UINT64_MAX+7 mod 2^64 = 6`; carry is 1; high is `4+8+1=13`. The 128-bit result is `(13:6)`.

## 12. Solution

Later negative values operate on the clamped accumulator. Clamping only the final mathematical sum changes history and therefore result; use the provided vector to expose the difference.

## 13. Solution

IEEE-754 operations round after each instruction and special values behave differently under reassociation. `(a*x+b)*x` need not equal `a*x*x+b*x` bit-for-bit.

## 14. Solution

No. It is exhaustive only for the executed inputs/environment. Keep unresolved/static candidate edges and label dynamic targets as observed coverage.

## 15. Solution

The location and layout of unnamed arguments, register-save areas, alignment, and `va_list` representation are platform ABI decisions. Apply the correct architecture/OS convention.

## 16. Solution

Linear sweep decodes sequential bytes and can consume embedded data as code. Recursive traversal follows reachable control-flow seeds and avoids some data, but misses unresolved indirect and hidden entry points. Retain confidence labels for both.

## 17. Solution

Never read beyond the mapped file-backed range. Return a structured failure; according to explicit policy, stop or emit one `.byte` and advance. Fuzz malformed boundaries under ASan/UBSan.

## 18. Solution

Classify stop cause, record it, and reinject signals required by transparent execution. Blindly suppressing SIGSEGV/SIGTRAP alters behavior; distinguish tracer traps from target-generated signals.

## 19. Solution

Cache/hash bytes by executed address and compare on later execution. When bytes differ, create a new code version and invalidate decoded blocks. DBI or page-write monitoring can additionally identify the writer.

## 20. Solution

Compile/run a known specimen, compare decoded instruction boundaries with objdump/Ghidra, compare CFG and types, trace concrete inputs in pwndbg, implement the recovered semantics independently, and differential-test normal, boundary, malformed, signedness, aliasing, and floating-point cases. Preserve uncertainty wherever tests do not prove a unique interpretation.
