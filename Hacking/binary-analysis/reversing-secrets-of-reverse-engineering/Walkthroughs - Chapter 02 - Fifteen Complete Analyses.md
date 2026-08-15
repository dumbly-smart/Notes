# Chapter 2 — Fifteen Complete Low-Level Walkthroughs

> [!evidence]
> Executed with GCC 16.1.1, Ghidra 12.1.2, GNU objdump, GDB 17.2, and pwndbg 2026.02.18. The analyzed artifact is an exact stripped copy of the symbolized executable.

## Build and observed result

```sh
gcc -O2 -fno-inline -fno-omit-frame-pointer -g -o ch02_debug ch02_low_level.c -lm
objcopy --strip-all ch02_debug ch02_stripped
/opt/ghidra/support/analyzeHeadless ... -import ch02_stripped -postScript ExportWalkthrough.java ...
pwndbg -nx -q --batch ch02_debug -ex 'source TraceFunctions.py' -ex run
```

```text
chapter02 evidence=1957969498
pwndbg installed breakpoints for 15 lab functions
checksec: PIE and NX enabled; stack canary present
```

## Complete source

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

NI int lab01_signed_relations(int32_t a,int32_t b){ return a<b?-1:(a>b?1:0); }
NI int lab02_unsigned_relations(uint32_t a,uint32_t b){ return a<b?-1:(a>b?1:0); }

NI int lab03_dense_switch(unsigned x) {
    switch(x){case 4:return 19;case 5:return 23;case 6:return 29;case 7:return 31;
    case 8:return 37;case 9:return 41;default:return -7;}
}

NI int lab04_sparse_switch(unsigned x) {
    switch(x){case 1:return 11;case 17:return 22;case 257:return 33;
    case 4096:return 44;case 65535:return 55;default:return -1;}
}

NI int lab05_loop_strength(const int *a,size_t n) {
    int total=0;
    for(size_t i=0;i<n;i++) total += a[i]*10 + (int)i;
    return total;
}

NI uint32_t lab06_rotate_mix(uint32_t x,unsigned rounds) {
    do { x=(x<<7)|(x>>25);x^=0x9e3779b9u;x+=rounds*33u; } while(rounds-- > 1);
    return x;
}

NI uint64_t lab07_recursive_tree(uint32_t n) {
    if(n<2)return n+1;
    return lab07_recursive_tree(n-1)+3*lab07_recursive_tree(n-2);
}

NI uint64_t lab08_tail_accumulate(uint32_t n,uint64_t acc) {
    if(n==0)return acc;
    return lab08_tail_accumulate(n-1,acc+(uint64_t)n*n);
}

NI int64_t lab09_structure_array(const Record *r,size_t n,uint32_t mask) {
    int64_t total=0;
    for(size_t i=0;i<n;i++) if((r[i].flags&mask)==mask)
        total+=(int64_t)r[i].x*r[i].y+r[i].weight;
    return total;
}

NI uint32_t lab10_union_alias(uint32_t bits) {
    Word w={.u=bits};
    uint32_t sign=w.b[3]>>7;
    w.b[0]^=w.b[2];
    return w.u ^ (sign*0xa5a5a5a5u);
}

NI uint64_t lab11_add128_low(uint64_t alo,uint64_t ahi,uint64_t blo,uint64_t bhi,uint64_t *hi) {
    uint64_t lo=alo+blo;
    *hi=ahi+bhi+(lo<alo);
    return lo;
}

NI int lab12_saturating_sum(const int16_t *a,size_t n) {
    int32_t total=0;
    for(size_t i=0;i<n;i++){total+=a[i];if(total>32767)total=32767;if(total<-32768)total=-32768;}
    return total;
}

NI double lab13_floating_polynomial(double x,double a,double b,double c) {
    return ((a*x+b)*x+c)/(x*x+1.0);
}

NI int positive(int x){return x>0;}
NI int odd(int x){return (x&1)!=0;}
NI int lab14_callback_filter(const int *a,size_t n,pred_fn p) {
    int total=0;
    for(size_t i=0;i<n;i++) if(p(a[i])) total+=a[i];
    return total;
}

NI int lab15_variadic_checksum(unsigned count,...) {
    va_list ap;va_start(ap,count);uint32_t h=0x13579bdf;
    for(unsigned i=0;i<count;i++){uint32_t x=va_arg(ap,uint32_t);h=(h<<5)|(h>>27);h^=x+i;}
    va_end(ap);return (int)h;
}

int main(void){
    int a[]={-5,2,7,11,19};int16_t s[]={30000,10000,-32000,-3000};
    Record r[]={{2,3,3,10},{-4,5,1,20},{7,-2,7,30}};uint64_t hi;
    uint64_t total=0;
    total+=lab01_signed_relations(-1,1);total+=lab02_unsigned_relations(0xffffffffu,1);
    total+=lab03_dense_switch(7);total+=lab04_sparse_switch(257);
    total+=lab05_loop_strength(a,5);total+=lab06_rotate_mix(0x12345678,4);
    total+=lab07_recursive_tree(8);total+=lab08_tail_accumulate(12,0);
    total+=lab09_structure_array(r,3,1);total+=lab10_union_alias(0xbf800000);
    total+=lab11_add128_low(UINT64_MAX,4,7,8,&hi)+hi;
    total+=lab12_saturating_sum(s,4);total+=(uint64_t)lab13_floating_polynomial(2,3,4,5);
    total+=lab14_callback_filter(a,5,positive)+lab14_callback_filter(a,5,odd);
    total+=lab15_variadic_checksum(4,1u,2u,3u,4u);
    evidence_sink=total;printf("chapter02 evidence=%llu\n",(unsigned long long)total);return 0;
}
```

# Walkthrough 01 — Signed three-way comparison

## Static question

Recover `FUN_00101460` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Use SETG/SETL or signed branches to recover -1/0/1 semantics and distinguish negative values from high unsigned values.

```c
FUNCTION FUN_00101460
ENTRY 00101460
SIGNATURE undefined FUN_00101460(void)
CALLERS 001020b4, 001021b8, 0010111d

ulong FUN_00101460(int param_1,int param_2)

{
  ulong uVar1;

  uVar1 = (ulong)(param_2 < param_1);
  if (param_1 < param_2) {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001460 <lab01_signed_relations>:
    1460:	31 c0                	xor    eax,eax
    1462:	39 f7                	cmp    edi,esi
    1464:	ba ff ff ff ff       	mov    edx,0xffffffff
    1469:	0f 9f c0             	setg   al
    146c:	0f 4c c2             	cmovl  eax,edx
    146f:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x7fffe0007
 RBX  0
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555553b0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe2a8 —▸ 0x7fffffffe67d ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0xffffffff
 RSI  1
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x555555555122 (main+162) ◂— movsxd r14, eax
 RIP  0x555555555460 (lab01_signed_relations) ◂— xor eax, eax
   0x555555555462 <lab01_signed_relations+2>     cmp    edi, esi            0xffffffff - 0x1     EFLAGS => 0x282 [ cf pf af zf SF IF df of ac ]
   0x555555555464 <lab01_signed_relations+4>     mov    edx, 0xffffffff     EDX => 0xffffffff
   0x555555555469 <lab01_signed_relations+9>     setg   al
   0x55555555546c <lab01_signed_relations+12>  ✔ cmovl  eax, edx
   0x55555555546f <lab01_signed_relations+15>    ret                                <main+162>
   0x555555555122 <main+162>                     movsxd r14, eax            R14 => 0xffffffffffffffff
   0x555555555125 <main+165>                     call   lab02_unsigned_relations    <lab02_unsigned_relations>
   0x55555555512a <main+170>                     mov    edi, 7              EDI => 7
   0x55555555512f <main+175>                     mov    esi, 5              ESI => 5
   0x555555555134 <main+180>                     movsxd r13, eax
=> 0x555555555460 <lab01_signed_relations>:	xor    eax,eax
   0x555555555462 <lab01_signed_relations+2>:	cmp    edi,esi
   0x555555555464 <lab01_signed_relations+4>:	mov    edx,0xffffffff
   0x555555555469 <lab01_signed_relations+9>:	setg   al
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab01_signed_relations` at RVA `0x1460`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 02 — Unsigned three-way comparison

## Static question

Recover `FUN_00101470` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Contrast JA/JB or SETA/SETB with lab01 on identical bit patterns; infer type from flag interpretation.

```c
FUNCTION FUN_00101470
ENTRY 00101470
SIGNATURE undefined FUN_00101470(void)
CALLERS 001020bc, 001021cc, 00101125

ulong FUN_00101470(uint param_1,uint param_2)

{
  ulong uVar1;

  uVar1 = 0xffffffff;
  if (param_2 <= param_1) {
    uVar1 = (ulong)(param_2 < param_1);
  }
  return uVar1;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001470 <lab02_unsigned_relations>:
    1470:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1475:	39 f7                	cmp    edi,esi
    1477:	72 07                	jb     1480 <lab02_unsigned_relations+0x10>
    1479:	31 c0                	xor    eax,eax
    147b:	39 fe                	cmp    esi,edi
    147d:	0f 92 c0             	setb   al
    1480:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0xffffffff
 RBX  0
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555553b0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xffffffff
 RDI  0xffffffff
 RSI  1
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x55555555512a (main+170) ◂— mov edi, 7
 RIP  0x555555555470 (lab02_unsigned_relations) ◂— mov eax, 0xffffffff
   0x555555555475 <lab02_unsigned_relations+5>     cmp    edi, esi            0xffffffff - 0x1     EFLAGS => 0x282 [ cf pf af zf SF IF df of ac ]
   0x555555555477 <lab02_unsigned_relations+7>   ✘ jb     lab02_unsigned_relations+16 <lab02_unsigned_relations+16>
   0x555555555479 <lab02_unsigned_relations+9>     xor    eax, eax            EAX => 0
   0x55555555547b <lab02_unsigned_relations+11>    cmp    esi, edi            0x1 - 0xffffffff     EFLAGS => 0x213 [ CF pf AF zf sf IF df of ac ]
   0x55555555547d <lab02_unsigned_relations+13>    setb   al
   0x555555555480 <lab02_unsigned_relations+16>    ret                                <main+170>
   0x55555555512a <main+170>                       mov    edi, 7              EDI => 7
   0x55555555512f <main+175>                       mov    esi, 5              ESI => 5
   0x555555555134 <main+180>                       movsxd r13, eax            R13 => 1
   0x555555555137 <main+183>                       call   lab03_dense_switch          <lab03_dense_switch>
=> 0x555555555470 <lab02_unsigned_relations>:	mov    eax,0xffffffff
   0x555555555475 <lab02_unsigned_relations+5>:	cmp    edi,esi
   0x555555555477 <lab02_unsigned_relations+7>:	jb     0x555555555480 <lab02_unsigned_relations+16>
   0x555555555479 <lab02_unsigned_relations+9>:	xor    eax,eax
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab02_unsigned_relations` at RVA `0x1470`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 03 — Dense switch lowering

## Static question

Recover `FUN_00101490` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recover range normalization and a compact lookup/jump table; map all six cases and default.

```c
FUNCTION FUN_00101490
ENTRY 00101490
SIGNATURE undefined FUN_00101490(void)
CALLERS 001020c4, 001021e0, 00101137

undefined4 FUN_00101490(int param_1)

{
  if (param_1 - 4U < 6) {
    return *(undefined4 *)(&DAT_00102020 + (ulong)(param_1 - 4U) * 4);
  }
  return 0xfffffff9;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001490 <lab03_dense_switch>:
    1490:	83 ef 04             	sub    edi,0x4
    1493:	83 ff 05             	cmp    edi,0x5
    1496:	77 10                	ja     14a8 <lab03_dense_switch+0x18>
    1498:	48 8d 05 81 0b 00 00 	lea    rax,[rip+0xb81]        # 2020 <CSWTCH.7>
    149f:	8b 04 b8             	mov    eax,DWORD PTR [rax+rdi*4]
    14a2:	c3                   	ret
    14a3:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    14a8:	b8 f9 ff ff ff       	mov    eax,0xfffffff9
    14ad:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  1
 RBX  0
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555553b0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xffffffff
 RDI  7
 RSI  5
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x55555555513c (main+188) ◂— mov edi, 0x101
 RIP  0x555555555490 (lab03_dense_switch) ◂— sub edi, 4
   0x555555555493 <lab03_dense_switch+3>     cmp    edi, 5     3 - 5     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x555555555496 <lab03_dense_switch+6>   ✘ ja     lab03_dense_switch+24       <lab03_dense_switch+24>
   0x555555555498 <lab03_dense_switch+8>     lea    rax, [rip + 0xb81]               RAX => 0x555555556020 (CSWTCH.7) ◂— 0x1700000013
   0x55555555549f <lab03_dense_switch+15>    mov    eax, dword ptr [rax + rdi*4]     EAX, [CSWTCH.7+12] => 0x1f
   0x5555555554a2 <lab03_dense_switch+18>    ret                                <main+188>
   0x55555555513c <main+188>                 mov    edi, 0x101     EDI => 0x101
   0x555555555141 <main+193>                 movsxd r12, eax       R12 => 0x1f
   0x555555555144 <main+196>                 call   lab04_sparse_switch         <lab04_sparse_switch>
   0x555555555149 <main+201>                 lea    rdi, [rbp - 0x90]
   0x555555555150 <main+208>                 movsxd rbx, eax
=> 0x555555555490 <lab03_dense_switch>:	sub    edi,0x4
   0x555555555493 <lab03_dense_switch+3>:	cmp    edi,0x5
   0x555555555496 <lab03_dense_switch+6>:	ja     0x5555555554a8 <lab03_dense_switch+24>
   0x555555555498 <lab03_dense_switch+8>:	lea    rax,[rip+0xb81]        # 0x555555556020 <CSWTCH.7>
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab03_dense_switch` at RVA `0x1490`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 04 — Sparse switch decision tree

## Static question

Recover `FUN_001014b0` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recover compiler-generated compare tree for widely separated constants; distinguish it from binary search over data.

```c
FUNCTION FUN_001014b0
ENTRY 001014b0
SIGNATURE undefined FUN_001014b0(void)
CALLERS 001020cc, 001021f4, 00101144

undefined8 FUN_001014b0(uint param_1)

{
  undefined8 uVar1;

  if (param_1 == 0x101) {
    uVar1 = 0x21;
  }
  else if (param_1 < 0x102) {
    uVar1 = 0xb;
    if (param_1 != 1) {
      uVar1 = 0xffffffff;
      if (param_1 == 0x11) {
        uVar1 = 0x16;
      }
      return uVar1;
    }
  }
  else {
    uVar1 = 0x2c;
    if (param_1 != 0x1000) {
      uVar1 = 0xffffffff;
      if (param_1 == 0xffff) {
        uVar1 = 0x37;
      }
      return uVar1;
    }
  }
  return uVar1;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014b0 <lab04_sparse_switch>:
    14b0:	81 ff 01 01 00 00    	cmp    edi,0x101
    14b6:	74 48                	je     1500 <lab04_sparse_switch+0x50>
    14b8:	76 26                	jbe    14e0 <lab04_sparse_switch+0x30>
    14ba:	b8 2c 00 00 00       	mov    eax,0x2c
    14bf:	81 ff 00 10 00 00    	cmp    edi,0x1000
    14c5:	74 3e                	je     1505 <lab04_sparse_switch+0x55>
    14c7:	81 ff ff ff 00 00    	cmp    edi,0xffff
    14cd:	ba 37 00 00 00       	mov    edx,0x37
    14d2:	b8 ff ff ff ff       	mov    eax,0xffffffff
    14d7:	0f 44 c2             	cmove  eax,edx
    14da:	c3                   	ret
    14db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    14e0:	b8 0b 00 00 00       	mov    eax,0xb
    14e5:	83 ff 01             	cmp    edi,0x1
    14e8:	74 1b                	je     1505 <lab04_sparse_switch+0x55>
    14ea:	83 ff 11             	cmp    edi,0x11
    14ed:	ba 16 00 00 00       	mov    edx,0x16
    14f2:	b8 ff ff ff ff       	mov    eax,0xffffffff
    14f7:	0f 44 c2             	cmove  eax,edx
    14fa:	c3                   	ret
    14fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1500:	b8 21 00 00 00       	mov    eax,0x21
    1505:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x1f
 RBX  0
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555553b0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xffffffff
 RDI  0x101
 RSI  5
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x555555555149 (main+201) ◂— lea rdi, [rbp - 0x90]
 RIP  0x5555555554b0 (lab04_sparse_switch) ◂— cmp edi, 0x101
   0x5555555554b6 <lab04_sparse_switch+6>   ✔ je     lab04_sparse_switch+80      <lab04_sparse_switch+80>
   0x555555555500 <lab04_sparse_switch+80>    mov    eax, 0x21      EAX => 0x21
   0x555555555505 <lab04_sparse_switch+85>    ret                                <main+201>
   0x555555555149 <main+201>                  lea    rdi, [rbp - 0x90]     RDI => 0x7fffffffe0d0 ◂— 0x2fffffffb
   0x555555555150 <main+208>                  movsxd rbx, eax              RBX => 0x21
   0x555555555153 <main+211>                  call   lab05_loop_strength         <lab05_loop_strength>
   0x555555555158 <main+216>                  mov    esi, 4                ESI => 4
   0x55555555515d <main+221>                  mov    edi, 0x12345678       EDI => 0x12345678
   0x555555555162 <main+226>                  movsxd r11, eax
   0x555555555165 <main+229>                  call   lab06_rotate_mix            <lab06_rotate_mix>
=> 0x5555555554b0 <lab04_sparse_switch>:	cmp    edi,0x101
   0x5555555554b6 <lab04_sparse_switch+6>:	je     0x555555555500 <lab04_sparse_switch+80>
   0x5555555554b8 <lab04_sparse_switch+8>:	jbe    0x5555555554e0 <lab04_sparse_switch+48>
   0x5555555554ba <lab04_sparse_switch+10>:	mov    eax,0x2c
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab04_sparse_switch` at RVA `0x14b0`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 05 — Strength-reduced counted loop

## Static question

Recover `FUN_00101510` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recognize multiply-by-10 lowered to LEA/add, array scale four, induction variable, and index contribution.

```c
FUNCTION FUN_00101510
ENTRY 00101510
SIGNATURE undefined FUN_00101510(void)
CALLERS 001020d4, 00102208, 00101153

int FUN_00101510(long param_1,long param_2)

{
  long lVar1;
  int iVar2;
  long lVar3;
  int iVar4;

  if (param_2 != 0) {
    lVar3 = 0;
    iVar4 = 0;
    do {
      lVar1 = lVar3 * 4;
      iVar2 = (int)lVar3;
      lVar3 = lVar3 + 1;
      iVar4 = iVar4 + iVar2 + *(int *)(param_1 + lVar1) * 10;
    } while (param_2 != lVar3);
    return iVar4;
  }
  return 0;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001510 <lab05_loop_strength>:
    1510:	48 85 f6             	test   rsi,rsi
    1513:	74 2b                	je     1540 <lab05_loop_strength+0x30>
    1515:	31 c0                	xor    eax,eax
    1517:	31 c9                	xor    ecx,ecx
    1519:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1520:	8b 14 87             	mov    edx,DWORD PTR [rdi+rax*4]
    1523:	8d 14 92             	lea    edx,[rdx+rdx*4]
    1526:	8d 14 50             	lea    edx,[rax+rdx*2]
    1529:	48 83 c0 01          	add    rax,0x1
    152d:	01 d1                	add    ecx,edx
    152f:	48 39 c6             	cmp    rsi,rax
    1532:	75 ec                	jne    1520 <lab05_loop_strength+0x10>
    1534:	89 c8                	mov    eax,ecx
    1536:	c3                   	ret
    1537:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    153e:	00 00
    1540:	31 c9                	xor    ecx,ecx
    1542:	89 c8                	mov    eax,ecx
    1544:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x21
 RBX  0x21
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555553b0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xffffffff
 RDI  0x7fffffffe0d0 ◂— 0x2fffffffb
 RSI  5
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x555555555158 (main+216) ◂— mov esi, 4
 RIP  0x555555555510 (lab05_loop_strength) ◂— test rsi, rsi
   0x555555555513 <lab05_loop_strength+3>   ✘ je     lab05_loop_strength+48      <lab05_loop_strength+48>
   0x555555555515 <lab05_loop_strength+5>     xor    eax, eax                         EAX => 0
   0x555555555517 <lab05_loop_strength+7>     xor    ecx, ecx                         ECX => 0
   0x555555555519 <lab05_loop_strength+9>     nop    dword ptr [rax]
   0x555555555520 <lab05_loop_strength+16>    mov    edx, dword ptr [rdi + rax*4]     EDX, [0x7fffffffe0d0] => 0xfffffffb
   0x555555555523 <lab05_loop_strength+19>    lea    edx, [rdx + rdx*4]               EDX => 0x4ffffffe7
   0x555555555526 <lab05_loop_strength+22>    lea    edx, [rax + rdx*2]               EDX => 0x1ffffffce
   0x555555555529 <lab05_loop_strength+25>    add    rax, 1                           RAX => 1 (0 + 1)
   0x55555555552d <lab05_loop_strength+29>    add    ecx, edx                         ECX => 0xffffffce (0x0 + 0xffffffce)
   0x55555555552f <lab05_loop_strength+31>    cmp    rsi, rax                         5 - 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
=> 0x555555555510 <lab05_loop_strength>:	test   rsi,rsi
   0x555555555513 <lab05_loop_strength+3>:	je     0x555555555540 <lab05_loop_strength+48>
   0x555555555515 <lab05_loop_strength+5>:	xor    eax,eax
   0x555555555517 <lab05_loop_strength+7>:	xor    ecx,ecx
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab05_loop_strength` at RVA `0x1510`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 06 — Do-while rotate/mix loop

## Static question

Recover `FUN_00101550` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recover rotate, XOR constant, multiply-by-33, unsigned round counter, and at-least-once execution.

```c
FUNCTION FUN_00101550
ENTRY 00101550
SIGNATURE undefined FUN_00101550(void)
CALLERS 001020dc, 0010221c, 00101165

uint FUN_00101550(uint param_1,uint param_2)

{
  bool bVar1;
  int iVar2;

  iVar2 = param_2 * 0x21;
  do {
    param_1 = ((param_1 << 7 | param_1 >> 0x19) ^ 0x9e3779b9) + iVar2;
    iVar2 = iVar2 + -0x21;
    bVar1 = 1 < param_2;
    param_2 = param_2 - 1;
  } while (bVar1);
  return param_1;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001550 <lab06_rotate_mix>:
    1550:	89 f2                	mov    edx,esi
    1552:	89 f8                	mov    eax,edi
    1554:	c1 e2 05             	shl    edx,0x5
    1557:	01 f2                	add    edx,esi
    1559:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1560:	c1 c0 07             	rol    eax,0x7
    1563:	89 f1                	mov    ecx,esi
    1565:	83 ee 01             	sub    esi,0x1
    1568:	35 b9 79 37 9e       	xor    eax,0x9e3779b9
    156d:	01 d0                	add    eax,edx
    156f:	83 ea 21             	sub    edx,0x21
    1572:	83 f9 01             	cmp    ecx,0x1
    1575:	77 e9                	ja     1560 <lab06_rotate_mix+0x10>
    1577:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x15e
 RBX  0x21
 RCX  0x15e
 RDX  0xc2
 RDI  0x12345678
 RSI  4
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x55555555516a (main+234) ◂— mov edi, 8
 RIP  0x555555555550 (lab06_rotate_mix) ◂— mov edx, esi
   0x555555555552 <lab06_rotate_mix+2>     mov    eax, edi            EAX => 0x12345678
   0x555555555554 <lab06_rotate_mix+4>     shl    edx, 5
   0x555555555557 <lab06_rotate_mix+7>     add    edx, esi            EDX => 0x84 (0x80 + 0x4)
   0x555555555559 <lab06_rotate_mix+9>     nop    dword ptr [rax]
   0x555555555560 <lab06_rotate_mix+16>    rol    eax, 7
   0x555555555563 <lab06_rotate_mix+19>    mov    ecx, esi            ECX => 4
   0x555555555565 <lab06_rotate_mix+21>    sub    esi, 1              ESI => 3 (4 - 1)
   0x555555555568 <lab06_rotate_mix+24>    xor    eax, 0x9e3779b9     EAX => 0x841c45b0 (0x1a2b3c09 ^ 0x9e3779b9)
   0x55555555556d <lab06_rotate_mix+29>    add    eax, edx            EAX => 0x841c4634 (0x841c45b0 + 0x84)
   0x55555555556f <lab06_rotate_mix+31>    sub    edx, 0x21           EDX => 0x63 (0x84 - 0x21)
=> 0x555555555550 <lab06_rotate_mix>:	mov    edx,esi
   0x555555555552 <lab06_rotate_mix+2>:	mov    eax,edi
   0x555555555554 <lab06_rotate_mix+4>:	shl    edx,0x5
   0x555555555557 <lab06_rotate_mix+7>:	add    edx,esi
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab06_rotate_mix` at RVA `0x1550`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 07 — Double-recursive recurrence

## Static question

Recover `FUN_00101580` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Build the recurrence and call tree from two self-calls, base case, saved intermediate, and result combination.

```c
FUNCTION FUN_00101580
ENTRY 00101580
SIGNATURE undefined FUN_00101580(void)
CALLERS 001020e4, 00102230, 00101174, 001015b3

long FUN_00101580(uint param_1)

{
  long lVar1;
  long lVar2;
  int iVar3;
  uint uVar4;
  long lVar5;

  if (param_1 < 2) {
    param_1 = param_1 + 1;
    lVar2 = 1;
    lVar5 = 0;
  }
  else {
    lVar2 = 1;
    lVar5 = 0;
    uVar4 = param_1;
    do {
      iVar3 = uVar4 - 1;
      uVar4 = uVar4 - 2;
      lVar1 = FUN_00101580(iVar3);
      lVar1 = lVar1 * lVar2;
      lVar2 = lVar2 * 3;
      lVar5 = lVar5 + lVar1;
    } while (1 < uVar4);
    param_1 = param_1 + (param_1 >> 1) * -2 + 1;
  }
  return (ulong)param_1 * lVar2 + lVar5;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001580 <lab07_recursive_tree>:
    1580:	55                   	push   rbp
    1581:	48 89 e5             	mov    rbp,rsp
    1584:	48 83 ec 20          	sub    rsp,0x20
    1588:	48 89 5d e0          	mov    QWORD PTR [rbp-0x20],rbx
    158c:	4c 89 75 f8          	mov    QWORD PTR [rbp-0x8],r14
    1590:	83 ff 01             	cmp    edi,0x1
    1593:	76 63                	jbe    15f8 <lab07_recursive_tree+0x78>
    1595:	4c 89 65 e8          	mov    QWORD PTR [rbp-0x18],r12
    1599:	bb 01 00 00 00       	mov    ebx,0x1
    159e:	41 89 fc             	mov    r12d,edi
    15a1:	45 31 f6             	xor    r14d,r14d
    15a4:	4c 89 6d f0          	mov    QWORD PTR [rbp-0x10],r13
    15a8:	41 89 fd             	mov    r13d,edi
    15ab:	41 8d 7d ff          	lea    edi,[r13-0x1]
    15af:	41 83 ed 02          	sub    r13d,0x2
    15b3:	e8 c8 ff ff ff       	call   1580 <lab07_recursive_tree>
    15b8:	48 0f af c3          	imul   rax,rbx
    15bc:	48 8d 1c 5b          	lea    rbx,[rbx+rbx*2]
    15c0:	49 01 c6             	add    r14,rax
    15c3:	41 83 fd 01          	cmp    r13d,0x1
    15c7:	77 e2                	ja     15ab <lab07_recursive_tree+0x2b>
    15c9:	44 89 e0             	mov    eax,r12d
    15cc:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    15d0:	d1 e8                	shr    eax,1
    15d2:	8d 54 00 fe          	lea    edx,[rax+rax*1-0x2]
    15d6:	41 8d 44 24 ff       	lea    eax,[r12-0x1]
    15db:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    15df:	29 d0                	sub    eax,edx
    15e1:	48 0f af c3          	imul   rax,rbx
    15e5:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    15e9:	4c 01 f0             	add    rax,r14
    15ec:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    15f0:	c9                   	leave
    15f1:	c3                   	ret
    15f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    15f8:	8d 47 01             	lea    eax,[rdi+0x1]
    15fb:	bb 01 00 00 00       	mov    ebx,0x1
    1600:	45 31 f6             	xor    r14d,r14d
    1603:	eb dc                	jmp    15e1 <lab07_recursive_tree+0x61>

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x9c9ce094
 RBX  0x21
 RCX  1
 RDX  0
 RDI  8
 RSI  0
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0a8 —▸ 0x555555555179 (main+249) ◂— mov edi, 0xc
 RIP  0x555555555580 (lab07_recursive_tree) ◂— push rbp
   0x555555555581 <lab07_recursive_tree+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0a0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555584 <lab07_recursive_tree+4>     sub    rsp, 0x20                       RSP => 0x7fffffffe080 (0x7fffffffe0a0 - 0x20)
   0x555555555588 <lab07_recursive_tree+8>     mov    qword ptr [rbp - 0x20], rbx     [0x7fffffffe080] <= 0x21
   0x55555555558c <lab07_recursive_tree+12>    mov    qword ptr [rbp - 8], r14        [0x7fffffffe098] <= 0xffffffffffffffff
   0x555555555590 <lab07_recursive_tree+16>    cmp    edi, 1                          8 - 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555593 <lab07_recursive_tree+19>  ✘ jbe    lab07_recursive_tree+120    <lab07_recursive_tree+120>
   0x555555555595 <lab07_recursive_tree+21>    mov    qword ptr [rbp - 0x18], r12     [0x7fffffffe088] <= 0x1f
   0x555555555599 <lab07_recursive_tree+25>    mov    ebx, 1                          EBX => 1
   0x55555555559e <lab07_recursive_tree+30>    mov    r12d, edi                       R12D => 8
   0x5555555555a1 <lab07_recursive_tree+33>    xor    r14d, r14d                      R14D => 0
=> 0x555555555580 <lab07_recursive_tree>:	push   rbp
   0x555555555581 <lab07_recursive_tree+1>:	mov    rbp,rsp
   0x555555555584 <lab07_recursive_tree+4>:	sub    rsp,0x20
   0x555555555588 <lab07_recursive_tree+8>:	mov    QWORD PTR [rbp-0x20],rbx
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab07_recursive_tree` at RVA `0x1580`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 08 — Tail recursion optimized into loop

## Static question

Recover `FUN_00101610` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Show that source recursion disappears at O2; recover accumulator update and countdown from loop-carried state.

```c
FUNCTION FUN_00101610
ENTRY 00101610
SIGNATURE undefined FUN_00101610(void)
CALLERS 001020ec, 00102260, 00101181

long FUN_00101610(uint param_1,long param_2)

{
  ulong uVar1;

  uVar1 = (ulong)param_1;
  if (param_1 != 0) {
    do {
      param_2 = param_2 + uVar1 * uVar1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  return param_2;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001610 <lab08_tail_accumulate>:
    1610:	89 fa                	mov    edx,edi
    1612:	48 89 f0             	mov    rax,rsi
    1615:	85 ff                	test   edi,edi
    1617:	74 17                	je     1630 <lab08_tail_accumulate+0x20>
    1619:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1620:	48 89 d1             	mov    rcx,rdx
    1623:	48 0f af ca          	imul   rcx,rdx
    1627:	48 01 c8             	add    rax,rcx
    162a:	48 83 ea 01          	sub    rdx,0x1
    162e:	75 f0                	jne    1620 <lab08_tail_accumulate+0x10>
    1630:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x2d5
 RBX  0x21
 RCX  1
 RDX  6
 RDI  0xc
 RSI  0
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x2d5
 RSP  0x7fffffffe0a8 —▸ 0x555555555186 (main+262) ◂— mov edx, 1
 RIP  0x555555555610 (lab08_tail_accumulate) ◂— mov edx, edi
   0x555555555612 <lab08_tail_accumulate+2>     mov    rax, rsi     RAX => 0
   0x555555555615 <lab08_tail_accumulate+5>     test   edi, edi     0xc & 0xc     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555617 <lab08_tail_accumulate+7>   ✘ je     lab08_tail_accumulate+32    <lab08_tail_accumulate+32>
   0x555555555619 <lab08_tail_accumulate+9>     nop    dword ptr [rax]
   0x555555555620 <lab08_tail_accumulate+16>    mov    rcx, rdx            RCX => 0xc
   0x555555555623 <lab08_tail_accumulate+19>    imul   rcx, rdx
   0x555555555627 <lab08_tail_accumulate+23>    add    rax, rcx            RAX => 0x90 (0x0 + 0x90)
   0x55555555562a <lab08_tail_accumulate+26>    sub    rdx, 1              RDX => 0xb (0xc - 0x1)
   0x55555555562e <lab08_tail_accumulate+30>  ✔ jne    lab08_tail_accumulate+16    <lab08_tail_accumulate+16>
   0x555555555620 <lab08_tail_accumulate+16>    mov    rcx, rdx            RCX => 0xb
=> 0x555555555610 <lab08_tail_accumulate>:	mov    edx,edi
   0x555555555612 <lab08_tail_accumulate+2>:	mov    rax,rsi
   0x555555555615 <lab08_tail_accumulate+5>:	test   edi,edi
   0x555555555617 <lab08_tail_accumulate+7>:	je     0x555555555630 <lab08_tail_accumulate+32>
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab08_tail_accumulate` at RVA `0x1610`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 09 — Structure-array stride and signed fields

## Static question

Recover `FUN_00101640` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Infer Record stride, signed 16-bit members, flags, 64-bit weight, mask predicate, and 64-bit accumulation.

```c
FUNCTION FUN_00101640
ENTRY 00101640
SIGNATURE undefined FUN_00101640(void)
CALLERS 001020f4, 00102274, 00101197

long FUN_00101640(short *param_1,long param_2,uint param_3)

{
  long lVar1;
  short *psVar2;

  if (param_2 != 0) {
    lVar1 = 0;
    psVar2 = param_1 + param_2 * 8;
    do {
      if (param_3 == (*(uint *)(param_1 + 2) & param_3)) {
        lVar1 = lVar1 + (long)*param_1 * (long)param_1[1] + *(long *)(param_1 + 4);
      }
      param_1 = param_1 + 8;
    } while (psVar2 != param_1);
    return lVar1;
  }
  return 0;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001640 <lab09_structure_array>:
    1640:	48 85 f6             	test   rsi,rsi
    1643:	74 6b                	je     16b0 <lab09_structure_array+0x70>
    1645:	48 c1 e6 04          	shl    rsi,0x4
    1649:	31 c9                	xor    ecx,ecx
    164b:	48 01 fe             	add    rsi,rdi
    164e:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1654:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    165b:	00 00 00 00
    165f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1666:	00 00 00 00
    166a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1671:	00 00 00 00
    1675:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    167c:	00 00 00 00
    1680:	8b 47 04             	mov    eax,DWORD PTR [rdi+0x4]
    1683:	21 d0                	and    eax,edx
    1685:	39 c2                	cmp    edx,eax
    1687:	75 14                	jne    169d <lab09_structure_array+0x5d>
    1689:	48 0f bf 07          	movsx  rax,WORD PTR [rdi]
    168d:	4c 0f bf 47 02       	movsx  r8,WORD PTR [rdi+0x2]
    1692:	49 0f af c0          	imul   rax,r8
    1696:	48 03 47 08          	add    rax,QWORD PTR [rdi+0x8]
    169a:	48 01 c1             	add    rcx,rax
    169d:	48 83 c7 10          	add    rdi,0x10
    16a1:	48 39 fe             	cmp    rsi,rdi
    16a4:	75 da                	jne    1680 <lab09_structure_array+0x40>
    16a6:	48 89 c8             	mov    rax,rcx
    16a9:	c3                   	ret
    16aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    16b0:	31 c9                	xor    ecx,ecx
    16b2:	48 89 c8             	mov    rax,rcx
    16b5:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x28a
 RBX  0x21
 RCX  1
 RDX  1
 RDI  0x7fffffffe0f0 ◂— 0x300030002
 RSI  3
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x55f
 RSP  0x7fffffffe0a8 —▸ 0x55555555519c (main+284) ◂— mov edi, 0xbf800000
 RIP  0x555555555640 (lab09_structure_array) ◂— test rsi, rsi
   0x555555555643 <lab09_structure_array+3>   ✘ je     lab09_structure_array+112   <lab09_structure_array+112>
   0x555555555645 <lab09_structure_array+5>     shl    rsi, 4
   0x555555555649 <lab09_structure_array+9>     xor    ecx, ecx                     ECX => 0
   0x55555555564b <lab09_structure_array+11>    add    rsi, rdi                     RSI => 0x7fffffffe120 (0x30 + 0x7fffffffe0f0)
   0x55555555564e <lab09_structure_array+14>    nop    word ptr [rax + rax]
   0x555555555654 <lab09_structure_array+20>    nop    word ptr [rax + rax]
   0x55555555565f <lab09_structure_array+31>    nop    word ptr [rax + rax]
   0x55555555566a <lab09_structure_array+42>    nop    word ptr [rax + rax]
   0x555555555675 <lab09_structure_array+53>    nop    word ptr [rax + rax]
   0x555555555680 <lab09_structure_array+64>    mov    eax, dword ptr [rdi + 4]     EAX, [0x7fffffffe0f4] => 3
=> 0x555555555640 <lab09_structure_array>:	test   rsi,rsi
   0x555555555643 <lab09_structure_array+3>:	je     0x5555555556b0 <lab09_structure_array+112>
   0x555555555645 <lab09_structure_array+5>:	shl    rsi,0x4
   0x555555555649 <lab09_structure_array+9>:	xor    ecx,ecx
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab09_structure_array` at RVA `0x1640`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 10 — Union/byte aliasing

## Static question

Recover `FUN_001016c0` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Track one 32-bit word through byte extraction/modification and conditional mask, avoiding a fictitious heap object.

```c
FUNCTION FUN_001016c0
ENTRY 001016c0
SIGNATURE undefined FUN_001016c0(void)
CALLERS 001020fc, 00102288, 001011b9

uint FUN_001016c0(int param_1)

{
  return param_1 >> 0x1f & 0xa5a5a5a5U ^
         CONCAT31((int3)((uint)param_1 >> 8),(byte)((uint)param_1 >> 0x10) ^ (byte)param_1);
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016c0 <lab10_union_alias>:
    16c0:	89 f8                	mov    eax,edi
    16c2:	89 fa                	mov    edx,edi
    16c4:	c1 e8 10             	shr    eax,0x10
    16c7:	88 c2                	mov    dl,al
    16c9:	89 f8                	mov    eax,edi
    16cb:	c1 f8 1f             	sar    eax,0x1f
    16ce:	40 30 fa             	xor    dl,dil
    16d1:	25 a5 a5 a5 a5       	and    eax,0xa5a5a5a5
    16d6:	31 d0                	xor    eax,edx
    16d8:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x20
 RBX  0x21
 RCX  8
 RDX  1
 RDI  0xbf800000
 RSI  4
 R8   0x7fffffffe0c0 ◂— 0x400000
 R9   0x55f
 RSP  0x7fffffffe0a8 —▸ 0x5555555551be (main+318) ◂— mov edx, 7
 RIP  0x5555555556c0 (lab10_union_alias) ◂— mov eax, edi
   0x5555555556c2 <lab10_union_alias+2>     mov    edx, edi            EDX => 0xbf800000
   0x5555555556c4 <lab10_union_alias+4>     shr    eax, 0x10
   0x5555555556c7 <lab10_union_alias+7>     mov    dl, al              DL => 0x80
   0x5555555556c9 <lab10_union_alias+9>     mov    eax, edi            EAX => 0xbf800000
   0x5555555556cb <lab10_union_alias+11>    sar    eax, 0x1f
   0x5555555556ce <lab10_union_alias+14>    xor    dl, dil             DL => 0x80 (0x80 ^ 0x0)
   0x5555555556d1 <lab10_union_alias+17>    and    eax, 0xa5a5a5a5     EAX => 0xa5a5a5a5 (0xffffffff & 0xa5a5a5a5)
   0x5555555556d6 <lab10_union_alias+22>    xor    eax, edx            EAX => 0x1a25a525 (0xa5a5a5a5 ^ 0xbf800080)
   0x5555555556d8 <lab10_union_alias+24>    ret                                <main+318>
   0x5555555551be <main+318>                mov    edx, 7              EDX => 7
=> 0x5555555556c0 <lab10_union_alias>:	mov    eax,edi
   0x5555555556c2 <lab10_union_alias+2>:	mov    edx,edi
   0x5555555556c4 <lab10_union_alias+4>:	shr    eax,0x10
   0x5555555556c7 <lab10_union_alias+7>:	mov    dl,al
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab10_union_alias` at RVA `0x16c0`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 11 — Multiword addition and carry

## Static question

Recover `FUN_001016e0` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recognize ADD plus carry materialization as 128-bit low/high arithmetic and recover the output-pointer contract.

```c
FUNCTION FUN_001016e0
ENTRY 001016e0
SIGNATURE undefined FUN_001016e0(void)
CALLERS 00102104, 0010229c, 001011d0

long FUN_001016e0(ulong param_1,long param_2,ulong param_3,long param_4,long *param_5)

{
  *param_5 = param_2 + param_4 + (ulong)CARRY8(param_1,param_3);
  return param_1 + param_3;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016e0 <lab11_add128_low>:
    16e0:	48 89 f8             	mov    rax,rdi
    16e3:	48 01 d0             	add    rax,rdx
    16e6:	48 11 ce             	adc    rsi,rcx
    16e9:	49 89 30             	mov    QWORD PTR [r8],rsi
    16ec:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x1a25a525
 RBX  0x21
 RCX  8
 RDX  7
 RDI  0xffffffffffffffff
 RSI  4
 R8   0x7fffffffe0c0 ◂— 0x400000
 R9   0x55f
 RSP  0x7fffffffe0a8 —▸ 0x5555555551d5 (main+341) ◂— add r9, qword ptr [rbp - 0xa0]
 RIP  0x5555555556e0 (lab11_add128_low) ◂— mov rax, rdi
   0x5555555556e3 <lab11_add128_low+3>     add    rax, rdx                RAX => 6 (0xffffffffffffffff + 0x7)
   0x5555555556e6 <lab11_add128_low+6>     adc    rsi, rcx
   0x5555555556e9 <lab11_add128_low+9>     mov    qword ptr [r8], rsi     [0x7fffffffe0c0] <= 0xd
   0x5555555556ec <lab11_add128_low+12>    ret                                <main+341>
   0x5555555551d5 <main+341>               add    r9, qword ptr [rbp - 0xa0]      R9 => 0x56c (0x55f + 0xd)
   0x5555555551dc <main+348>               mov    esi, 4                          ESI => 4
   0x5555555551e1 <main+353>               lea    rdi, [rbp - 0x98]               RDI => 0x7fffffffe0c8 ◂— 0xf448830027107530
   0x5555555551e8 <main+360>               lea    r8, [r9 + rax]                  R8 => 0x572
   0x5555555551ec <main+364>               mov    eax, dword ptr [rbp - 0xac]     EAX, [0x7fffffffe0b4] => 0x1a25a525
   0x5555555551f2 <main+370>               add    r8, r14                         R8 => 0x571 (0x572 + 0xffffffffffffffff)
=> 0x5555555556e0 <lab11_add128_low>:	mov    rax,rdi
   0x5555555556e3 <lab11_add128_low+3>:	add    rax,rdx
   0x5555555556e6 <lab11_add128_low+6>:	adc    rsi,rcx
   0x5555555556e9 <lab11_add128_low+9>:	mov    QWORD PTR [r8],rsi
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab11_add128_low` at RVA `0x16e0`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 12 — Saturating arithmetic

## Static question

Recover `FUN_001016f0` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Separate ordinary accumulation from clamp-to-int16 boundaries; identify sign extension from 16-bit input.

```c
FUNCTION FUN_001016f0
ENTRY 001016f0
SIGNATURE undefined FUN_001016f0(void)
CALLERS 0010210c, 001022b0, 0010120e

int FUN_001016f0(short *param_1,long param_2)

{
  short *psVar1;
  int iVar2;

  if (param_2 != 0) {
    psVar1 = param_1 + param_2;
    iVar2 = 0;
    do {
      iVar2 = iVar2 + *param_1;
      if (iVar2 < -0x8000) {
        iVar2 = -0x8000;
      }
      if (0x7fff < iVar2) {
        iVar2 = 0x7fff;
      }
      param_1 = param_1 + 1;
    } while (psVar1 != param_1);
    return iVar2;
  }
  return 0;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016f0 <lab12_saturating_sum>:
    16f0:	48 85 f6             	test   rsi,rsi
    16f3:	74 33                	je     1728 <lab12_saturating_sum+0x38>
    16f5:	48 8d 0c 77          	lea    rcx,[rdi+rsi*2]
    16f9:	31 c0                	xor    eax,eax
    16fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1700:	0f bf 17             	movsx  edx,WORD PTR [rdi]
    1703:	01 d0                	add    eax,edx
    1705:	ba 00 80 ff ff       	mov    edx,0xffff8000
    170a:	39 d0                	cmp    eax,edx
    170c:	0f 4c c2             	cmovl  eax,edx
    170f:	ba ff 7f 00 00       	mov    edx,0x7fff
    1714:	39 d0                	cmp    eax,edx
    1716:	0f 4f c2             	cmovg  eax,edx
    1719:	48 83 c7 02          	add    rdi,0x2
    171d:	48 39 f9             	cmp    rcx,rdi
    1720:	75 de                	jne    1700 <lab12_saturating_sum+0x10>
    1722:	c3                   	ret
    1723:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1728:	31 c0                	xor    eax,eax
    172a:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0x1a25a525
 RBX  0x21
 RCX  8
 RDX  7
 RDI  0x7fffffffe0c8 ◂— 0xf448830027107530
 RSI  4
 R8   0xb6c28ce9
 R9   0x56c
 RSP  0x7fffffffe0a8 —▸ 0x555555555213 (main+403) ◂— movsd xmm1, qword ptr [rip + 0xe3d]
 RIP  0x5555555556f0 (lab12_saturating_sum) ◂— test rsi, rsi
   0x5555555556f3 <lab12_saturating_sum+3>   ✘ je     lab12_saturating_sum+56     <lab12_saturating_sum+56>
   0x5555555556f5 <lab12_saturating_sum+5>     lea    rcx, [rdi + rsi*2]        RCX => 0x7fffffffe0d0 ◂— 0x2fffffffb
   0x5555555556f9 <lab12_saturating_sum+9>     xor    eax, eax                  EAX => 0
   0x5555555556fb <lab12_saturating_sum+11>    nop    dword ptr [rax + rax]
   0x555555555700 <lab12_saturating_sum+16>    movsx  edx, word ptr [rdi]       EDX, [0x7fffffffe0c8] => 0x7530
   0x555555555703 <lab12_saturating_sum+19>    add    eax, edx                  EAX => 0x7530 (0x0 + 0x7530)
   0x555555555705 <lab12_saturating_sum+21>    mov    edx, 0xffff8000           EDX => 0xffff8000
   0x55555555570a <lab12_saturating_sum+26>    cmp    eax, edx                  0x7530 - 0xffff8000     EFLAGS => 0x207 [ CF PF af zf sf IF df of ac ]
   0x55555555570c <lab12_saturating_sum+28>  ✘ cmovl  eax, edx
   0x55555555570f <lab12_saturating_sum+31>    mov    edx, 0x7fff               EDX => 0x7fff
=> 0x5555555556f0 <lab12_saturating_sum>:	test   rsi,rsi
   0x5555555556f3 <lab12_saturating_sum+3>:	je     0x555555555728 <lab12_saturating_sum+56>
   0x5555555556f5 <lab12_saturating_sum+5>:	lea    rcx,[rdi+rsi*2]
   0x5555555556f9 <lab12_saturating_sum+9>:	xor    eax,eax
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab12_saturating_sum` at RVA `0x16f0`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 13 — Floating-point expression recovery

## Static question

Recover `FUN_00101730` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recover Horner-style numerator, denominator, division, and ABI use of XMM registers while preserving evaluation order.

```c
FUNCTION FUN_00101730
ENTRY 00101730
SIGNATURE undefined FUN_00101730(void)
CALLERS 00102114, 001022c4, 00101238

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

double FUN_00101730(double param_1,double param_2,double param_3,double param_4)

{
  return ((param_2 * param_1 + param_3) * param_1 + param_4) / (param_1 * param_1 + _DAT_00102040);
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001730 <lab13_floating_polynomial>:
    1730:	f2 0f 59 c8          	mulsd  xmm1,xmm0
    1734:	f2 0f 58 ca          	addsd  xmm1,xmm2
    1738:	f2 0f 59 c8          	mulsd  xmm1,xmm0
    173c:	f2 0f 59 c0          	mulsd  xmm0,xmm0
    1740:	f2 0f 58 05 f8 08 00 	addsd  xmm0,QWORD PTR [rip+0x8f8]        # 2040 <CSWTCH.7+0x20>
    1747:	00
    1748:	f2 0f 58 cb          	addsd  xmm1,xmm3
    174c:	f2 0f 5e c8          	divsd  xmm1,xmm0
    1750:	66 0f 28 c1          	movapd xmm0,xmm1
    1754:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0xb6c28430
 RBX  0x21
 RCX  0x7fffffffe0d0 ◂— 0x2fffffffb
 RDX  0x7fff
 RDI  0x7fffffffe0d0 ◂— 0x2fffffffb
 RSI  4
 R8   0xb6c28ce9
 R9   0x56c
 RSP  0x7fffffffe0a8 —▸ 0x55555555523d (main+445) ◂— movsd xmm1, qword ptr [rip + 0xe23]
 RIP  0x555555555730 (lab13_floating_polynomial) ◂— mulsd xmm1, xmm0
   0x555555555734 <lab13_floating_polynomial+4>     addsd  xmm1, xmm2
   0x555555555738 <lab13_floating_polynomial+8>     mulsd  xmm1, xmm0
   0x55555555573c <lab13_floating_polynomial+12>    mulsd  xmm0, xmm0
   0x555555555740 <lab13_floating_polynomial+16>    addsd  xmm0, qword ptr [rip + 0x8f8]
   0x555555555748 <lab13_floating_polynomial+24>    addsd  xmm1, xmm3
   0x55555555574c <lab13_floating_polynomial+28>    divsd  xmm1, xmm0
   0x555555555750 <lab13_floating_polynomial+32>    movapd xmm0, xmm1
   0x555555555754 <lab13_floating_polynomial+36>    ret                                <main+445>
   0x55555555523d <main+445>                        movsd  xmm1, qword ptr [rip + 0xe23]
   0x555555555245 <main+453>                        comisd xmm0, xmm1
=> 0x555555555730 <lab13_floating_polynomial>:	mulsd  xmm1,xmm0
   0x555555555734 <lab13_floating_polynomial+4>:	addsd  xmm1,xmm2
   0x555555555738 <lab13_floating_polynomial+8>:	mulsd  xmm1,xmm0
   0x55555555573c <lab13_floating_polynomial+12>:	mulsd  xmm0,xmm0
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab13_floating_polynomial` at RVA `0x1730`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 14 — Predicate callback and conditional fold

## Static question

Recover `FUN_00101760` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Infer predicate signature from indirect calls, Boolean test, conditional accumulation, and repeated targets.

```c
FUNCTION FUN_00101760
ENTRY 00101760
SIGNATURE undefined FUN_00101760(void)
CALLERS 0010211c, 001022d8, 0010126a, 00101284

int FUN_00101760(long param_1,long param_2,code *param_3)

{
  int iVar1;
  long lVar2;
  int iVar3;

  if (param_2 != 0) {
    iVar3 = 0;
    lVar2 = 0;
    do {
      iVar1 = (*param_3)(*(undefined4 *)(param_1 + lVar2 * 4));
      if (iVar1 != 0) {
        iVar3 = iVar3 + *(int *)(param_1 + lVar2 * 4);
      }
      lVar2 = lVar2 + 1;
    } while (param_2 != lVar2);
    return iVar3;
  }
  return 0;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001760 <lab14_callback_filter>:
    1760:	55                   	push   rbp
    1761:	48 89 e5             	mov    rbp,rsp
    1764:	48 83 ec 30          	sub    rsp,0x30
    1768:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    176c:	48 85 f6             	test   rsi,rsi
    176f:	74 57                	je     17c8 <lab14_callback_filter+0x68>
    1771:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1775:	45 31 f6             	xor    r14d,r14d
    1778:	31 db                	xor    ebx,ebx
    177a:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    177e:	49 89 f4             	mov    r12,rsi
    1781:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1785:	49 89 d5             	mov    r13,rdx
    1788:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    178c:	49 89 ff             	mov    r15,rdi
    178f:	90                   	nop
    1790:	41 8b 3c 9f          	mov    edi,DWORD PTR [r15+rbx*4]
    1794:	41 ff d5             	call   r13
    1797:	85 c0                	test   eax,eax
    1799:	74 04                	je     179f <lab14_callback_filter+0x3f>
    179b:	45 03 34 9f          	add    r14d,DWORD PTR [r15+rbx*4]
    179f:	48 83 c3 01          	add    rbx,0x1
    17a3:	49 39 dc             	cmp    r12,rbx
    17a6:	75 e8                	jne    1790 <lab14_callback_filter+0x30>
    17a8:	44 89 f0             	mov    eax,r14d
    17ab:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    17af:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    17b3:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    17b7:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    17bb:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    17bf:	c9                   	leave
    17c0:	c3                   	ret
    17c1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    17c8:	45 31 f6             	xor    r14d,r14d
    17cb:	44 89 f0             	mov    eax,r14d
    17ce:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    17d2:	c9                   	leave
    17d3:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0xb6c28430
 RBX  0x21
 RCX  0x7fffffffe0d0 ◂— 0x2fffffffb
 RDX  0x555555555440 (positive) ◂— xor eax, eax
 RDI  0x7fffffffe0d0 ◂— 0x2fffffffb
 RSI  5
 R8   0xb6c28ce9
 R9   0x56c
 RSP  0x7fffffffe0a8 —▸ 0x55555555526f (main+495) ◂— lea rdx, [rip + 0x1da]
 RIP  0x555555555760 (lab14_callback_filter) ◂— push rbp
   0x555555555761 <lab14_callback_filter+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0a0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555764 <lab14_callback_filter+4>     sub    rsp, 0x30                       RSP => 0x7fffffffe070 (0x7fffffffe0a0 - 0x30)
   0x555555555768 <lab14_callback_filter+8>     mov    qword ptr [rbp - 0x10], r14     [0x7fffffffe090] <= 0xffffffffffffffff
   0x55555555576c <lab14_callback_filter+12>    test   rsi, rsi                        5 & 5     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x55555555576f <lab14_callback_filter+15>  ✘ je     lab14_callback_filter+104   <lab14_callback_filter+104>
   0x555555555771 <lab14_callback_filter+17>    mov    qword ptr [rbp - 0x28], rbx     [0x7fffffffe078] <= 0x21
   0x555555555775 <lab14_callback_filter+21>    xor    r14d, r14d                      R14D => 0
   0x555555555778 <lab14_callback_filter+24>    xor    ebx, ebx                        EBX => 0
   0x55555555577a <lab14_callback_filter+26>    mov    qword ptr [rbp - 0x20], r12     [0x7fffffffe080] <= 0xb6c28435
   0x55555555577e <lab14_callback_filter+30>    mov    r12, rsi                        R12 => 5
=> 0x555555555760 <lab14_callback_filter>:	push   rbp
   0x555555555761 <lab14_callback_filter+1>:	mov    rbp,rsp
   0x555555555764 <lab14_callback_filter+4>:	sub    rsp,0x30
   0x555555555768 <lab14_callback_filter+8>:	mov    QWORD PTR [rbp-0x10],r14
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab14_callback_filter` at RVA `0x1760`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Walkthrough 15 — Variadic ABI and checksum

## Static question

Recover `FUN_001017e0` from stripped optimized code. Determine prototype, signedness, control structure, exact arithmetic, and edge behavior.

## Ghidra result and interpretation

Recover count-controlled varargs traversal, register-save/overflow areas, rotate recurrence, and per-argument index mixing.

```c
FUNCTION FUN_001017e0
ENTRY 001017e0
SIGNATURE undefined FUN_001017e0(void)
CALLERS 00102124, 00102314, 001012a8

uint FUN_001017e0(int param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  uint uVar1;
  ulong uVar2;
  int iVar3;
  uint uVar4;
  long in_FS_OFFSET;
  int local_38 [2];
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;

  local_30 = param_2;
  local_28 = param_3;
  local_20 = param_4;
  local_18 = param_5;
  local_10 = param_6;
  if (param_1 == 0) {
    uVar1 = 0x13579bdf;
  }
  else {
    iVar3 = 0;
    uVar1 = 0x13579bdf;
    uVar2 = 8;
    do {
      if (0x2f < (uint)uVar2) goto LAB_00101860;
      uVar4 = *(int *)((long)local_38 + uVar2) + iVar3;
      iVar3 = iVar3 + 1;
      uVar1 = (uVar1 << 5 | uVar1 >> 0x1b) ^ uVar4;
      uVar2 = (ulong)((uint)uVar2 + 8);
    } while (param_1 != iVar3);
  }
LAB_0010187a:
  if (*(long *)(in_FS_OFFSET + 0x28) == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
LAB_00101860:
  do {
    register0x00000020 = (BADSPACEBASE *)((long)register0x00000020 + 8);
    uVar4 = *(int *)register0x00000020 + iVar3;
    iVar3 = iVar3 + 1;
    uVar1 = (uVar1 << 5 | uVar1 >> 0x1b) ^ uVar4;
  } while (param_1 != iVar3);
  goto LAB_0010187a;
}
```

## Full machine-code listing

```asm
reversing-walkthrough-lab/build/ch02/ch02_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017e0 <lab15_variadic_checksum>:
    17e0:	55                   	push   rbp
    17e1:	48 89 e5             	mov    rbp,rsp
    17e4:	48 83 ec 50          	sub    rsp,0x50
    17e8:	48 89 75 d8          	mov    QWORD PTR [rbp-0x28],rsi
    17ec:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
    17f0:	48 89 4d e8          	mov    QWORD PTR [rbp-0x18],rcx
    17f4:	4c 89 45 f0          	mov    QWORD PTR [rbp-0x10],r8
    17f8:	4c 89 4d f8          	mov    QWORD PTR [rbp-0x8],r9
    17fc:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1803:	00 00
    1805:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    1809:	31 c0                	xor    eax,eax
    180b:	48 8d 45 10          	lea    rax,[rbp+0x10]
    180f:	c7 45 b0 08 00 00 00 	mov    DWORD PTR [rbp-0x50],0x8
    1816:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
    181a:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    181e:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    1822:	85 ff                	test   edi,edi
    1824:	74 6a                	je     1890 <lab15_variadic_checksum+0xb0>
    1826:	49 89 c1             	mov    r9,rax
    1829:	b9 08 00 00 00       	mov    ecx,0x8
    182e:	48 8d 75 10          	lea    rsi,[rbp+0x10]
    1832:	31 d2                	xor    edx,edx
    1834:	b8 df 9b 57 13       	mov    eax,0x13579bdf
    1839:	eb 1f                	jmp    185a <lab15_variadic_checksum+0x7a>
    183b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1840:	41 89 c8             	mov    r8d,ecx
    1843:	c1 c0 05             	rol    eax,0x5
    1846:	83 c1 08             	add    ecx,0x8
    1849:	47 8b 14 01          	mov    r10d,DWORD PTR [r9+r8*1]
    184d:	41 01 d2             	add    r10d,edx
    1850:	83 c2 01             	add    edx,0x1
    1853:	44 31 d0             	xor    eax,r10d
    1856:	39 d7                	cmp    edi,edx
    1858:	74 20                	je     187a <lab15_variadic_checksum+0x9a>
    185a:	83 f9 2f             	cmp    ecx,0x2f
    185d:	76 e1                	jbe    1840 <lab15_variadic_checksum+0x60>
    185f:	90                   	nop
    1860:	48 89 f1             	mov    rcx,rsi
    1863:	c1 c0 05             	rol    eax,0x5
    1866:	48 83 c6 08          	add    rsi,0x8
    186a:	44 8b 19             	mov    r11d,DWORD PTR [rcx]
    186d:	41 01 d3             	add    r11d,edx
    1870:	83 c2 01             	add    edx,0x1
    1873:	44 31 d8             	xor    eax,r11d
    1876:	39 d7                	cmp    edi,edx
    1878:	75 e6                	jne    1860 <lab15_variadic_checksum+0x80>
    187a:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    187e:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    1885:	00 00
    1887:	75 0e                	jne    1897 <lab15_variadic_checksum+0xb7>
    1889:	c9                   	leave
    188a:	c3                   	ret
    188b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1890:	b8 df 9b 57 13       	mov    eax,0x13579bdf
    1895:	eb e3                	jmp    187a <lab15_variadic_checksum+0x9a>
    1897:	e8 94 f7 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## Actual pwndbg entry state

```text
RAX  0
 RBX  0x27
 RCX  3
 RDX  2
 RDI  4
 RSI  1
 R8   4
 R9   0x56c
 RSP  0x7fffffffe0a8 —▸ 0x5555555552ad (main+557) ◂— lea esi, [rbx + r13]
 RIP  0x5555555557e0 (lab15_variadic_checksum) ◂— push rbp
   0x5555555557e1 <lab15_variadic_checksum+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0a0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555557e4 <lab15_variadic_checksum+4>     sub    rsp, 0x50                       RSP => 0x7fffffffe050 (0x7fffffffe0a0 - 0x50)
   0x5555555557e8 <lab15_variadic_checksum+8>     mov    qword ptr [rbp - 0x28], rsi     [0x7fffffffe078] <= 1
   0x5555555557ec <lab15_variadic_checksum+12>    mov    qword ptr [rbp - 0x20], rdx     [0x7fffffffe080] <= 2
   0x5555555557f0 <lab15_variadic_checksum+16>    mov    qword ptr [rbp - 0x18], rcx     [0x7fffffffe088] <= 3
   0x5555555557f4 <lab15_variadic_checksum+20>    mov    qword ptr [rbp - 0x10], r8      [0x7fffffffe090] <= 4
   0x5555555557f8 <lab15_variadic_checksum+24>    mov    qword ptr [rbp - 8], r9         [0x7fffffffe098] <= 0x56c
   0x5555555557fc <lab15_variadic_checksum+28>    mov    rax, qword ptr fs:[0x28]        RAX, [0x7ffff7e4c768] => 0x16a09d37a4c2f500
   0x555555555805 <lab15_variadic_checksum+37>    mov    qword ptr [rbp - 0x38], rax     [0x7fffffffe068] <= 0x16a09d37a4c2f500
   0x555555555809 <lab15_variadic_checksum+41>    xor    eax, eax                        EAX => 0
=> 0x5555555557e0 <lab15_variadic_checksum>:	push   rbp
   0x5555555557e1 <lab15_variadic_checksum+1>:	mov    rbp,rsp
   0x5555555557e4 <lab15_variadic_checksum+4>:	sub    rsp,0x50
   0x5555555557e8 <lab15_variadic_checksum+8>:	mov    QWORD PTR [rbp-0x28],rsi
```

## Step-by-step recovery

1. Mark all incoming ABI locations and the first definition/use of each.
2. Split basic blocks at branch targets and fall-throughs; label signed/unsigned predicates from flags.
3. Convert address expressions into element/field offsets and record widths/extensions.
4. Collapse compiler idioms only after proving bit-width equivalence.
5. Compare the recovered model with the shown runtime values and the complete source only after finishing the blind reconstruction.

## Verified conclusion

The evidence supports `lab15_variadic_checksum` at RVA `0x17e0`. Recompile at different optimization levels and explain which source structures vanish, merge, or change instruction shape without changing the contract.

# Twenty Practice Questions

1. Which branches encode signed less/greater?
2. How do you distinguish dense and sparse switch lowering?
3. Why can source multiplication disappear?
4. What proves do-while semantics?
5. Why does tail recursion vanish?
6. How is structure stride recovered?
7. What proves a 16-bit field is signed?
8. How is carry detected in multiword addition?
9. Why does variadic code save registers?
10. How do XMM arguments change prototype recovery?
11. What makes lab04 a switch rather than arbitrary ifs?
12. How do you validate signedness dynamically?
13. Why preserve 32-bit wrap in rotate mix?
14. What does a callback return test reveal?
15. How can recursion depth be measured?
16. What is a saturation boundary test?
17. Why might decompiler show strange vararg locals?
18. What is operator strength reduction?
19. How do debug symbols affect the experiment?
20. What is mastery evidence?

# Complete Solutions

## 1. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** JL/JG or SETL/SETG interpret SF and OF; unsigned uses JB/JA or SETB/SETA.
4. Construct a boundary input that would falsify the answer.

## 2. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Dense cases justify indexed tables after range normalization; sparse constants usually form compare trees or search tables.
4. Construct a boundary input that would falsify the answer.

## 3. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** LEA, shifts, and adds implement constant multiplication more cheaply while preserving modular semantics.
4. Construct a boundary input that would falsify the answer.

## 4. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** The body dominates the first condition test, so it executes at least once.
4. Construct a boundary input that would falsify the answer.

## 5. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** The recursive call is in tail position and becomes a loop carrying updated arguments.
4. Construct a boundary input that would falsify the answer.

## 6. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Pointer increment between elements plus repeated member offsets and caller allocation establish the stride.
4. Construct a boundary input that would falsify the answer.

## 7. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** MOVSX/sign extension and signed downstream arithmetic, contrasted with MOVZX.
4. Construct a boundary input that would falsify the answer.

## 8. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Carry flag or comparison of low result with an operand feeds ADC/high-word increment.
4. Construct a boundary input that would falsify the answer.

## 9. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** The ABI makes unnamed arguments arrive in both registers and stack overflow area; va_list tracks both.
4. Construct a boundary input that would falsify the answer.

## 10. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Floating-point parameters use vector registers under the ABI, so integer-register-only reasoning misses them.
4. Construct a boundary input that would falsify the answer.

## 11. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** All comparisons dispatch on the same input to constant-result cases and a shared default.
4. Construct a boundary input that would falsify the answer.

## 12. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Use bit pattern 0xffffffff against 1 and compare signed -1 behavior with unsigned 4294967295.
4. Construct a boundary input that would falsify the answer.

## 13. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** C uint32_t operations and EAX writes truncate; unlimited-integer algebra changes later rotates/XOR.
4. Construct a boundary input that would falsify the answer.

## 14. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Nonzero/zero condition implies predicate-like Boolean semantics even if exact source type is int.
4. Construct a boundary input that would falsify the answer.

## 15. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Repeated entry breakpoints with argument values plus backtraces reveal the active call tree.
4. Construct a boundary input that would falsify the answer.

## 16. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Inputs whose running sum reaches 32767/-32768 exactly, then exceeds by one, and later moves inward.
4. Construct a boundary input that would falsify the answer.

## 17. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** va_list’s ABI-specific register-save offsets and overflow pointer are reconstructed imperfectly.
4. Construct a boundary input that would falsify the answer.

## 18. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** Compiler substitutes equivalent cheaper operations, such as x*10 → 5x then double.
4. Construct a boundary input that would falsify the answer.

## 19. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** They are used only to correlate ground truth; Ghidra analyzes the stripped identical code where names/types are absent.
4. Construct a boundary input that would falsify the answer.

## 20. Solution

1. Locate the exact instruction/ABI evidence.
2. Preserve operand width and flags.
3. **Answer:** A hand-derived prototype/CFG/expression predicts unseen boundary inputs and matches runtime state.
4. Construct a boundary input that would falsify the answer.


Return to [[Chapter 02 - Low-Level Software]].
