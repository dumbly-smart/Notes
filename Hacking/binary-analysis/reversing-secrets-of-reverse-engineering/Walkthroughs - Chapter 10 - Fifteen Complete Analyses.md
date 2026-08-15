# Chapter 10 — Fifteen Complete Antireversing Walkthroughs

> [!scope]
> These self-authored mechanisms teach recognition and normalization. They do not target third-party protection.

## Baseline

```text
chapter10 evidence=1967238714
```

## Complete source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;
NI int lab01_debug_flag(uint32_t process_flags){return(process_flags&0x70u)!=0;}
NI uint64_t lab02_timing_delta(uint64_t before,uint64_t after,uint64_t threshold){uint64_t d=after-before;return d>threshold?d:0;}
NI uint32_t lab03_code_checksum(const uint8_t*p,size_t n){uint32_t x=0;for(size_t i=0;i<n;i++){x=(x<<3)|(x>>29);x^=p[i]+(uint32_t)i;}return x;}
NI int lab04_opaque_even(uint32_t x){return ((x*(x+1u))&1u)==0?42:-42;}
NI int lab05_opaque_square(uint32_t x){uint32_t y=x*x;return (y%4u==2u)?-1:(int)(y&255u);}
NI int lab06_table_vm(const uint8_t*bc,size_t n,int input){int acc=input;size_t pc=0;while(pc<n){uint8_t op=bc[pc++];if(op==0xff)break;if(pc>=n)return-1;int8_t v=(int8_t)bc[pc++];switch(op){case 1:acc+=v;break;case 2:acc^=v;break;case 3:acc*=v;break;default:return-2;}}return acc;}
NI int lab07_flatten(int x){int state=0,y=0;for(;;){switch(state){case 0:y=x+7;state=y>20?1:2;break;case 1:return y*3;case 2:return y-5;default:return-1;}}}
NI uint32_t lab08_encode_value(uint32_t x,uint32_t key){return ((x+7u)^key)*33u;}
NI uint32_t lab09_decode_value(uint32_t x,uint32_t key){uint32_t inv=0x3e0f83e1u;return (x*inv^key)-7u;}
NI int lab10_permuted_array(const int*a,size_t n,size_t logical){if(logical>=n)return-1;size_t physical=(logical*5u+3u)%n;return a[physical];}
NI uint32_t lab11_hash_name(const char*s){uint32_t h=0;for(;*s;s++){uint8_t c=*s;if(c>='a'&&c<='z')c-=32;h=(h>>13)|(h<<19);h+=c;}return h;}
typedef int(*fn)(int);NI int inc(int x){return x+1;}NI int mix(int x){return(x<<1)^0x55;}
NI int lab12_indirect_chain(int x,const uint8_t*ops,size_t n){static fn t[]={inc,mix};for(size_t i=0;i<n;i++){if(ops[i]>=2)return-1;x=t[ops[i]](x);}return x;}
NI void lab13_self_transform(uint8_t*out,const uint8_t*in,size_t n,uint32_t k){for(size_t i=0;i<n;i++){k=k*1103515245u+12345u;out[i]=in[i]^(k>>24);}}
NI int lab14_interleaved(int a,int b){int x=a+1;int y=b*3;x=x*5-2;y=(y^0x33)+7;return(x&0xffff)|(y<<16);}
NI int lab15_composite_guard(const uint8_t*p,size_t n,uint32_t expected,uint64_t delta){uint32_t c=lab03_code_checksum(p,n);int d=lab01_debug_flag((uint32_t)delta);if(c!=expected)return-1;if(d)return-2;if(delta>100000)return-3;return 1;}
int main(void){uint8_t data[]="MENTOR",bc[]={1,5,2,3,3,2,0xff},ops[]={0,1,0};int arr[]={10,20,30,40,50,60,70};uint8_t out[6];
 uint32_t c=lab03_code_checksum(data,6);uint64_t total=0;total+=lab01_debug_flag(0);total+=lab02_timing_delta(10,25,100);
 total+=c+lab04_opaque_even(99)+lab05_opaque_square(17)+lab06_table_vm(bc,sizeof bc,7)+lab07_flatten(9);
 uint32_t e=lab08_encode_value(123,0xa5a5a5a5u);total+=e+lab09_decode_value(e,0xa5a5a5a5u);
 total+=lab10_permuted_array(arr,7,4)+lab11_hash_name("CreateFileW")+lab12_indirect_chain(3,ops,3);
 lab13_self_transform(out,data,6,7);total+=lab14_interleaved(2,4)+lab15_composite_guard(data,6,c,0);
 evidence_sink=total;printf("chapter10 evidence=%llu\n",(unsigned long long)total);return 0;}
```

# Walkthrough 01 — Debugger-state bit test

## Obstacle

Recover mask and Boolean; map sensor→decision rather than blindly flipping it.

## Ghidra output

```c
FUNCTION FUN_001013a0
ENTRY 001013a0
SIGNATURE undefined FUN_001013a0(void)
CALLERS 00102074, 00102178, 00101107, 00101667

bool FUN_001013a0(uint param_1)

{
  return (param_1 & 0x70) != 0;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013a0 <lab01_debug_flag>:
    13a0:	31 c0                	xor    eax,eax
    13a2:	83 e7 70             	and    edi,0x70
    13a5:	0f 95 c0             	setne  al
    13a8:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x22570f
 RBX  0
 RCX  0x57
 RDX  0x64
 RDI  0
 RSI  0x19
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x55555555510c (main+140) ◂— mov edi, 0xa
 RIP  0x5555555553a0 (lab01_debug_flag) ◂— xor eax, eax
   0x5555555553a2 <lab01_debug_flag+2>    and    edi, 0x70     EDI => 0 (0x0 & 0x70)
   0x5555555553a5 <lab01_debug_flag+5>    setne  al
   0x5555555553a8 <lab01_debug_flag+8>    ret                                <main+140>
   0x55555555510c <main+140>              mov    edi, 0xa      EDI => 0xa
   0x555555555111 <main+145>              mov    r10d, eax     R10D => 0
   0x555555555114 <main+148>              call   lab02_timing_delta          <lab02_timing_delta>
   0x555555555119 <main+153>              mov    edi, 0x63     EDI => 0x63
   0x55555555511e <main+158>              mov    edx, 7        EDX => 7
   0x555555555123 <main+163>              mov    esi, 7        ESI => 7
   0x555555555128 <main+168>              add    r10, rax
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab01_debug_flag`, RVA `0x13a0`.

# Walkthrough 02 — Timing threshold

## Obstacle

Recover unsigned delta, threshold, zero-or-delta return, and wrap assumptions.

## Ghidra output

```c
FUNCTION FUN_001013b0
ENTRY 001013b0
SIGNATURE undefined FUN_001013b0(void)
CALLERS 0010207c, 0010218c, 00101114

ulong FUN_001013b0(long param_1,long param_2,ulong param_3)

{
  ulong uVar1;

  uVar1 = param_2 - param_1;
  if (uVar1 <= param_3) {
    uVar1 = 0;
  }
  return uVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013b0 <lab02_timing_delta>:
    13b0:	48 89 f0             	mov    rax,rsi
    13b3:	48 29 f8             	sub    rax,rdi
    13b6:	48 39 c2             	cmp    rdx,rax
    13b9:	ba 00 00 00 00       	mov    edx,0x0
    13be:	48 0f 43 c2          	cmovae rax,rdx
    13c2:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0
 RBX  0
 RCX  0x57
 RDX  0x64
 RDI  0xa
 RSI  0x19
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x555555555119 (main+153) ◂— mov edi, 0x63
 RIP  0x5555555553b0 (lab02_timing_delta) ◂— mov rax, rsi
   0x5555555553b3 <lab02_timing_delta+3>     sub    rax, rdi     RAX => 0xf (0x19 - 0xa)
   0x5555555553b6 <lab02_timing_delta+6>     cmp    rdx, rax     0x64 - 0xf     EFLAGS => 0x216 [ cf PF AF zf sf IF df of ac ]
   0x5555555553b9 <lab02_timing_delta+9>     mov    edx, 0       EDX => 0
   0x5555555553be <lab02_timing_delta+14>  ✔ cmovae rax, rdx
   0x5555555553c2 <lab02_timing_delta+18>    ret                                <main+153>
   0x555555555119 <main+153>                 mov    edi, 0x63     EDI => 0x63
   0x55555555511e <main+158>                 mov    edx, 7        EDX => 7
   0x555555555123 <main+163>                 mov    esi, 7        ESI => 7
   0x555555555128 <main+168>                 add    r10, rax      R10 => 0 (0 + 0)
   0x55555555512b <main+171>                 call   lab04_opaque_even           <lab04_opaque_even>
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab02_timing_delta`, RVA `0x13b0`.

# Walkthrough 03 — Code/data checksum

## Obstacle

Recover covered pointer/length, rotate/XOR/index recurrence, and expected comparison consumers.

## Ghidra output

```c
FUNCTION FUN_001013d0
ENTRY 001013d0
SIGNATURE undefined FUN_001013d0(void)
CALLERS 00102084, 001021a0, 001010f3, 0010165a

uint FUN_001013d0(long param_1,long param_2)

{
  byte *pbVar1;
  uint uVar2;
  int iVar3;
  long lVar4;

  if (param_2 != 0) {
    lVar4 = 0;
    uVar2 = 0;
    do {
      pbVar1 = (byte *)(param_1 + lVar4);
      iVar3 = (int)lVar4;
      lVar4 = lVar4 + 1;
      uVar2 = (uVar2 << 3 | uVar2 >> 0x1d) ^ (uint)*pbVar1 + iVar3;
    } while (param_2 != lVar4);
    return uVar2;
  }
  return 0;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013d0 <lab03_code_checksum>:
    13d0:	48 85 f6             	test   rsi,rsi
    13d3:	74 23                	je     13f8 <lab03_code_checksum+0x28>
    13d5:	31 d2                	xor    edx,edx
    13d7:	31 c0                	xor    eax,eax
    13d9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    13e0:	0f b6 0c 17          	movzx  ecx,BYTE PTR [rdi+rdx*1]
    13e4:	c1 c0 03             	rol    eax,0x3
    13e7:	01 d1                	add    ecx,edx
    13e9:	48 83 c2 01          	add    rdx,0x1
    13ed:	31 c8                	xor    eax,ecx
    13ef:	48 39 d6             	cmp    rsi,rdx
    13f2:	75 ec                	jne    13e0 <lab03_code_checksum+0x10>
    13f4:	c3                   	ret
    13f5:	0f 1f 00             	nop    DWORD PTR [rax]
    13f8:	31 c0                	xor    eax,eax
    13fa:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x3c00000032
 RBX  0
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555552f0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe2a8 —▸ 0x7fffffffe67d ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
 RSI  6
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x5555555550f8 (main+120) ◂— xor edi, edi
 RIP  0x5555555553d0 (lab03_code_checksum) ◂— test rsi, rsi
   0x5555555553d3 <lab03_code_checksum+3>   ✘ je     lab03_code_checksum+40      <lab03_code_checksum+40>
   0x5555555553d5 <lab03_code_checksum+5>     xor    edx, edx                      EDX => 0
   0x5555555553d7 <lab03_code_checksum+7>     xor    eax, eax                      EAX => 0
   0x5555555553d9 <lab03_code_checksum+9>     nop    dword ptr [rax]
   0x5555555553e0 <lab03_code_checksum+16>    movzx  ecx, byte ptr [rdi + rdx]     ECX, [0x7fffffffe11a] => 0x4d
   0x5555555553e4 <lab03_code_checksum+20>    rol    eax, 3
   0x5555555553e7 <lab03_code_checksum+23>    add    ecx, edx                      ECX => 0x4d (0x4d + 0x0)
   0x5555555553e9 <lab03_code_checksum+25>    add    rdx, 1                        RDX => 1 (0 + 1)
   0x5555555553ed <lab03_code_checksum+29>    xor    eax, ecx                      EAX => 0x4d (0x0 ^ 0x4d)
   0x5555555553ef <lab03_code_checksum+31>    cmp    rsi, rdx                      6 - 1     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab03_code_checksum`, RVA `0x13d0`.

# Walkthrough 04 — Always-true parity predicate

## Obstacle

Prove x(x+1) even at 32-bit width and identify optimized constant result.

## Ghidra output

```c
FUNCTION FUN_00101400
ENTRY 00101400
SIGNATURE undefined FUN_00101400(void)
CALLERS 0010208c, 001021b4, 0010112b

int FUN_00101400(int param_1)

{
  return (-(uint)(((param_1 + 1) * param_1 & 1U) == 0) & 0x54) - 0x2a;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001400 <lab04_opaque_even>:
    1400:	8d 47 01             	lea    eax,[rdi+0x1]
    1403:	0f af c7             	imul   eax,edi
    1406:	83 e0 01             	and    eax,0x1
    1409:	83 f8 01             	cmp    eax,0x1
    140c:	19 c0                	sbb    eax,eax
    140e:	83 e0 54             	and    eax,0x54
    1411:	83 e8 2a             	sub    eax,0x2a
    1414:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0
 RBX  0
 RCX  0x57
 RDX  7
 RDI  0x63
 RSI  7
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x555555555130 (main+176) ◂— mov edi, 0x11
 RIP  0x555555555400 (lab04_opaque_even) ◂— lea eax, [rdi + 1]
   0x555555555403 <lab04_opaque_even+3>     imul   eax, edi
   0x555555555406 <lab04_opaque_even+6>     and    eax, 1             EAX => 0 (0x26ac & 0x1)
   0x555555555409 <lab04_opaque_even+9>     cmp    eax, 1             0 - 1     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ac ]
   0x55555555540c <lab04_opaque_even+12>    sbb    eax, eax
   0x55555555540e <lab04_opaque_even+14>    and    eax, 0x54          EAX => 0x54 (0xffffffff & 0x54)
   0x555555555411 <lab04_opaque_even+17>    sub    eax, 0x2a          EAX => 0x2a (0x54 - 0x2a)
   0x555555555414 <lab04_opaque_even+20>    ret                                <main+176>
   0x555555555130 <main+176>                mov    edi, 0x11          EDI => 0x11
   0x555555555135 <main+181>                mov    r11d, eax          R11D => 0x2a
   0x555555555138 <main+184>                call   lab05_opaque_square         <lab05_opaque_square>
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab04_opaque_even`, RVA `0x1400`.

# Walkthrough 05 — Impossible square residue

## Obstacle

Prove a square modulo 4 cannot equal 2 and examine compiler removal.

## Ghidra output

```c
FUNCTION FUN_00101420
ENTRY 00101420
SIGNATURE undefined FUN_00101420(void)
CALLERS 00102094, 001021c8, 00101138

char FUN_00101420(char param_1)

{
  return param_1 * param_1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001420 <lab05_opaque_square>:
    1420:	0f af ff             	imul   edi,edi
    1423:	40 0f b6 c7          	movzx  eax,dil
    1427:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x2a
 RBX  0
 RCX  0x57
 RDX  7
 RDI  0x11
 RSI  7
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x55555555513d (main+189) ◂— lea rdi, [rbp - 0x3f]
 RIP  0x555555555420 (lab05_opaque_square) ◂— imul edi, edi
   0x555555555423 <lab05_opaque_square+3>    movzx  eax, dil     EAX => 0x21
   0x555555555427 <lab05_opaque_square+7>    ret                                <main+189>
   0x55555555513d <main+189>                 lea    rdi, [rbp - 0x3f]     RDI => 0x7fffffffe121 ◂— 0xff020303020501
   0x555555555141 <main+193>                 add    r11d, eax             R11D => 0x4b (0x2a + 0x21)
   0x555555555144 <main+196>                 call   lab06_table_vm              <lab06_table_vm>
   0x555555555149 <main+201>                 add    r11d, r13d
   0x55555555514c <main+204>                 mov    edi, 9                EDI => 9
   0x555555555151 <main+209>                 mov    esi, 0xa5a5a5a5       ESI => 0xa5a5a5a5
   0x555555555156 <main+214>                 lea    ebx, [rax + r11]
   0x55555555515a <main+218>                 call   lab07_flatten               <lab07_flatten>
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab05_opaque_square`, RVA `0x1420`.

# Walkthrough 06 — Bytecode interpreter

## Obstacle

Recover PC, accumulator, op/value grammar, dispatch, signed operand, termination, and errors.

## Ghidra output

```c
FUNCTION FUN_00101430
ENTRY 00101430
SIGNATURE undefined FUN_00101430(void)
CALLERS 0010209c, 001021dc, 00101144

uint FUN_00101430(long param_1,ulong param_2,uint param_3)

{
  char cVar1;
  ulong uVar2;
  uint uVar3;

  if (param_2 != 0) {
    uVar2 = 0;
    do {
      cVar1 = *(char *)(param_1 + uVar2);
      if (cVar1 == -1) {
        return param_3;
      }
      if ((param_2 & 0xfffffffffffffffe) == uVar2) {
        return 0xffffffff;
      }
      uVar3 = (uint)*(char *)(param_1 + 1 + uVar2);
      if (cVar1 == '\x02') {
        param_3 = param_3 ^ uVar3;
      }
      else if (cVar1 == '\x03') {
        param_3 = param_3 * uVar3;
      }
      else {
        if (cVar1 != '\x01') {
          return 0xfffffffe;
        }
        param_3 = param_3 + uVar3;
      }
      uVar2 = uVar2 + 2;
    } while (uVar2 < param_2);
  }
  return param_3;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001430 <lab06_table_vm>:
    1430:	48 89 f8             	mov    rax,rdi
    1433:	49 89 f0             	mov    r8,rsi
    1436:	48 85 f6             	test   rsi,rsi
    1439:	74 3a                	je     1475 <lab06_table_vm+0x45>
    143b:	49 89 f1             	mov    r9,rsi
    143e:	31 c9                	xor    ecx,ecx
    1440:	49 83 e1 fe          	and    r9,0xfffffffffffffffe
    1444:	0f b6 34 08          	movzx  esi,BYTE PTR [rax+rcx*1]
    1448:	40 80 fe ff          	cmp    sil,0xff
    144c:	74 27                	je     1475 <lab06_table_vm+0x45>
    144e:	49 39 c9             	cmp    r9,rcx
    1451:	74 4d                	je     14a0 <lab06_table_vm+0x70>
    1453:	0f be 7c 08 01       	movsx  edi,BYTE PTR [rax+rcx*1+0x1]
    1458:	40 80 fe 02          	cmp    sil,0x2
    145c:	74 3a                	je     1498 <lab06_table_vm+0x68>
    145e:	40 80 fe 03          	cmp    sil,0x3
    1462:	74 2c                	je     1490 <lab06_table_vm+0x60>
    1464:	40 80 fe 01          	cmp    sil,0x1
    1468:	75 16                	jne    1480 <lab06_table_vm+0x50>
    146a:	01 fa                	add    edx,edi
    146c:	48 83 c1 02          	add    rcx,0x2
    1470:	4c 39 c1             	cmp    rcx,r8
    1473:	72 cf                	jb     1444 <lab06_table_vm+0x14>
    1475:	89 d0                	mov    eax,edx
    1477:	c3                   	ret
    1478:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    147f:	00
    1480:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1485:	c3                   	ret
    1486:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    148d:	00 00 00
    1490:	0f af d7             	imul   edx,edi
    1493:	eb d7                	jmp    146c <lab06_table_vm+0x3c>
    1495:	0f 1f 00             	nop    DWORD PTR [rax]
    1498:	31 fa                	xor    edx,edi
    149a:	eb d0                	jmp    146c <lab06_table_vm+0x3c>
    149c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    14a0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    14a5:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x21
 RBX  0
 RCX  0x57
 RDX  7
 RDI  0x7fffffffe121 ◂— 0xff020303020501
 RSI  7
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0d8 —▸ 0x555555555149 (main+201) ◂— add r11d, r13d
 RIP  0x555555555430 (lab06_table_vm) ◂— mov rax, rdi
   0x555555555433 <lab06_table_vm+3>     mov    r8, rsi      R8 => 7
   0x555555555436 <lab06_table_vm+6>     test   rsi, rsi     7 & 7     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555439 <lab06_table_vm+9>   ✘ je     lab06_table_vm+69           <lab06_table_vm+69>
   0x55555555543b <lab06_table_vm+11>    mov    r9, rsi                       R9 => 7
   0x55555555543e <lab06_table_vm+14>    xor    ecx, ecx                      ECX => 0
   0x555555555440 <lab06_table_vm+16>    and    r9, 0xfffffffffffffffe        R9 => 6 (7 & -2)
   0x555555555444 <lab06_table_vm+20>    movzx  esi, byte ptr [rax + rcx]     ESI, [0x7fffffffe121] => 1
   0x555555555448 <lab06_table_vm+24>    cmp    sil, 0xff                     0x1 - 0xff     EFLAGS => 0x213 [ CF pf AF zf sf IF df of ac ]
   0x55555555544c <lab06_table_vm+28>  ✘ je     lab06_table_vm+69           <lab06_table_vm+69>
   0x55555555544e <lab06_table_vm+30>    cmp    r9, rcx                       6 - 0     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab06_table_vm`, RVA `0x1430`.

# Walkthrough 07 — Flattened state machine

## Obstacle

Recover state transitions and reconstruct direct if/else semantics.

## Ghidra output

```c
FUNCTION FUN_001014b0
ENTRY 001014b0
SIGNATURE undefined FUN_001014b0(void)
CALLERS 001020a4, 001021f0, 0010115a

int FUN_001014b0(int param_1)

{
  int iVar1;

  iVar1 = (param_1 + 7) * 3;
  if (param_1 + 7 < 0x15) {
    iVar1 = param_1 + 2;
  }
  return iVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014b0 <lab07_flatten>:
    14b0:	8d 47 07             	lea    eax,[rdi+0x7]
    14b3:	83 c7 02             	add    edi,0x2
    14b6:	83 f8 15             	cmp    eax,0x15
    14b9:	8d 04 40             	lea    eax,[rax+rax*2]
    14bc:	0f 4c c7             	cmovl  eax,edi
    14bf:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x1e
 RBX  0x225778
 RCX  6
 RDX  0x1e
 RDI  9
 RSI  0xa5a5a5a5
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x55555555515f (main+223) ◂— mov edi, 0x7b
 RIP  0x5555555554b0 (lab07_flatten) ◂— lea eax, [rdi + 7]
   0x5555555554b3 <lab07_flatten+3>     add    edi, 2                 EDI => 0xb (9 + 2)
   0x5555555554b6 <lab07_flatten+6>     cmp    eax, 0x15              0x10 - 0x15     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x5555555554b9 <lab07_flatten+9>     lea    eax, [rax + rax*2]     EAX => 0x30
   0x5555555554bc <lab07_flatten+12>  ✔ cmovl  eax, edi
   0x5555555554bf <lab07_flatten+15>    ret                                <main+223>
   0x55555555515f <main+223>            mov    edi, 0x7b              EDI => 0x7b
   0x555555555164 <main+228>            mov    r14d, eax              R14D => 0xb
   0x555555555167 <main+231>            call   lab08_encode_value          <lab08_encode_value>
   0x55555555516c <main+236>            mov    edi, eax
   0x55555555516e <main+238>            mov    edx, eax
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab07_flatten`, RVA `0x14b0`.

# Walkthrough 08 — Encoded variable writer

## Obstacle

Recover add/XOR/multiply encoding.

## Ghidra output

```c
FUNCTION FUN_001014c0
ENTRY 001014c0
SIGNATURE undefined FUN_001014c0(void)
CALLERS 001020ac, 00102204, 00101167

int FUN_001014c0(int param_1,uint param_2)

{
  return (param_1 + 7U ^ param_2) * 0x21;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014c0 <lab08_encode_value>:
    14c0:	83 c7 07             	add    edi,0x7
    14c3:	31 f7                	xor    edi,esi
    14c5:	89 f8                	mov    eax,edi
    14c7:	c1 e0 05             	shl    eax,0x5
    14ca:	01 f8                	add    eax,edi
    14cc:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0xb
 RBX  0x225778
 RCX  6
 RDX  0x1e
 RDI  0x7b
 RSI  0xa5a5a5a5
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x55555555516c (main+236) ◂— mov edi, eax
 RIP  0x5555555554c0 (lab08_encode_value) ◂— add edi, 7
   0x5555555554c3 <lab08_encode_value+3>     xor    edi, esi     EDI => 0xa5a5a527 (0x82 ^ 0xa5a5a5a5)
   0x5555555554c5 <lab08_encode_value+5>     mov    eax, edi     EAX => 0xa5a5a527
   0x5555555554c7 <lab08_encode_value+7>     shl    eax, 5
   0x5555555554ca <lab08_encode_value+10>    add    eax, edi     EAX => 0x5a5a4a07 (0xb4b4a4e0 + 0xa5a5a527)
   0x5555555554cc <lab08_encode_value+12>    ret                                <main+236>
   0x55555555516c <main+236>                 mov    edi, eax     EDI => 0x5a5a4a07
   0x55555555516e <main+238>                 mov    edx, eax     EDX => 0x5a5a4a07
   0x555555555170 <main+240>                 call   lab09_decode_value          <lab09_decode_value>
   0x555555555175 <main+245>                 mov    esi, 7                ESI => 7
   0x55555555517a <main+250>                 lea    rdi, [rbp - 0x70]
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab08_encode_value`, RVA `0x14c0`.

# Walkthrough 09 — Encoded variable reader

## Obstacle

Pair modular inverse, XOR, subtract and prove round trip.

## Ghidra output

```c
FUNCTION FUN_001014d0
ENTRY 001014d0
SIGNATURE undefined FUN_001014d0(void)
CALLERS 001020b4, 00102218, 00101170

int FUN_001014d0(int param_1,uint param_2)

{
  return (param_1 * 0x3e0f83e1 ^ param_2) - 7;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014d0 <lab09_decode_value>:
    14d0:	69 ff e1 83 0f 3e    	imul   edi,edi,0x3e0f83e1
    14d6:	31 f7                	xor    edi,esi
    14d8:	8d 47 f9             	lea    eax,[rdi-0x7]
    14db:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x5a5a4a07
 RBX  0x225778
 RCX  6
 RDX  0x5a5a4a07
 RDI  0x5a5a4a07
 RSI  0xa5a5a5a5
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x555555555175 (main+245) ◂— mov esi, 7
 RIP  0x5555555554d0 (lab09_decode_value) ◂— imul edi, edi, 0x3e0f83e1
   0x5555555554d6 <lab09_decode_value+6>     xor    edi, esi                 EDI => 0x82 (0xa5a5a527 ^ 0xa5a5a5a5)
   0x5555555554d8 <lab09_decode_value+8>     lea    eax, [rdi - 7]           EAX => 0x7b
   0x5555555554db <lab09_decode_value+11>    ret                                <main+245>
   0x555555555175 <main+245>                 mov    esi, 7                   ESI => 7
   0x55555555517a <main+250>                 lea    rdi, [rbp - 0x70]        RDI => 0x7fffffffe0f0 ◂— 0x140000000a /* '\n' */
   0x55555555517e <main+254>                 lea    r12d, [rax + rdx]        R12D => 0x5a5a4a82
   0x555555555182 <main+258>                 mov    edx, 4                   EDX => 4
   0x555555555187 <main+263>                 call   lab10_permuted_array        <lab10_permuted_array>
   0x55555555518c <main+268>                 lea    rdi, [rip + 0xe71]       RDI => 0x555555556004 ◂— 'CreateFileW'
   0x555555555193 <main+275>                 add    r12, r10
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab09_decode_value`, RVA `0x14d0`.

# Walkthrough 10 — Restructured array index

## Obstacle

Recover physical=(logical*5+3)%n and bounds.

## Ghidra output

```c
FUNCTION FUN_001014e0
ENTRY 001014e0
SIGNATURE undefined FUN_001014e0(void)
CALLERS 001020bc, 0010222c, 00101187

undefined4 FUN_001014e0(long param_1,ulong param_2,ulong param_3)

{
  if (param_3 < param_2) {
    return *(undefined4 *)(param_1 + ((param_3 * 5 + 3) % param_2) * 4);
  }
  return 0xffffffff;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014e0 <lab10_permuted_array>:
    14e0:	48 39 f2             	cmp    rdx,rsi
    14e3:	73 13                	jae    14f8 <lab10_permuted_array+0x18>
    14e5:	48 8d 44 92 03       	lea    rax,[rdx+rdx*4+0x3]
    14ea:	31 d2                	xor    edx,edx
    14ec:	48 f7 f6             	div    rsi
    14ef:	8b 04 97             	mov    eax,DWORD PTR [rdi+rdx*4]
    14f2:	c3                   	ret
    14f3:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    14f8:	b8 ff ff ff ff       	mov    eax,0xffffffff
    14fd:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x7b
 RBX  0x225778
 RCX  6
 RDX  4
 RDI  0x7fffffffe0f0 ◂— 0x140000000a /* '\n' */
 RSI  7
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x55555555518c (main+268) ◂— lea rdi, [rip + 0xe71]
 RIP  0x5555555554e0 (lab10_permuted_array) ◂— cmp rdx, rsi
   0x5555555554e3 <lab10_permuted_array+3>   ✘ jae    lab10_permuted_array+24     <lab10_permuted_array+24>
   0x5555555554e5 <lab10_permuted_array+5>     lea    rax, [rdx + rdx*4 + 3]           RAX => 0x17
   0x5555555554ea <lab10_permuted_array+10>    xor    edx, edx                         EDX => 0
   0x5555555554ec <lab10_permuted_array+12>    div    rsi
   0x5555555554ef <lab10_permuted_array+15>    mov    eax, dword ptr [rdi + rdx*4]     EAX, [0x7fffffffe0f8] => 0x1e
   0x5555555554f2 <lab10_permuted_array+18>    ret                                <main+268>
   0x55555555518c <main+268>                   lea    rdi, [rip + 0xe71]               RDI => 0x555555556004 ◂— 'CreateFileW'
   0x555555555193 <main+275>                   add    r12, r10                         R12 => 0x5a5a4a82 (0x5a5a4a82 + 0x0)
   0x555555555196 <main+278>                   mov    dword ptr [rbp - 0x74], eax      [0x7fffffffe0ec] <= 0x1e
   0x555555555199 <main+281>                   call   lab11_hash_name             <lab11_hash_name>
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab10_permuted_array`, RVA `0x14e0`.

# Walkthrough 11 — API-name hashing

## Obstacle

Recover ASCII uppercase fold, rotate-right-13, add-byte loop, and terminator.

## Ghidra output

```c
FUNCTION FUN_00101500
ENTRY 00101500
SIGNATURE undefined FUN_00101500(void)
CALLERS 001020c4, 00102240, 00101199

uint FUN_00101500(byte *param_1)

{
  uint uVar1;
  byte bVar2;
  byte bVar3;

  bVar2 = *param_1;
  uVar1 = 0;
  if (bVar2 == 0) {
    return 0;
  }
  do {
    bVar3 = bVar2 - 0x20;
    if (0x19 < (byte)(bVar2 + 0x9f)) {
      bVar3 = bVar2;
    }
    bVar2 = param_1[1];
    param_1 = param_1 + 1;
    uVar1 = (uVar1 >> 0xd | uVar1 << 0x13) + (uint)bVar3;
  } while (bVar2 != 0);
  return uVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001500 <lab11_hash_name>:
    1500:	0f b6 0f             	movzx  ecx,BYTE PTR [rdi]
    1503:	31 c0                	xor    eax,eax
    1505:	84 c9                	test   cl,cl
    1507:	74 5f                	je     1568 <lab11_hash_name+0x68>
    1509:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1510:	00 00 00 00
    1514:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    151b:	00 00 00 00
    151f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1526:	00 00 00 00
    152a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1531:	00 00 00 00
    1535:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    153c:	00 00 00 00
    1540:	8d 71 9f             	lea    esi,[rcx-0x61]
    1543:	8d 51 e0             	lea    edx,[rcx-0x20]
    1546:	40 80 fe 1a          	cmp    sil,0x1a
    154a:	0f 43 d1             	cmovae edx,ecx
    154d:	0f b6 4f 01          	movzx  ecx,BYTE PTR [rdi+0x1]
    1551:	c1 c8 0d             	ror    eax,0xd
    1554:	48 83 c7 01          	add    rdi,0x1
    1558:	0f b6 d2             	movzx  edx,dl
    155b:	01 d0                	add    eax,edx
    155d:	84 c9                	test   cl,cl
    155f:	75 df                	jne    1540 <lab11_hash_name+0x40>
    1561:	c3                   	ret
    1562:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1568:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x1e
 RBX  0x225778
 RCX  6
 RDX  2
 RDI  0x555555556004 ◂— 'CreateFileW'
 RSI  7
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x55555555519e (main+286) ◂— lea rsi, [rbp - 0x4f]
 RIP  0x555555555500 (lab11_hash_name) ◂— movzx ecx, byte ptr [rdi]
   0x555555555503 <lab11_hash_name+3>     xor    eax, eax                EAX => 0
   0x555555555505 <lab11_hash_name+5>     test   cl, cl                  0x43 & 0x43     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555507 <lab11_hash_name+7>   ✘ je     lab11_hash_name+104         <lab11_hash_name+104>
   0x555555555509 <lab11_hash_name+9>     nop    word ptr [rax + rax]
   0x555555555514 <lab11_hash_name+20>    nop    word ptr [rax + rax]
   0x55555555551f <lab11_hash_name+31>    nop    word ptr [rax + rax]
   0x55555555552a <lab11_hash_name+42>    nop    word ptr [rax + rax]
   0x555555555535 <lab11_hash_name+53>    nop    word ptr [rax + rax]
   0x555555555540 <lab11_hash_name+64>    lea    esi, [rcx - 0x61]        ESI => 0xffffffffffffffe2
   0x555555555543 <lab11_hash_name+67>    lea    edx, [rcx - 0x20]        EDX => 0x23
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab11_hash_name`, RVA `0x1500`.

# Walkthrough 12 — Indirect control chain

## Obstacle

Recover handler table, opcode bounds, repeated state update, and target set.

## Ghidra output

```c
FUNCTION FUN_00101570
ENTRY 00101570
SIGNATURE undefined FUN_00101570(void)
CALLERS 001020cc, 00102254, 001011af

ulong FUN_00101570(ulong param_1,byte *param_2,long param_3)

{
  byte *pbVar1;
  ulong uVar2;

  if (param_3 == 0) {
    return param_1 & 0xffffffff;
  }
  pbVar1 = param_2 + param_3;
  do {
    if (1 < *param_2) {
      return 0xffffffff;
    }
    uVar2 = (*(code *)(&PTR_FUN_00103dd0)[*param_2])(param_1);
    param_2 = param_2 + 1;
    param_1 = uVar2 & 0xffffffff;
  } while (param_2 != pbVar1);
  return uVar2;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001570 <lab12_indirect_chain>:
    1570:	48 85 d2             	test   rdx,rdx
    1573:	74 4b                	je     15c0 <lab12_indirect_chain+0x50>
    1575:	55                   	push   rbp
    1576:	48 89 e5             	mov    rbp,rsp
    1579:	41 55                	push   r13
    157b:	4c 8d 2d 4e 28 00 00 	lea    r13,[rip+0x284e]        # 3dd0 <t.0>
    1582:	41 54                	push   r12
    1584:	4c 8d 24 16          	lea    r12,[rsi+rdx*1]
    1588:	53                   	push   rbx
    1589:	48 89 f3             	mov    rbx,rsi
    158c:	48 83 ec 08          	sub    rsp,0x8
    1590:	eb 16                	jmp    15a8 <lab12_indirect_chain+0x38>
    1592:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1598:	41 ff 54 d5 00       	call   QWORD PTR [r13+rdx*8+0x0]
    159d:	48 83 c3 01          	add    rbx,0x1
    15a1:	89 c7                	mov    edi,eax
    15a3:	4c 39 e3             	cmp    rbx,r12
    15a6:	74 0d                	je     15b5 <lab12_indirect_chain+0x45>
    15a8:	0f b6 13             	movzx  edx,BYTE PTR [rbx]
    15ab:	80 fa 01             	cmp    dl,0x1
    15ae:	76 e8                	jbe    1598 <lab12_indirect_chain+0x28>
    15b0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    15b5:	48 83 c4 08          	add    rsp,0x8
    15b9:	5b                   	pop    rbx
    15ba:	41 5c                	pop    r12
    15bc:	41 5d                	pop    r13
    15be:	5d                   	pop    rbp
    15bf:	c3                   	ret
    15c0:	89 f8                	mov    eax,edi
    15c2:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x1a7f0bab
 RBX  0x225778
 RCX  0
 RDX  3
 RDI  3
 RSI  0x7fffffffe111 ◂— 0x4800000000000100
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x5555555551b4 (main+308) ◂— mov edx, 6
 RIP  0x555555555570 (lab12_indirect_chain) ◂— test rdx, rdx
   0x555555555573 <lab12_indirect_chain+3>   ✘ je     lab12_indirect_chain+80     <lab12_indirect_chain+80>
   0x555555555575 <lab12_indirect_chain+5>     push   rbp
   0x555555555576 <lab12_indirect_chain+6>     mov    rbp, rsp                RBP => 0x7fffffffe0d0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555579 <lab12_indirect_chain+9>     push   r13
   0x55555555557b <lab12_indirect_chain+11>    lea    r13, [rip + 0x284e]     R13 => 0x555555557dd0 (t) —▸ 0x555555555380 (inc) ◂— lea eax, [rdi + 1]
   0x555555555582 <lab12_indirect_chain+18>    push   r12
   0x555555555584 <lab12_indirect_chain+20>    lea    r12, [rsi + rdx]        R12 => 0x7fffffffe114 ◂— 0x454de14800000000
   0x555555555588 <lab12_indirect_chain+24>    push   rbx
   0x555555555589 <lab12_indirect_chain+25>    mov    rbx, rsi                RBX => 0x7fffffffe111 ◂— 0x4800000000000100
   0x55555555558c <lab12_indirect_chain+28>    sub    rsp, 8                  RSP => 0x7fffffffe0b0 (0x7fffffffe0b8 - 0x8)
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab12_indirect_chain`, RVA `0x1570`.

# Walkthrough 13 — Runtime byte transformation

## Obstacle

Recover decode state/output window while noting bytes are never executed here.

## Ghidra output

```c
FUNCTION FUN_001015d0
ENTRY 001015d0
SIGNATURE undefined FUN_001015d0(void)
CALLERS 001020d4, 00102280, 001011c9

void FUN_001015d0(long param_1,long param_2,long param_3,int param_4)

{
  long lVar1;

  if (param_3 != 0) {
    lVar1 = 0;
    do {
      param_4 = param_4 * 0x41c64e6d + 0x3039;
      *(byte *)(param_1 + lVar1) = (byte)((uint)param_4 >> 0x18) ^ *(byte *)(param_2 + lVar1);
      lVar1 = lVar1 + 1;
    } while (param_3 != lVar1);
  }
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000015d0 <lab13_self_transform>:
    15d0:	49 89 f0             	mov    r8,rsi
    15d3:	48 89 d6             	mov    rsi,rdx
    15d6:	48 85 d2             	test   rdx,rdx
    15d9:	74 46                	je     1621 <lab13_self_transform+0x51>
    15db:	31 c0                	xor    eax,eax
    15dd:	66 90                	xchg   ax,ax
    15df:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    15e6:	00 00 00 00
    15ea:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    15f1:	00 00 00 00
    15f5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    15fc:	00 00 00 00
    1600:	69 c9 6d 4e c6 41    	imul   ecx,ecx,0x41c64e6d
    1606:	81 c1 39 30 00 00    	add    ecx,0x3039
    160c:	89 ca                	mov    edx,ecx
    160e:	c1 ea 18             	shr    edx,0x18
    1611:	41 32 14 00          	xor    dl,BYTE PTR [r8+rax*1]
    1615:	88 14 07             	mov    BYTE PTR [rdi+rax*1],dl
    1618:	48 83 c0 01          	add    rax,0x1
    161c:	48 39 c6             	cmp    rsi,rax
    161f:	75 df                	jne    1600 <lab13_self_transform+0x30>
    1621:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x5e
 RBX  0x225778
 RCX  7
 RDX  6
 RDI  0x7fffffffe114 ◂— 0x454de14800000000
 RSI  0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
 R8   7
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x5555555551ce (main+334) ◂— mov esi, 4
 RIP  0x5555555555d0 (lab13_self_transform) ◂— mov r8, rsi
   0x5555555555d3 <lab13_self_transform+3>     mov    rsi, rdx     RSI => 6
   0x5555555555d6 <lab13_self_transform+6>     test   rdx, rdx     6 & 6     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555555d9 <lab13_self_transform+9>   ✘ je     lab13_self_transform+81     <lab13_self_transform+81>
   0x5555555555db <lab13_self_transform+11>    xor    eax, eax                 EAX => 0
   0x5555555555dd <lab13_self_transform+13>    nop
   0x5555555555df <lab13_self_transform+15>    nop    word ptr [rax + rax]
   0x5555555555ea <lab13_self_transform+26>    nop    word ptr [rax + rax]
   0x5555555555f5 <lab13_self_transform+37>    nop    word ptr [rax + rax]
   0x555555555600 <lab13_self_transform+48>    imul   ecx, ecx, 0x41c64e6d
   0x555555555606 <lab13_self_transform+54>    add    ecx, 0x3039              ECX => 0xcc6c5534 (0xcc6c24fb + 0x3039)
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab13_self_transform`, RVA `0x15d0`.

# Walkthrough 14 — Interleaved independent calculations

## Obstacle

Use slicing to separate x and y computations before final packing.

## Ghidra output

```c
FUNCTION FUN_00101630
ENTRY 00101630
SIGNATURE undefined FUN_00101630(void)
CALLERS 001020dc, 00102294, 001011da

uint FUN_00101630(int param_1,int param_2)

{
  return param_1 * 5 + 3U & 0xffff | ((param_2 * 3 ^ 0x33U) + 7) * 0x10000;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001630 <lab14_interleaved>:
    1630:	8d 14 76             	lea    edx,[rsi+rsi*2]
    1633:	8d 44 bf 03          	lea    eax,[rdi+rdi*4+0x3]
    1637:	83 f2 33             	xor    edx,0x33
    163a:	0f b7 c0             	movzx  eax,ax
    163d:	83 c2 07             	add    edx,0x7
    1640:	c1 e2 10             	shl    edx,0x10
    1643:	09 d0                	or     eax,edx
    1645:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  6
 RBX  0x225778
 RCX  0
 RDX  0xdf
 RDI  2
 RSI  4
 R8   0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x5555555551df (main+351) ◂— mov esi, 6
 RIP  0x555555555630 (lab14_interleaved) ◂— lea edx, [rsi + rsi*2]
   0x555555555633 <lab14_interleaved+3>     lea    eax, [rdi + rdi*4 + 3]     EAX => 0xd
   0x555555555637 <lab14_interleaved+7>     xor    edx, 0x33                  EDX => 0x3f (0xc ^ 0x33)
   0x55555555563a <lab14_interleaved+10>    movzx  eax, ax                    EAX => 0xd
   0x55555555563d <lab14_interleaved+13>    add    edx, 7                     EDX => 0x46 (0x3f + 0x7)
   0x555555555640 <lab14_interleaved+16>    shl    edx, 0x10
   0x555555555643 <lab14_interleaved+19>    or     eax, edx                   EAX => 0x46000d (0xd | 0x460000)
   0x555555555645 <lab14_interleaved+21>    ret                                <main+351>
   0x5555555551df <main+351>                mov    esi, 6                ESI => 6
   0x5555555551e4 <main+356>                lea    rdi, [rbp - 0x46]     RDI => 0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
   0x5555555551e8 <main+360>                mov    edx, r13d             EDX => 0x22570f
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab14_interleaved`, RVA `0x1630`.

# Walkthrough 15 — Interdependent guard

## Obstacle

Trace checksum, debugger flag, timing delta, ordered failures, and shared dependencies.

## Ghidra output

```c
FUNCTION FUN_00101650
ENTRY 00101650
SIGNATURE undefined FUN_00101650(void)
CALLERS 001020e4, 001022a8, 001011ee

int FUN_00101650(undefined8 param_1,undefined8 param_2,int param_3,ulong param_4)

{
  int iVar1;

  iVar1 = FUN_001013d0();
  if (iVar1 != param_3) {
    return -1;
  }
  iVar1 = FUN_001013a0(param_4 & 0xffffffff);
  if (iVar1 == 0) {
    return (-(uint)(param_4 < 0x186a1) & 4) - 3;
  }
  return -2;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch10/ch10_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001650 <lab15_composite_guard>:
    1650:	55                   	push   rbp
    1651:	41 89 d1             	mov    r9d,edx
    1654:	49 89 c8             	mov    r8,rcx
    1657:	48 89 e5             	mov    rbp,rsp
    165a:	e8 71 fd ff ff       	call   13d0 <lab03_code_checksum>
    165f:	44 39 c8             	cmp    eax,r9d
    1662:	75 24                	jne    1688 <lab15_composite_guard+0x38>
    1664:	44 89 c7             	mov    edi,r8d
    1667:	e8 34 fd ff ff       	call   13a0 <lab01_debug_flag>
    166c:	85 c0                	test   eax,eax
    166e:	75 20                	jne    1690 <lab15_composite_guard+0x40>
    1670:	49 81 f8 a1 86 01 00 	cmp    r8,0x186a1
    1677:	5d                   	pop    rbp
    1678:	19 c0                	sbb    eax,eax
    167a:	83 e0 04             	and    eax,0x4
    167d:	83 e8 03             	sub    eax,0x3
    1680:	c3                   	ret
    1681:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1688:	b8 ff ff ff ff       	mov    eax,0xffffffff
    168d:	5d                   	pop    rbp
    168e:	c3                   	ret
    168f:	90                   	nop
    1690:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1695:	5d                   	pop    rbp
    1696:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x46000d
 RBX  0x225778
 RCX  0
 RDX  0x22570f
 RDI  0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
 RSI  6
 R8   0x7fffffffe11a ◂— 0x100524f544e454d /* 'MENTOR' */
 R9   6
 RSP  0x7fffffffe0d8 —▸ 0x5555555551f3 (main+371) ◂— lea rdi, [rip + 0xe16]
 RIP  0x555555555650 (lab15_composite_guard) ◂— push rbp
   0x555555555651 <lab15_composite_guard+1>     mov    r9d, edx     R9D => 0x22570f
   0x555555555654 <lab15_composite_guard+4>     mov    r8, rcx      R8 => 0
   0x555555555657 <lab15_composite_guard+7>     mov    rbp, rsp     RBP => 0x7fffffffe0d0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x55555555565a <lab15_composite_guard+10>    call   lab03_code_checksum         <lab03_code_checksum>
   0x55555555565f <lab15_composite_guard+15>    cmp    eax, r9d
   0x555555555662 <lab15_composite_guard+18>    jne    lab15_composite_guard+56    <lab15_composite_guard+56>
   0x555555555664 <lab15_composite_guard+20>    mov    edi, r8d
   0x555555555667 <lab15_composite_guard+23>    call   lab01_debug_flag            <lab01_debug_flag>
   0x55555555566c <lab15_composite_guard+28>    test   eax, eax
   0x55555555566e <lab15_composite_guard+30>    jne    lab15_composite_guard+64    <lab15_composite_guard+64>
```

## Normalization walkthrough

1. Identify observation/encoding/dispatcher inputs and every downstream use.
2. Lift exact operations into width-aware expressions and CFG.
3. Prove constants, opaque edges, inverse transforms, or target sets.
4. Replace complexity in the analysis model, not by an unexplained patch.
5. Differential-test normalized and original functions on boundaries/random vectors.

**Recovered:** `lab15_composite_guard`, RVA `0x1650`.

# Twenty Practice Questions

1. How map antidebug check?
2. Why not flip branch first?
3. How prove opaque parity?
4. Square mod 4 residues?
5. Linear sweep weakness?
6. Recursive traversal weakness?
7. What identifies VM?
8. How devirtualize?
9. Why exact modular inverse?
10. How slice interleaved code?
11. What does API hash hide?
12. How validate hash?
13. When is timing noisy?
14. What is checksum range evidence?
15. Why dynamic code boundary?
16. What is false opaque conclusion?
17. How preserve fixed width?
18. What is ordering transform recovery?
19. Why compare Ghidra and pwndbg?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Sensor→interpretation→state/branch/key→consequence.
4. Prove equivalence with a counterexample-oriented test.

## 2. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Result may feed key/state and redundant checks.
4. Prove equivalence with a counterexample-oriented test.

## 3. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Consecutive integers include one even factor.
4. Prove equivalence with a counterexample-oriented test.

## 4. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Only 0 or 1.
4. Prove equivalence with a counterexample-oriented test.

## 5. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Decodes embedded data and can desynchronize.
4. Prove equivalence with a counterexample-oriented test.

## 6. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Misses unresolved indirect targets.
4. Prove equivalence with a counterexample-oriented test.

## 7. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Central loop reads opcode/state and dispatches handlers.
4. Prove equivalence with a counterexample-oriented test.

## 8. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Recover VM state, opcode semantics, transitions, and replace with direct IR/CFG.
4. Prove equivalence with a counterexample-oriented test.

## 9. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Encoding/decoding equivalence depends on arithmetic modulo 2^32.
4. Prove equivalence with a counterexample-oriented test.

## 10. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Group definitions/uses by output dependency rather than address proximity.
4. Prove equivalence with a counterexample-oriented test.

## 11. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Symbol strings/imports, but runtime targets and hash loop reveal resolution.
4. Prove equivalence with a counterexample-oriented test.

## 12. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Reimplement exact case fold/rotate/add and compare known names.
4. Prove equivalence with a counterexample-oriented test.

## 13. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Scheduling, virtualization, load, and debugger instrumentation affect it.
4. Prove equivalence with a counterexample-oriented test.

## 14. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Pointer/length at call, memory mapping, and changes inside/outside range.
4. Prove equivalence with a counterexample-oriented test.

## 15. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Transformed bytes become meaningful only at runtime; execution transfer establishes code.
4. Prove equivalence with a counterexample-oriented test.

## 16. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Branch unobserved in tests but not mathematically unreachable.
4. Prove equivalence with a counterexample-oriented test.

## 17. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Use bit-vector/modular operations and exact shifts/masks.
4. Prove equivalence with a counterexample-oriented test.

## 18. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Use dependencies and CFG, not physical address order.
4. Prove equivalence with a counterexample-oriented test.

## 19. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Static normalization covers alternatives; runtime confirms actual state/targets.
4. Prove equivalence with a counterexample-oriented test.

## 20. Solution

1. Identify the invariant hidden by the transformation.
2. Preserve exact machine width and side effects.
3. **Answer:** Normalize all fifteen functions into simpler equivalent code and differential-test outputs.
4. Prove equivalence with a counterexample-oriented test.


Return to [[Chapter 10 - Antireversing Techniques]].
