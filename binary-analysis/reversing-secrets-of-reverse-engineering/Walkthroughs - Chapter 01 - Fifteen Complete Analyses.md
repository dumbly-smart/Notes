# Chapter 1 — Fifteen Complete Tool-Backed Walkthroughs

> [!evidence]
> These are executed walkthroughs, not suggested exercises. The specimen was compiled with GCC 16.1.1, imported into Ghidra 12.1.2 headlessly, disassembled with GNU objdump, and executed under GDB 17.2 with pwndbg 2026.02.18. Addresses below are RVAs in Ghidra’s PIE image; runtime addresses vary with ASLR.

## Reproduction Record

```sh
gcc -O2 -fno-inline -fno-omit-frame-pointer -g -Wall -Wextra \
  -o ch01_debug ch01_foundations.c
objcopy --strip-all ch01_debug ch01_stripped_same
/opt/ghidra/support/analyzeHeadless ... -import ch01_stripped_same \
  -postScript ExportWalkthrough.java ghidra-stripped.txt
pwndbg -nx -q --batch ch01_debug \
  -ex 'source TraceFunctions.py' -ex 'set args USER 999;' -ex run
```

Observed baseline:

```text
chapter01 evidence=15561264657395583068 out=AAABBC q=9
Ghidra stripped-function count: 36
pwndbg function breakpoints installed: 15
```

## Complete Specimen Source

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

# Walkthrough 01 — Rolling hash recovery

## Question and target

Given only stripped function `FUN_00101530`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover a byte-wise FNV-style recurrence from the seed, XOR, multiplication constant, pointer end-test, and 32-bit wraparound. The hard part is separating the mathematical recurrence from compiler pointer-loop optimization.

```c
FUNCTION FUN_00101530
ENTRY 00101530
SIGNATURE undefined FUN_00101530(void)
CALLERS 0010210c, 00102224, 00101219, 00101c71

uint FUN_00101530(byte *param_1,long param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;

  if (param_2 != 0) {
    pbVar3 = param_1 + param_2;
    uVar2 = 0x811c9dc5;
    do {
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      uVar2 = (uVar2 ^ bVar1) * 0x1000193;
    } while (pbVar3 != param_1);
    return uVar2;
  }
  return 0x811c9dc5;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001530 <lab01_rolling_hash>:
    1530:	48 85 f6             	test   rsi,rsi
    1533:	74 23                	je     1558 <lab01_rolling_hash+0x28>
    1535:	48 01 fe             	add    rsi,rdi
    1538:	b8 c5 9d 1c 81       	mov    eax,0x811c9dc5
    153d:	0f 1f 00             	nop    DWORD PTR [rax]
    1540:	0f b6 17             	movzx  edx,BYTE PTR [rdi]
    1543:	48 83 c7 01          	add    rdi,0x1
    1547:	31 d0                	xor    eax,edx
    1549:	69 c0 93 01 00 01    	imul   eax,eax,0x1000193
    154f:	48 39 fe             	cmp    rsi,rdi
    1552:	75 ec                	jne    1540 <lab01_rolling_hash+0x10>
    1554:	c3                   	ret
    1555:	0f 1f 00             	nop    DWORD PTR [rax]
    1558:	b8 c5 9d 1c 81       	mov    eax,0x811c9dc5
    155d:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0x7804020302010301
 RBX  0
 RCX  6
 RDX  0
 RDI  0x7fffffffe0b0 ◂— 0x722d726f746e656d ('mentor-r')
 RSI  0x10
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffdf98 —▸ 0x55555555521e (main+414) ◂— lea rdx, [rbp - 0xc1]
 RIP  0x555555555530 (lab01_rolling_hash) ◂— test rsi, rsi
   0x555555555533 <lab01_rolling_hash+3>   ✘ je     lab01_rolling_hash+40       <lab01_rolling_hash+40>
   0x555555555535 <lab01_rolling_hash+5>     add    rsi, rdi                RSI => 0x7fffffffe0c0 (0x10 + 0x7fffffffe0b0)
   0x555555555538 <lab01_rolling_hash+8>     mov    eax, 0x811c9dc5         EAX => 0x811c9dc5
   0x55555555553d <lab01_rolling_hash+13>    nop    dword ptr [rax]
   0x555555555540 <lab01_rolling_hash+16>    movzx  edx, byte ptr [rdi]     EDX, [0x7fffffffe0b0] => 0x6d
   0x555555555543 <lab01_rolling_hash+19>    add    rdi, 1                  RDI => 0x7fffffffe0b1 (0x7fffffffe0b0 + 0x1)
   0x555555555547 <lab01_rolling_hash+23>    xor    eax, edx                EAX => 0x811c9da8 (0x811c9dc5 ^ 0x6d)
   0x555555555549 <lab01_rolling_hash+25>    imul   eax, eax, 0x1000193
   0x55555555554f <lab01_rolling_hash+31>    cmp    rsi, rdi                0x7fffffffe0c0 - 0x7fffffffe0b1     EFLAGS => 0x216 [ cf PF AF zf sf IF df of ac ]
   0x555555555552 <lab01_rolling_hash+34>  ✔ jne    lab01_rolling_hash+16       <lab01_rolling_hash+16>
=> 0x555555555530 <lab01_rolling_hash>:	test   rsi,rsi
   0x555555555533 <lab01_rolling_hash+3>:	je     0x555555555558 <lab01_rolling_hash+40>
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab01_rolling_hash` with entry RVA `0x1530`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 02 — Bounds-safe RLE decoder

## Question and target

Given only stripped function `FUN_00101560`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Reconstruct two input cursors, output capacity, the count/value pair grammar, overflow-safe remaining-capacity check, nested expansion loop, and two distinct malformed-input returns.

```c
FUNCTION FUN_00101560
ENTRY 00101560
SIGNATURE undefined FUN_00101560(void)
CALLERS 00102114, 00102238, 00101230

long FUN_00101560(long param_1,long param_2,long param_3,ulong param_4)

{
  long *plVar1;
  long *plVar2;
  byte bVar3;
  uint uVar4;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  uint uVar9;
  long lVar10;
  ulong uVar5;

  if (param_4 < 2) {
    lVar7 = 0;
    uVar8 = 0;
  }
  else {
    uVar8 = param_4 & 0xfffffffffffffffe;
    lVar7 = 0;
    uVar6 = 0;
    do {
      bVar3 = *(byte *)(param_3 + uVar6);
      uVar4 = (uint)bVar3;
      uVar5 = (ulong)uVar4;
      if ((ulong)(param_2 - lVar7) < uVar5) {
        return -1;
      }
      uVar6 = uVar6 + 2;
      if (bVar3 != 0) {
        plVar1 = (long *)(param_1 + lVar7);
        lVar10 = (ulong)*(byte *)(param_3 + -1 + uVar6) * 0x101010101010101;
        if (uVar4 < 0x40) {
          if ((bVar3 & 0x20) == 0) {
            if ((bVar3 & 0x10) == 0) {
              if ((bVar3 & 8) == 0) {
                if ((bVar3 & 4) == 0) {
                  if ((uVar4 != 0) && (*(char *)plVar1 = (char)lVar10, (bVar3 & 2) != 0)) {
                    *(short *)((uVar5 - 2) + (long)plVar1) = (short)lVar10;
                  }
                }
                else {
                  *(int *)plVar1 = (int)lVar10;
                  *(int *)((uVar5 - 4) + (long)plVar1) = (int)lVar10;
                }
              }
              else {
                *plVar1 = lVar10;
                *(long *)((uVar5 - 8) + (long)plVar1) = lVar10;
              }
            }
            else {
              *plVar1 = lVar10;
              plVar1[1] = lVar10;
              plVar1 = (long *)((uVar5 - 0x10) + (long)plVar1);
              *plVar1 = lVar10;
              plVar1[1] = lVar10;
            }
          }
          else {
            *plVar1 = lVar10;
            plVar1[1] = lVar10;
            plVar1[2] = lVar10;
            plVar1[3] = lVar10;
            plVar2 = (long *)((uVar5 - 0x20) + (long)plVar1);
            *plVar2 = lVar10;
            plVar2[1] = lVar10;
            plVar1 = (long *)((uVar5 - 0x10) + (long)plVar1);
            *plVar1 = lVar10;
            plVar1[1] = lVar10;
          }
        }
        else {
          plVar2 = (long *)((uVar5 - 0x40) + (long)plVar1);
          *plVar2 = lVar10;
          plVar2[1] = lVar10;
          plVar2 = (long *)((uVar5 - 0x30) + (long)plVar1);
          *plVar2 = lVar10;
          plVar2[1] = lVar10;
          plVar2 = (long *)((uVar5 - 0x20) + (long)plVar1);
          *plVar2 = lVar10;
          plVar2[1] = lVar10;
          plVar2 = (long *)((uVar5 - 0x10) + (long)plVar1);
          *plVar2 = lVar10;
          plVar2[1] = lVar10;
          if (0x3f < uVar4 - 1) {
            uVar9 = 0;
            do {
              uVar5 = (ulong)uVar9;
              uVar9 = uVar9 + 0x40;
              *(long *)((long)plVar1 + uVar5) = lVar10;
              ((long *)((long)plVar1 + uVar5))[1] = lVar10;
              plVar2 = (long *)((long)plVar1 + uVar5 + 0x10);
              *plVar2 = lVar10;
              plVar2[1] = lVar10;
              plVar2 = (long *)((long)plVar1 + uVar5 + 0x20);
              *plVar2 = lVar10;
              plVar2[1] = lVar10;
              plVar2 = (long *)((long)plVar1 + uVar5 + 0x30);
              *plVar2 = lVar10;
              plVar2[1] = lVar10;
            } while (uVar9 < (uVar4 - 1 & 0xffffffc0));
          }
        }
        lVar7 = lVar7 + 1 + (ulong)(uVar4 - 1 & 0xff);
      }
    } while (uVar6 != uVar8);
  }
  if (param_4 != uVar8) {
    lVar7 = -1;
  }
  return lVar7;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001560 <lab02_rle_decode>:
    1560:	55                   	push   rbp
    1561:	48 89 e5             	mov    rbp,rsp
    1564:	48 83 ec 20          	sub    rsp,0x20
    1568:	48 89 5d e0          	mov    QWORD PTR [rbp-0x20],rbx
    156c:	48 89 cb             	mov    rbx,rcx
    156f:	48 83 f9 01          	cmp    rcx,0x1
    1573:	0f 86 89 01 00 00    	jbe    1702 <lab02_rle_decode+0x1a2>
    1579:	49 89 c8             	mov    r8,rcx
    157c:	49 89 f9             	mov    r9,rdi
    157f:	49 89 f2             	mov    r10,rsi
    1582:	4c 89 65 e8          	mov    QWORD PTR [rbp-0x18],r12
    1586:	4c 89 6d f0          	mov    QWORD PTR [rbp-0x10],r13
    158a:	48 89 d7             	mov    rdi,rdx
    158d:	49 83 e0 fe          	and    r8,0xfffffffffffffffe
    1591:	31 f6                	xor    esi,esi
    1593:	49 bb 01 01 01 01 01 	movabs r11,0x101010101010101
    159a:	01 01 01
    159d:	4c 89 75 f8          	mov    QWORD PTR [rbp-0x8],r14
    15a1:	31 c9                	xor    ecx,ecx
    15a3:	eb 47                	jmp    15ec <lab02_rle_decode+0x8c>
    15a5:	0f 1f 00             	nop    DWORD PTR [rax]
    15a8:	a8 20                	test   al,0x20
    15aa:	0f 85 00 01 00 00    	jne    16b0 <lab02_rle_decode+0x150>
    15b0:	a8 10                	test   al,0x10
    15b2:	0f 85 13 01 00 00    	jne    16cb <lab02_rle_decode+0x16b>
    15b8:	a8 08                	test   al,0x8
    15ba:	0f 85 1b 01 00 00    	jne    16db <lab02_rle_decode+0x17b>
    15c0:	a8 04                	test   al,0x4
    15c2:	0f 85 21 01 00 00    	jne    16e9 <lab02_rle_decode+0x189>
    15c8:	85 c0                	test   eax,eax
    15ca:	74 0c                	je     15d8 <lab02_rle_decode+0x78>
    15cc:	45 88 65 00          	mov    BYTE PTR [r13+0x0],r12b
    15d0:	a8 02                	test   al,0x2
    15d2:	0f 85 1f 01 00 00    	jne    16f7 <lab02_rle_decode+0x197>
    15d8:	83 ea 01             	sub    edx,0x1
    15db:	0f b6 d2             	movzx  edx,dl
    15de:	48 8d 74 16 01       	lea    rsi,[rsi+rdx*1+0x1]
    15e3:	4c 39 c1             	cmp    rcx,r8
    15e6:	0f 84 a1 00 00 00    	je     168d <lab02_rle_decode+0x12d>
    15ec:	0f b6 04 0f          	movzx  eax,BYTE PTR [rdi+rcx*1]
    15f0:	4d 89 d4             	mov    r12,r10
    15f3:	49 29 f4             	sub    r12,rsi
    15f6:	48 89 c2             	mov    rdx,rax
    15f9:	49 39 c4             	cmp    r12,rax
    15fc:	72 73                	jb     1671 <lab02_rle_decode+0x111>
    15fe:	48 83 c1 02          	add    rcx,0x2
    1602:	84 c0                	test   al,al
    1604:	74 dd                	je     15e3 <lab02_rle_decode+0x83>
    1606:	44 0f b6 64 0f ff    	movzx  r12d,BYTE PTR [rdi+rcx*1-0x1]
    160c:	4d 8d 2c 31          	lea    r13,[r9+rsi*1]
    1610:	4d 0f af e3          	imul   r12,r11
    1614:	66 49 0f 6e c4       	movq   xmm0,r12
    1619:	66 0f 6c c0          	punpcklqdq xmm0,xmm0
    161d:	83 f8 40             	cmp    eax,0x40
    1620:	72 86                	jb     15a8 <lab02_rle_decode+0x48>
    1622:	42 0f 11 44 28 c0    	movups XMMWORD PTR [rax+r13*1-0x40],xmm0
    1628:	42 0f 11 44 28 d0    	movups XMMWORD PTR [rax+r13*1-0x30],xmm0
    162e:	42 0f 11 44 28 e0    	movups XMMWORD PTR [rax+r13*1-0x20],xmm0
    1634:	42 0f 11 44 28 f0    	movups XMMWORD PTR [rax+r13*1-0x10],xmm0
    163a:	83 e8 01             	sub    eax,0x1
    163d:	83 f8 40             	cmp    eax,0x40
    1640:	72 96                	jb     15d8 <lab02_rle_decode+0x78>
    1642:	83 e0 c0             	and    eax,0xffffffc0
    1645:	45 31 e4             	xor    r12d,r12d
    1648:	45 89 e6             	mov    r14d,r12d
    164b:	41 83 c4 40          	add    r12d,0x40
    164f:	43 0f 11 44 35 00    	movups XMMWORD PTR [r13+r14*1+0x0],xmm0
    1655:	43 0f 11 44 35 10    	movups XMMWORD PTR [r13+r14*1+0x10],xmm0
    165b:	43 0f 11 44 35 20    	movups XMMWORD PTR [r13+r14*1+0x20],xmm0
    1661:	43 0f 11 44 35 30    	movups XMMWORD PTR [r13+r14*1+0x30],xmm0
    1667:	41 39 c4             	cmp    r12d,eax
    166a:	72 dc                	jb     1648 <lab02_rle_decode+0xe8>
    166c:	e9 67 ff ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    1671:	48 c7 c6 ff ff ff ff 	mov    rsi,0xffffffffffffffff
    1678:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    167c:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    1680:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    1684:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    1688:	48 89 f0             	mov    rax,rsi
    168b:	c9                   	leave
    168c:	c3                   	ret
    168d:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    1691:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    1695:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    1699:	4c 39 c3             	cmp    rbx,r8
    169c:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
    16a3:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    16a7:	c9                   	leave
    16a8:	48 0f 45 f0          	cmovne rsi,rax
    16ac:	48 89 f0             	mov    rax,rsi
    16af:	c3                   	ret
    16b0:	41 0f 11 45 00       	movups XMMWORD PTR [r13+0x0],xmm0
    16b5:	41 0f 11 45 10       	movups XMMWORD PTR [r13+0x10],xmm0
    16ba:	42 0f 11 44 28 e0    	movups XMMWORD PTR [rax+r13*1-0x20],xmm0
    16c0:	42 0f 11 44 28 f0    	movups XMMWORD PTR [rax+r13*1-0x10],xmm0
    16c6:	e9 0d ff ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    16cb:	41 0f 11 45 00       	movups XMMWORD PTR [r13+0x0],xmm0
    16d0:	42 0f 11 44 28 f0    	movups XMMWORD PTR [rax+r13*1-0x10],xmm0
    16d6:	e9 fd fe ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    16db:	4d 89 65 00          	mov    QWORD PTR [r13+0x0],r12
    16df:	4e 89 64 28 f8       	mov    QWORD PTR [rax+r13*1-0x8],r12
    16e4:	e9 ef fe ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    16e9:	45 89 65 00          	mov    DWORD PTR [r13+0x0],r12d
    16ed:	46 89 64 28 fc       	mov    DWORD PTR [rax+r13*1-0x4],r12d
    16f2:	e9 e1 fe ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    16f7:	66 46 89 64 28 fe    	mov    WORD PTR [rax+r13*1-0x2],r12w
    16fd:	e9 d6 fe ff ff       	jmp    15d8 <lab02_rle_decode+0x78>
    1702:	31 f6                	xor    esi,esi
    1704:	45 31 c0             	xor    r8d,r8d
    1707:	eb 90                	jmp    1699 <lab02_rle_decode+0x139>

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xc0b7e950
 RBX  0xc0b7e950
 RCX  6
 RDX  0x7fffffffe08f ◂— 0x301430142024103
 RDI  0x7fffffffe0f0 ◂— 0
 RSI  0x20
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffdf98 —▸ 0x555555555235 (main+437) ◂— lea rdi, [rbp - 0xb0]
 RIP  0x555555555560 (lab02_rle_decode) ◂— push rbp
   0x555555555561 <lab02_rle_decode+1>     mov    rbp, rsp                        RBP => 0x7fffffffdf90 —▸ 0x7fffffffe150 —▸ 0x7fffffffe200 —▸ 0x7fffffffe260 ◂— ...
   0x555555555564 <lab02_rle_decode+4>     sub    rsp, 0x20                       RSP => 0x7fffffffdf70 (0x7fffffffdf90 - 0x20)
   0x555555555568 <lab02_rle_decode+8>     mov    qword ptr [rbp - 0x20], rbx     [0x7fffffffdf70] <= 0xc0b7e950
   0x55555555556c <lab02_rle_decode+12>    mov    rbx, rcx                        RBX => 6
   0x55555555556f <lab02_rle_decode+15>    cmp    rcx, 1                          6 - 1     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555573 <lab02_rle_decode+19>  ✘ jbe    lab02_rle_decode+418        <lab02_rle_decode+418>
   0x555555555579 <lab02_rle_decode+25>    mov    r8, rcx                         R8 => 6
   0x55555555557c <lab02_rle_decode+28>    mov    r9, rdi                         R9 => 0x7fffffffe0f0 ◂— 0
   0x55555555557f <lab02_rle_decode+31>    mov    r10, rsi                        R10 => 0x20
   0x555555555582 <lab02_rle_decode+34>    mov    qword ptr [rbp - 0x18], r12     [0x7fffffffdf78] <= 3
=> 0x555555555560 <lab02_rle_decode>:	push   rbp
   0x555555555561 <lab02_rle_decode+1>:	mov    rbp,rsp
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab02_rle_decode` with entry RVA `0x1560`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 03 — Binary header validator

## Question and target

Given only stripped function `FUN_00101710`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Work backward from return codes through magic comparison, little-endian field loads, version gate, payload-length check, and minimum header size. Recover a tentative on-disk structure.

```c
FUNCTION FUN_00101710
ENTRY 00101710
SIGNATURE undefined FUN_00101710(void)
CALLERS 0010211c, 00102284, 00101244

ulong FUN_00101710(int *param_1,ulong param_2)

{
  if ((param_2 < 0xc) || (*param_1 != 0x31564552)) {
    return 0xffffffff;
  }
  if (((short)param_1[1] == 3) && ((ulong)(uint)param_1[2] <= param_2 - 0xc)) {
    return (ulong)(uint)param_1[2];
  }
  return 0xfffffffe;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001710 <lab03_validate_header>:
    1710:	48 83 fe 0b          	cmp    rsi,0xb
    1714:	76 22                	jbe    1738 <lab03_validate_header+0x28>
    1716:	81 3f 52 45 56 31    	cmp    DWORD PTR [rdi],0x31564552
    171c:	75 1a                	jne    1738 <lab03_validate_header+0x28>
    171e:	66 83 7f 04 03       	cmp    WORD PTR [rdi+0x4],0x3
    1723:	75 1b                	jne    1740 <lab03_validate_header+0x30>
    1725:	8b 57 08             	mov    edx,DWORD PTR [rdi+0x8]
    1728:	48 83 ee 0c          	sub    rsi,0xc
    172c:	48 89 d0             	mov    rax,rdx
    172f:	48 39 d6             	cmp    rsi,rdx
    1732:	72 0c                	jb     1740 <lab03_validate_header+0x30>
    1734:	c3                   	ret
    1735:	0f 1f 00             	nop    DWORD PTR [rax]
    1738:	b8 ff ff ff ff       	mov    eax,0xffffffff
    173d:	c3                   	ret
    173e:	66 90                	xchg   ax,ax
    1740:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1745:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  6
 RBX  0xc0b7e950
 RCX  6
 RDX  0
 RDI  0x7fffffffe0a0 ◂— 0x331564552
 RSI  0x10
 R8   6
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x555555555249 (main+457) ◂— lea rdi, [rip + 0xdb4]
 RIP  0x555555555710 (lab03_validate_header) ◂— cmp rsi, 0xb
   0x555555555714 <lab03_validate_header+4>   ✘ jbe    lab03_validate_header+40    <lab03_validate_header+40>
   0x555555555716 <lab03_validate_header+6>     cmp    dword ptr [rdi], 0x31564552     0x31564552 - 0x31564552     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x55555555571c <lab03_validate_header+12>  ✘ jne    lab03_validate_header+40    <lab03_validate_header+40>
   0x55555555571e <lab03_validate_header+14>    cmp    word ptr [rdi + 4], 3           3 - 3     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555723 <lab03_validate_header+19>  ✘ jne    lab03_validate_header+48    <lab03_validate_header+48>
   0x555555555725 <lab03_validate_header+21>    mov    edx, dword ptr [rdi + 8]        EDX, [0x7fffffffe0a8] => 4
   0x555555555728 <lab03_validate_header+24>    sub    rsi, 0xc                        RSI => 4 (0x10 - 0xc)
   0x55555555572c <lab03_validate_header+28>    mov    rax, rdx                        RAX => 4
   0x55555555572f <lab03_validate_header+31>    cmp    rsi, rdx                        4 - 4     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555732 <lab03_validate_header+34>  ✘ jb     lab03_validate_header+48    <lab03_validate_header+48>
=> 0x555555555710 <lab03_validate_header>:	cmp    rsi,0xb
   0x555555555714 <lab03_validate_header+4>:	jbe    0x555555555738 <lab03_validate_header+40>
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab03_validate_header` with entry RVA `0x1710`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 04 — Protocol state machine

## Question and target

Given only stripped function `FUN_00101750`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Convert a flattened switch-like character parser into states, transition conditions, numeric accumulation, terminal delimiter, and rejection states. Validate with accepted and rejected strings.

```c
FUNCTION FUN_00101750
ENTRY 00101750
SIGNATURE undefined FUN_00101750(void)
CALLERS 00102124, 00102298, 00101262

int FUN_00101750(char *param_1)

{
  char *pcVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  char *pcVar5;

  if (((*param_1 != '\0') && (*param_1 == 'U')) && (cVar2 = param_1[1], cVar2 != '\0')) {
    while (cVar2 != ' ') {
      if (0x19 < (byte)(cVar2 + 0xbfU)) {
        return -1;
      }
      cVar2 = param_1[2];
      param_1 = param_1 + 1;
      if (cVar2 == '\0') {
        return -1;
      }
    }
    if ((param_1[2] != '\0') && (bVar3 = param_1[2] - 0x30, bVar3 < 10)) {
      pcVar5 = param_1 + 3;
      cVar2 = param_1[3];
      iVar4 = (int)(char)bVar3;
      if (cVar2 != '\0') {
        while( true ) {
          if (9 < (byte)(cVar2 - 0x30U)) {
            if (cVar2 != ';') {
              iVar4 = -1;
            }
            return iVar4;
          }
          pcVar1 = pcVar5 + 1;
          pcVar5 = pcVar5 + 1;
          if (*pcVar1 == '\0') break;
          iVar4 = (int)(char)(cVar2 + -0x30) + iVar4 * 10;
          cVar2 = *pcVar1;
        }
      }
    }
  }
  return -1;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001750 <lab04_protocol_state>:
    1750:	0f b6 07             	movzx  eax,BYTE PTR [rdi]
    1753:	84 c0                	test   al,al
    1755:	74 04                	je     175b <lab04_protocol_state+0xb>
    1757:	3c 55                	cmp    al,0x55
    1759:	74 0d                	je     1768 <lab04_protocol_state+0x18>
    175b:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1760:	c3                   	ret
    1761:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1768:	0f b6 47 01          	movzx  eax,BYTE PTR [rdi+0x1]
    176c:	48 8d 57 01          	lea    rdx,[rdi+0x1]
    1770:	84 c0                	test   al,al
    1772:	74 e7                	je     175b <lab04_protocol_state+0xb>
    1774:	3c 20                	cmp    al,0x20
    1776:	74 17                	je     178f <lab04_protocol_state+0x3f>
    1778:	83 e8 41             	sub    eax,0x41
    177b:	3c 19                	cmp    al,0x19
    177d:	77 dc                	ja     175b <lab04_protocol_state+0xb>
    177f:	0f b6 42 01          	movzx  eax,BYTE PTR [rdx+0x1]
    1783:	48 83 c2 01          	add    rdx,0x1
    1787:	84 c0                	test   al,al
    1789:	74 d0                	je     175b <lab04_protocol_state+0xb>
    178b:	3c 20                	cmp    al,0x20
    178d:	75 e9                	jne    1778 <lab04_protocol_state+0x28>
    178f:	0f b6 42 01          	movzx  eax,BYTE PTR [rdx+0x1]
    1793:	84 c0                	test   al,al
    1795:	74 c4                	je     175b <lab04_protocol_state+0xb>
    1797:	83 e8 30             	sub    eax,0x30
    179a:	3c 09                	cmp    al,0x9
    179c:	77 bd                	ja     175b <lab04_protocol_state+0xb>
    179e:	48 8d 7a 02          	lea    rdi,[rdx+0x2]
    17a2:	0f b6 52 02          	movzx  edx,BYTE PTR [rdx+0x2]
    17a6:	0f be c0             	movsx  eax,al
    17a9:	89 d1                	mov    ecx,edx
    17ab:	84 d2                	test   dl,dl
    17ad:	74 ac                	je     175b <lab04_protocol_state+0xb>
    17af:	8d 71 d0             	lea    esi,[rcx-0x30]
    17b2:	40 80 fe 09          	cmp    sil,0x9
    17b6:	77 23                	ja     17db <lab04_protocol_state+0x8b>
    17b8:	0f b6 4f 01          	movzx  ecx,BYTE PTR [rdi+0x1]
    17bc:	48 83 c7 01          	add    rdi,0x1
    17c0:	84 c9                	test   cl,cl
    17c2:	74 97                	je     175b <lab04_protocol_state+0xb>
    17c4:	83 ea 30             	sub    edx,0x30
    17c7:	8d 04 80             	lea    eax,[rax+rax*4]
    17ca:	8d 71 d0             	lea    esi,[rcx-0x30]
    17cd:	0f be d2             	movsx  edx,dl
    17d0:	8d 04 42             	lea    eax,[rdx+rax*2]
    17d3:	89 ca                	mov    edx,ecx
    17d5:	40 80 fe 09          	cmp    sil,0x9
    17d9:	76 dd                	jbe    17b8 <lab04_protocol_state+0x68>
    17db:	80 f9 3b             	cmp    cl,0x3b
    17de:	ba ff ff ff ff       	mov    edx,0xffffffff
    17e3:	0f 45 c2             	cmovne eax,edx
    17e6:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  4
 RBX  0xc0b7e95a
 RCX  6
 RDX  4
 RDI  0x7fffffffe674 ◂— 0x3939390052455355 /* 'USER' */
 RSI  4
 R8   6
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x555555555267 (main+487) ◂— mov edx, 0x17
 RIP  0x555555555750 (lab04_protocol_state) ◂— movzx eax, byte ptr [rdi]
   0x555555555753 <lab04_protocol_state+3>     test   al, al                  0x55 & 0x55     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555755 <lab04_protocol_state+5>   ✘ je     lab04_protocol_state+11     <lab04_protocol_state+11>
   0x555555555757 <lab04_protocol_state+7>     cmp    al, 0x55                0x55 - 0x55     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555759 <lab04_protocol_state+9>   ✔ je     lab04_protocol_state+24     <lab04_protocol_state+24>
   0x555555555768 <lab04_protocol_state+24>    movzx  eax, byte ptr [rdi + 1]     EAX, [0x7fffffffe675] => 0x53
   0x55555555576c <lab04_protocol_state+28>    lea    rdx, [rdi + 1]              RDX => 0x7fffffffe675 ◂— 0x39393900524553 /* 'SER' */
   0x555555555770 <lab04_protocol_state+32>    test   al, al                      0x53 & 0x53     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555772 <lab04_protocol_state+34>  ✘ je     lab04_protocol_state+11     <lab04_protocol_state+11>
   0x555555555774 <lab04_protocol_state+36>    cmp    al, 0x20                    0x53 - 0x20     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555776 <lab04_protocol_state+38>  ✘ je     lab04_protocol_state+63     <lab04_protocol_state+63>
=> 0x555555555750 <lab04_protocol_state>:	movzx  eax,BYTE PTR [rdi]
   0x555555555753 <lab04_protocol_state+3>:	test   al,al
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab04_protocol_state` with entry RVA `0x1750`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 05 — Lower-bound binary search

## Question and target

Given only stripped function `FUN_001017f0`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recognize half-open interval semantics, overflow-resistant midpoint, lower-bound update rules, and the final equality test. Distinguish this from the classic immediate-return binary search.

```c
FUNCTION FUN_001017f0
ENTRY 001017f0
SIGNATURE undefined FUN_001017f0(void)
CALLERS 0010212c, 001022ac, 0010127b

ulong FUN_001017f0(long param_1,ulong param_2,int param_3)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;

  uVar1 = 0;
  uVar3 = param_2;
  while (uVar2 = uVar3, uVar1 < uVar2) {
    uVar3 = (uVar2 - uVar1 >> 1) + uVar1;
    if (*(int *)(param_1 + uVar3 * 4) < param_3) {
      uVar1 = uVar3 + 1;
      uVar3 = uVar2;
    }
  }
  if ((uVar1 < param_2) && (*(int *)(param_1 + uVar1 * 4) == param_3)) {
    return uVar1;
  }
  return 0xffffffff;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017f0 <lab05_binary_search>:
    17f0:	49 89 f0             	mov    r8,rsi
    17f3:	31 c0                	xor    eax,eax
    17f5:	89 d6                	mov    esi,edx
    17f7:	4c 89 c1             	mov    rcx,r8
    17fa:	eb 18                	jmp    1814 <lab05_binary_search+0x24>
    17fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1800:	48 89 ca             	mov    rdx,rcx
    1803:	48 29 c2             	sub    rdx,rax
    1806:	48 d1 ea             	shr    rdx,1
    1809:	48 01 c2             	add    rdx,rax
    180c:	39 34 97             	cmp    DWORD PTR [rdi+rdx*4],esi
    180f:	7c 17                	jl     1828 <lab05_binary_search+0x38>
    1811:	48 89 d1             	mov    rcx,rdx
    1814:	48 39 c8             	cmp    rax,rcx
    1817:	72 e7                	jb     1800 <lab05_binary_search+0x10>
    1819:	4c 39 c0             	cmp    rax,r8
    181c:	73 10                	jae    182e <lab05_binary_search+0x3e>
    181e:	39 34 87             	cmp    DWORD PTR [rdi+rax*4],esi
    1821:	75 0b                	jne    182e <lab05_binary_search+0x3e>
    1823:	c3                   	ret
    1824:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1828:	48 8d 42 01          	lea    rax,[rdx+0x1]
    182c:	eb e6                	jmp    1814 <lab05_binary_search+0x24>
    182e:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1833:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xffffffff
 RBX  0xc0b7e95a
 RCX  6
 RDX  0x17
 RDI  0x7fffffffe020 ◂— 0x400000001
 RSI  7
 R8   6
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x555555555280 (main+512) ◂— lea rdi, [rbp - 0x170]
 RIP  0x5555555557f0 (lab05_binary_search) ◂— mov r8, rsi
   0x5555555557f3 <lab05_binary_search+3>     xor    eax, eax     EAX => 0
   0x5555555557f5 <lab05_binary_search+5>     mov    esi, edx     ESI => 0x17
   0x5555555557f7 <lab05_binary_search+7>     mov    rcx, r8      RCX => 7
   0x5555555557fa <lab05_binary_search+10>    jmp    lab05_binary_search+36      <lab05_binary_search+36>
   0x555555555814 <lab05_binary_search+36>    cmp    rax, rcx     0 - 7     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ac ]
   0x555555555817 <lab05_binary_search+39>  ✔ jb     lab05_binary_search+16      <lab05_binary_search+16>
   0x555555555800 <lab05_binary_search+16>    mov    rdx, rcx     RDX => 7
   0x555555555803 <lab05_binary_search+19>    sub    rdx, rax     RDX => 7 (7 - 0)
   0x555555555806 <lab05_binary_search+22>    shr    rdx, 1
   0x555555555809 <lab05_binary_search+25>    add    rdx, rax     RDX => 3 (3 + 0)
=> 0x5555555557f0 <lab05_binary_search>:	mov    r8,rsi
   0x5555555557f3 <lab05_binary_search+3>:	xor    eax,eax
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab05_binary_search` with entry RVA `0x17f0`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 06 — Linked-list structure recovery

## Question and target

Given only stripped function `FUN_00101840`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Infer Node offsets from next-pointer traversal, key mask test, and signed value accumulation. Validate alignment and structure size across the caller’s stack construction.

```c
FUNCTION FUN_00101840
ENTRY 00101840
SIGNATURE undefined FUN_00101840(void)
CALLERS 00102134, 001022c0, 00101296

int FUN_00101840(uint *param_1,uint param_2)

{
  int iVar1;

  iVar1 = 0;
  for (; param_1 != (uint *)0x0; param_1 = *(uint **)(param_1 + 2)) {
    if (param_2 == (*param_1 & param_2)) {
      iVar1 = iVar1 + param_1[1];
    }
  }
  return iVar1;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001840 <lab06_list_accumulate>:
    1840:	31 d2                	xor    edx,edx
    1842:	48 85 ff             	test   rdi,rdi
    1845:	74 2d                	je     1874 <lab06_list_accumulate+0x34>
    1847:	0f 1f 00             	nop    DWORD PTR [rax]
    184a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1851:	00 00 00 00
    1855:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    185c:	00 00 00 00
    1860:	8b 07                	mov    eax,DWORD PTR [rdi]
    1862:	21 f0                	and    eax,esi
    1864:	39 c6                	cmp    esi,eax
    1866:	75 03                	jne    186b <lab06_list_accumulate+0x2b>
    1868:	03 57 04             	add    edx,DWORD PTR [rdi+0x4]
    186b:	48 8b 7f 08          	mov    rdi,QWORD PTR [rdi+0x8]
    186f:	48 85 ff             	test   rdi,rdi
    1872:	75 ec                	jne    1860 <lab06_list_accumulate+0x20>
    1874:	89 d0                	mov    eax,edx
    1876:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  5
 RBX  0xc0b7e95a
 RCX  0x555555555520 (mul_op) ◂— mov eax, edi
 RDX  4
 RDI  0x7fffffffdfe0 ◂— 0xa00000003
 RSI  2
 R8   7
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x55555555529b (main+539) ◂— mov edx, 1
 RIP  0x555555555840 (lab06_list_accumulate) ◂— xor edx, edx
   0x555555555842 <lab06_list_accumulate+2>     test   rdi, rdi     0x7fffffffdfe0 & 0x7fffffffdfe0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555845 <lab06_list_accumulate+5>   ✘ je     lab06_list_accumulate+52    <lab06_list_accumulate+52>
   0x555555555847 <lab06_list_accumulate+7>     nop    dword ptr [rax]
   0x55555555584a <lab06_list_accumulate+10>    nop    word ptr [rax + rax]
   0x555555555855 <lab06_list_accumulate+21>    nop    word ptr [rax + rax]
   0x555555555860 <lab06_list_accumulate+32>    mov    eax, dword ptr [rdi]     EAX, [0x7fffffffdfe0] => 3
   0x555555555862 <lab06_list_accumulate+34>    and    eax, esi                 EAX => 2 (3 & 2)
   0x555555555864 <lab06_list_accumulate+36>    cmp    esi, eax                 2 - 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555866 <lab06_list_accumulate+38>  ✘ jne    lab06_list_accumulate+43    <lab06_list_accumulate+43>
   0x555555555868 <lab06_list_accumulate+40>    add    edx, dword ptr [rdi + 4]     EDX => 0xa (0x0 + 0xa)
=> 0x555555555840 <lab06_list_accumulate>:	xor    edx,edx
   0x555555555842 <lab06_list_accumulate+2>:	test   rdi,rdi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab06_list_accumulate` with entry RVA `0x1840`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 07 — Callback ABI recovery

## Question and target

Given only stripped function `FUN_00101880`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover the fourth parameter as a function pointer, identify its two integer arguments and return value, and reconstruct a generic fold. Prove behavior by observing the target change among add/xor/multiply callbacks.

```c
FUNCTION FUN_00101880
ENTRY 00101880
SIGNATURE undefined FUN_00101880(void)
CALLERS 0010213c, 001022d4, 001012af

undefined4 FUN_00101880(long param_1,long param_2,undefined4 param_3,code *param_4)

{
  long lVar1;
  long lVar2;

  if (param_2 != 0) {
    lVar2 = 0;
    do {
      lVar1 = lVar2 * 4;
      lVar2 = lVar2 + 1;
      param_3 = (*param_4)(param_3,*(undefined4 *)(param_1 + lVar1));
    } while (param_2 != lVar2);
  }
  return param_3;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001880 <lab07_callback_fold>:
    1880:	55                   	push   rbp
    1881:	48 89 e5             	mov    rbp,rsp
    1884:	48 83 ec 20          	sub    rsp,0x20
    1888:	4c 89 75 f8          	mov    QWORD PTR [rbp-0x8],r14
    188c:	49 89 fe             	mov    r14,rdi
    188f:	89 d7                	mov    edi,edx
    1891:	48 85 f6             	test   rsi,rsi
    1894:	74 38                	je     18ce <lab07_callback_fold+0x4e>
    1896:	48 89 5d e0          	mov    QWORD PTR [rbp-0x20],rbx
    189a:	31 db                	xor    ebx,ebx
    189c:	4c 89 65 e8          	mov    QWORD PTR [rbp-0x18],r12
    18a0:	49 89 f4             	mov    r12,rsi
    18a3:	4c 89 6d f0          	mov    QWORD PTR [rbp-0x10],r13
    18a7:	49 89 cd             	mov    r13,rcx
    18aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    18b0:	41 8b 34 9e          	mov    esi,DWORD PTR [r14+rbx*4]
    18b4:	48 83 c3 01          	add    rbx,0x1
    18b8:	41 ff d5             	call   r13
    18bb:	89 c7                	mov    edi,eax
    18bd:	49 39 dc             	cmp    r12,rbx
    18c0:	75 ee                	jne    18b0 <lab07_callback_fold+0x30>
    18c2:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    18c6:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    18ca:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    18ce:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    18d2:	89 f8                	mov    eax,edi
    18d4:	c9                   	leave
    18d5:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0x3c
 RBX  0xc0b7e95a
 RCX  0x555555555520 (mul_op) ◂— mov eax, edi
 RDX  1
 RDI  0x7fffffffdff0 ◂— 0x300000002
 RSI  4
 R8   7
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x5555555552b4 (main+564) ◂— mov edi, 0xabcde123
 RIP  0x555555555880 (lab07_callback_fold) ◂— push rbp
   0x555555555881 <lab07_callback_fold+1>     mov    rbp, rsp                     RBP => 0x7fffffffdf90 —▸ 0x7fffffffe150 —▸ 0x7fffffffe200 —▸ 0x7fffffffe260 ◂— ...
   0x555555555884 <lab07_callback_fold+4>     sub    rsp, 0x20                    RSP => 0x7fffffffdf70 (0x7fffffffdf90 - 0x20)
   0x555555555888 <lab07_callback_fold+8>     mov    qword ptr [rbp - 8], r14     [0x7fffffffdf88] <= 5
   0x55555555588c <lab07_callback_fold+12>    mov    r14, rdi                     R14 => 0x7fffffffdff0 ◂— 0x300000002
   0x55555555588f <lab07_callback_fold+15>    mov    edi, edx                     EDI => 1
   0x555555555891 <lab07_callback_fold+17>    test   rsi, rsi                     4 & 4     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555894 <lab07_callback_fold+20>  ✘ je     lab07_callback_fold+78      <lab07_callback_fold+78>
   0x555555555896 <lab07_callback_fold+22>    mov    qword ptr [rbp - 0x20], rbx     [0x7fffffffdf70] <= 0xc0b7e95a
   0x55555555589a <lab07_callback_fold+26>    xor    ebx, ebx                        EBX => 0
   0x55555555589c <lab07_callback_fold+28>    mov    qword ptr [rbp - 0x18], r12     [0x7fffffffdf78] <= 3
=> 0x555555555880 <lab07_callback_fold>:	push   rbp
   0x555555555881 <lab07_callback_fold+1>:	mov    rbp,rsp
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab07_callback_fold` with entry RVA `0x1880`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 08 — Packed bitfield decoding

## Question and target

Given only stripped function `FUN_001018e0`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Translate shifts, masks, multiply-by-33 optimization, and XOR combination into named logical fields. Preserve unsigned 32-bit semantics.

```c
FUNCTION FUN_001018e0
ENTRY 001018e0
SIGNATURE undefined FUN_001018e0(void)
CALLERS 00102144, 00102304, 001012c1

uint FUN_001018e0(uint param_1)

{
  return param_1 >> 0xc & 0xffff ^ param_1 & 7 ^ (param_1 >> 3 & 0x1ff) * 0x21;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000018e0 <lab08_unpack_flags>:
    18e0:	89 f8                	mov    eax,edi
    18e2:	89 fa                	mov    edx,edi
    18e4:	c1 ef 03             	shr    edi,0x3
    18e7:	c1 e8 0c             	shr    eax,0xc
    18ea:	83 e2 07             	and    edx,0x7
    18ed:	81 e7 ff 01 00 00    	and    edi,0x1ff
    18f3:	0f b7 c0             	movzx  eax,ax
    18f6:	31 d0                	xor    eax,edx
    18f8:	89 fa                	mov    edx,edi
    18fa:	c1 e2 05             	shl    edx,0x5
    18fd:	01 fa                	add    edx,edi
    18ff:	31 d0                	xor    eax,edx
    1901:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xd2
 RBX  0xc0b7e95a
 RCX  0x555555555520 (mul_op) ◂— mov eax, edi
 RDX  1
 RDI  0xabcde123
 RSI  0x55
 R8   7
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x5555555552c6 (main+582) ◂— mov edx, 0xaa
 RIP  0x5555555558e0 (lab08_unpack_flags) ◂— mov eax, edi
   0x5555555558e2 <lab08_unpack_flags+2>     mov    edx, edi       EDX => 0xabcde123
   0x5555555558e4 <lab08_unpack_flags+4>     shr    edi, 3
   0x5555555558e7 <lab08_unpack_flags+7>     shr    eax, 0xc
   0x5555555558ea <lab08_unpack_flags+10>    and    edx, 7         EDX => 3 (0xabcde123 & 0x7)
   0x5555555558ed <lab08_unpack_flags+13>    and    edi, 0x1ff     EDI => 0x24 (0x1579bc24 & 0x1ff)
   0x5555555558f3 <lab08_unpack_flags+19>    movzx  eax, ax        EAX => 0xbcde
   0x5555555558f6 <lab08_unpack_flags+22>    xor    eax, edx       EAX => 0xbcdd (0xbcde ^ 0x3)
   0x5555555558f8 <lab08_unpack_flags+24>    mov    edx, edi       EDX => 0x24
   0x5555555558fa <lab08_unpack_flags+26>    shl    edx, 5
   0x5555555558fd <lab08_unpack_flags+29>    add    edx, edi       EDX => 0x4a4 (0x480 + 0x24)
=> 0x5555555558e0 <lab08_unpack_flags>:	mov    eax,edi
   0x5555555558e2 <lab08_unpack_flags+2>:	mov    edx,edi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab08_unpack_flags` with entry RVA `0x18e0`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 09 — Function-pointer dispatcher

## Question and target

Given only stripped function `FUN_00101910`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover an opcode bounds check, table base, pointer-sized stride, indirect call, and shared callback signature. Determine invalid-opcode behavior without executing out of bounds.

```c
FUNCTION FUN_00101910
ENTRY 00101910
SIGNATURE undefined FUN_00101910(void)
CALLERS 0010214c, 00102318, 001012d6

uint FUN_00101910(undefined4 param_1,uint param_2,uint param_3)

{
  switch(param_1) {
  case 0:
    return param_2 + param_3;
  case 1:
    return param_2 ^ param_3;
  case 2:
    return param_2 * param_3;
  default:
    return 0xffffffff;
  }
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001910 <lab09_dispatch>:
    1910:	83 ff 02             	cmp    edi,0x2
    1913:	77 1b                	ja     1930 <lab09_dispatch+0x20>
    1915:	89 ff                	mov    edi,edi
    1917:	48 8d 0d a2 24 00 00 	lea    rcx,[rip+0x24a2]        # 3dc0 <table.0>
    191e:	48 8b 0c f9          	mov    rcx,QWORD PTR [rcx+rdi*8]
    1922:	89 f7                	mov    edi,esi
    1924:	89 d6                	mov    esi,edx
    1926:	ff e1                	jmp    rcx
    1928:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    192f:	00
    1930:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1935:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xb879
 RBX  0xc0b7e95a
 RCX  0x555555555520 (mul_op) ◂— mov eax, edi
 RDX  0xaa
 RDI  1
 RSI  0x55
 R8   7
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x5555555552db (main+603) ◂— mov edi, 0x13
 RIP  0x555555555910 (lab09_dispatch) ◂— cmp edi, 2
   0x555555555913 <lab09_dispatch+3>   ✘ ja     lab09_dispatch+32           <lab09_dispatch+32>
   0x555555555915 <lab09_dispatch+5>     mov    edi, edi                         EDI => 1
   0x555555555917 <lab09_dispatch+7>     lea    rcx, [rip + 0x24a2]              RCX => 0x555555557dc0 (table) —▸ 0x555555555500 (add_op) ◂— lea eax, [rdi + rsi]
   0x55555555591e <lab09_dispatch+14>    mov    rcx, qword ptr [rcx + rdi*8]     RCX, [table+8] => 0x555555555510 (xor_op) ◂— mov eax, edi
   0x555555555922 <lab09_dispatch+18>    mov    edi, esi                         EDI => 0x55
   0x555555555924 <lab09_dispatch+20>    mov    esi, edx                         ESI => 0xaa
   0x555555555926 <lab09_dispatch+22>    jmp    rcx                         <xor_op>
   0x555555555510 <xor_op>               mov    eax, edi     EAX => 0x55
   0x555555555512 <xor_op+2>             xor    eax, esi     EAX => 0xff (0x55 ^ 0xaa)
   0x555555555514 <xor_op+4>             ret                                <main+603>
=> 0x555555555910 <lab09_dispatch>:	cmp    edi,0x2
   0x555555555913 <lab09_dispatch+3>:	ja     0x555555555930 <lab09_dispatch+32>
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab09_dispatch` with entry RVA `0x1910`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 10 — Recursive nonlinear mixer

## Question and target

Given only stripped function `FUN_00101940`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Identify the base case, argument halving, recursive result, rotate-like expression, multiplication constant, and operator-precedence artifact. Use repeated breakpoint entries to reconstruct the call tree.

```c
FUNCTION FUN_00101940
ENTRY 00101940
SIGNATURE undefined FUN_00101940(void)
CALLERS 00102154, 0010232c, 001012e3, 00101955

ulong FUN_00101940(uint param_1)

{
  ulong uVar1;

  if (1 < param_1) {
    uVar1 = FUN_00101940(param_1 >> 1);
    return uVar1 >> 0x39 ^ (ulong)param_1 * 0x100000001b3 | uVar1 << 7;
  }
  return (ulong)param_1 ^ 0x9e3779b97f4a7c15;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001940 <lab10_recursive_mix>:
    1940:	89 fa                	mov    edx,edi
    1942:	83 ff 01             	cmp    edi,0x1
    1945:	76 39                	jbe    1980 <lab10_recursive_mix+0x40>
    1947:	55                   	push   rbp
    1948:	d1 ef                	shr    edi,1
    194a:	48 89 e5             	mov    rbp,rsp
    194d:	48 83 ec 10          	sub    rsp,0x10
    1951:	48 89 55 f8          	mov    QWORD PTR [rbp-0x8],rdx
    1955:	e8 e6 ff ff ff       	call   1940 <lab10_recursive_mix>
    195a:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    195e:	48 be b3 01 00 00 00 	movabs rsi,0x100000001b3
    1965:	01 00 00
    1968:	c9                   	leave
    1969:	48 89 c1             	mov    rcx,rax
    196c:	48 c1 e8 39          	shr    rax,0x39
    1970:	48 0f af d6          	imul   rdx,rsi
    1974:	48 c1 e1 07          	shl    rcx,0x7
    1978:	48 31 d0             	xor    rax,rdx
    197b:	48 09 c8             	or     rax,rcx
    197e:	c3                   	ret
    197f:	90                   	nop
    1980:	48 b8 15 7c 4a 7f b9 	movabs rax,0x9e3779b97f4a7c15
    1987:	79 37 9e
    198a:	48 31 d0             	xor    rax,rdx
    198d:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xff
 RBX  0xc0b7e95a
 RCX  0x555555555510 (xor_op) ◂— mov eax, edi
 RDX  0xaa
 RDI  0x13
 RSI  0xaa
 R8   0xff
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x5555555552e8 (main+616) ◂— lea rdi, [rbp - 0x110]
 RIP  0x555555555940 (lab10_recursive_mix) ◂— mov edx, edi
   0x555555555942 <lab10_recursive_mix+2>     cmp    edi, 1       0x13 - 0x1     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555945 <lab10_recursive_mix+5>   ✘ jbe    lab10_recursive_mix+64      <lab10_recursive_mix+64>
   0x555555555947 <lab10_recursive_mix+7>     push   rbp
   0x555555555948 <lab10_recursive_mix+8>     shr    edi, 1
   0x55555555594a <lab10_recursive_mix+10>    mov    rbp, rsp                     RBP => 0x7fffffffdf90 —▸ 0x7fffffffe150 —▸ 0x7fffffffe200 —▸ 0x7fffffffe260 ◂— ...
   0x55555555594d <lab10_recursive_mix+13>    sub    rsp, 0x10                    RSP => 0x7fffffffdf80 (0x7fffffffdf90 - 0x10)
   0x555555555951 <lab10_recursive_mix+17>    mov    qword ptr [rbp - 8], rdx     [0x7fffffffdf88] <= 0x13
   0x555555555955 <lab10_recursive_mix+21>    call   lab10_recursive_mix         <lab10_recursive_mix>
   0x55555555595a <lab10_recursive_mix+26>    mov    rdx, qword ptr [rbp - 8]
   0x55555555595e <lab10_recursive_mix+30>    movabs rsi, 0x100000001b3           RSI => 0x100000001b3
=> 0x555555555940 <lab10_recursive_mix>:	mov    edx,edi
   0x555555555942 <lab10_recursive_mix+2>:	cmp    edi,0x1
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab10_recursive_mix` with entry RVA `0x1940`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 11 — Two-dimensional array indexing

## Question and target

Given only stripped function `FUN_00101990`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover a 4×4 row-major matrix from scale/stride arithmetic, diagonal condition, edge predicates, and final weighted score. Verify element width and row stride.

```c
FUNCTION FUN_00101990
ENTRY 00101990
SIGNATURE undefined FUN_00101990(void)
CALLERS 0010215c, 0010234c, 0010130b

int FUN_00101990(long param_1)

{
  long lVar1;
  long lVar2;
  int iVar3;
  int iVar4;

  lVar2 = 0;
  iVar3 = 0;
  iVar4 = 0;
  do {
    lVar1 = 0;
    do {
      if (lVar2 == lVar1) {
        iVar4 = iVar4 + *(int *)(param_1 + lVar2 * 4);
      }
      if (((9UL >> ((byte)lVar1 & 0x3f) | 9UL >> ((byte)lVar2 & 0x3f)) & 1) != 0) {
        iVar3 = iVar3 + *(int *)(param_1 + lVar1 * 4);
      }
      lVar1 = lVar1 + 1;
    } while (lVar1 != 4);
    lVar2 = lVar2 + 1;
    param_1 = param_1 + 0x10;
  } while (lVar2 != 4);
  return iVar4 * 7 - iVar3;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001990 <lab11_matrix_score>:
    1990:	31 d2                	xor    edx,edx
    1992:	31 f6                	xor    esi,esi
    1994:	45 31 d2             	xor    r10d,r10d
    1997:	41 b8 09 00 00 00    	mov    r8d,0x9
    199d:	89 d1                	mov    ecx,edx
    199f:	4d 89 c1             	mov    r9,r8
    19a2:	49 d3 e9             	shr    r9,cl
    19a5:	31 c9                	xor    ecx,ecx
    19a7:	48 39 ca             	cmp    rdx,rcx
    19aa:	74 3c                	je     19e8 <lab11_matrix_score+0x58>
    19ac:	4c 89 c0             	mov    rax,r8
    19af:	48 d3 e8             	shr    rax,cl
    19b2:	4c 09 c8             	or     rax,r9
    19b5:	a8 01                	test   al,0x1
    19b7:	74 03                	je     19bc <lab11_matrix_score+0x2c>
    19b9:	03 34 8f             	add    esi,DWORD PTR [rdi+rcx*4]
    19bc:	48 83 c1 01          	add    rcx,0x1
    19c0:	48 83 f9 04          	cmp    rcx,0x4
    19c4:	75 e1                	jne    19a7 <lab11_matrix_score+0x17>
    19c6:	48 83 c2 01          	add    rdx,0x1
    19ca:	48 83 c7 10          	add    rdi,0x10
    19ce:	48 83 fa 04          	cmp    rdx,0x4
    19d2:	75 c9                	jne    199d <lab11_matrix_score+0xd>
    19d4:	42 8d 04 d5 00 00 00 	lea    eax,[r10*8+0x0]
    19db:	00
    19dc:	44 29 d0             	sub    eax,r10d
    19df:	29 f0                	sub    eax,esi
    19e1:	c3                   	ret
    19e2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    19e8:	44 03 14 97          	add    r10d,DWORD PTR [rdi+rdx*4]
    19ec:	eb be                	jmp    19ac <lab11_matrix_score+0x1c>

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0xb879
 RBX  0xc0b7e95a
 RCX  0xd7f4a7c165b7d200
 RDX  0x130000002049
 RDI  0x7fffffffe040 ◂— 0x200000001
 RSI  0x100000001b3
 R8   0xff
 R9   0x7fffffffe0f0 ◂— 0x434242414141 /* 'AAABBC' */
 RSP  0x7fffffffdf98 —▸ 0x555555555310 (main+656) ◂— mov edx, 0x11
 RIP  0x555555555990 (lab11_matrix_score) ◂— xor edx, edx
   0x555555555992 <lab11_matrix_score+2>     xor    esi, esi       ESI => 0
   0x555555555994 <lab11_matrix_score+4>     xor    r10d, r10d     R10D => 0
   0x555555555997 <lab11_matrix_score+7>     mov    r8d, 9         R8D => 9
   0x55555555599d <lab11_matrix_score+13>    mov    ecx, edx       ECX => 0
   0x55555555599f <lab11_matrix_score+15>    mov    r9, r8         R9 => 9
   0x5555555559a2 <lab11_matrix_score+18>    shr    r9, cl
   0x5555555559a5 <lab11_matrix_score+21>    xor    ecx, ecx       ECX => 0
   0x5555555559a7 <lab11_matrix_score+23>    cmp    rdx, rcx       0 - 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555559aa <lab11_matrix_score+26>  ✔ je     lab11_matrix_score+88       <lab11_matrix_score+88>
   0x5555555559e8 <lab11_matrix_score+88>    add    r10d, dword ptr [rdi + rdx*4]     R10D => 1 (0 + 1)
=> 0x555555555990 <lab11_matrix_score>:	xor    edx,edx
   0x555555555992 <lab11_matrix_score+2>:	xor    esi,esi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab11_matrix_score` with entry RVA `0x1990`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 12 — Stateful stream transform

## Question and target

Given only stripped function `FUN_001019f0`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover three xorshift state transitions, high-byte keystream extraction, in-place XOR, rolling check value, and final state writeback. Separate persistent state from per-byte temporaries.

```c
FUNCTION FUN_001019f0
ENTRY 001019f0
SIGNATURE undefined FUN_001019f0(void)
CALLERS 00102164, 00102360, 00101323

uint FUN_001019f0(uint *param_1,byte *param_2,long param_3)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;

  uVar3 = *param_1;
  if (param_3 != 0) {
    uVar1 = 0;
    pbVar4 = param_2;
    do {
      pbVar5 = pbVar4 + 1;
      uVar3 = uVar3 ^ uVar3 << 0xd;
      uVar3 = uVar3 >> 0x11 ^ uVar3;
      uVar3 = uVar3 << 5 ^ uVar3;
      bVar2 = (byte)(uVar3 >> 0x18) ^ *pbVar4;
      *pbVar4 = bVar2;
      uVar1 = (uVar1 << 3 | uVar1 >> 0x1d) ^ (uint)bVar2;
      pbVar4 = pbVar5;
    } while (param_2 + param_3 != pbVar5);
    *param_1 = uVar3;
    return uVar1;
  }
  *param_1 = uVar3;
  return 0;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000019f0 <lab12_xorshift_stream>:
    19f0:	49 89 f8             	mov    r8,rdi
    19f3:	48 89 f7             	mov    rdi,rsi
    19f6:	41 8b 30             	mov    esi,DWORD PTR [r8]
    19f9:	48 85 d2             	test   rdx,rdx
    19fc:	74 7a                	je     1a78 <lab12_xorshift_stream+0x88>
    19fe:	48 01 fa             	add    rdx,rdi
    1a01:	31 c0                	xor    eax,eax
    1a03:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1a09:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a10:	00 00 00 00
    1a14:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a1b:	00 00 00 00
    1a1f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a26:	00 00 00 00
    1a2a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a31:	00 00 00 00
    1a35:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a3c:	00 00 00 00
    1a40:	89 f1                	mov    ecx,esi
    1a42:	c1 c0 03             	rol    eax,0x3
    1a45:	48 83 c7 01          	add    rdi,0x1
    1a49:	c1 e1 0d             	shl    ecx,0xd
    1a4c:	31 ce                	xor    esi,ecx
    1a4e:	89 f1                	mov    ecx,esi
    1a50:	c1 e9 11             	shr    ecx,0x11
    1a53:	31 f1                	xor    ecx,esi
    1a55:	89 ce                	mov    esi,ecx
    1a57:	c1 e6 05             	shl    esi,0x5
    1a5a:	31 ce                	xor    esi,ecx
    1a5c:	89 f1                	mov    ecx,esi
    1a5e:	c1 e9 18             	shr    ecx,0x18
    1a61:	32 4f ff             	xor    cl,BYTE PTR [rdi-0x1]
    1a64:	88 4f ff             	mov    BYTE PTR [rdi-0x1],cl
    1a67:	0f b6 c9             	movzx  ecx,cl
    1a6a:	31 c8                	xor    eax,ecx
    1a6c:	48 39 fa             	cmp    rdx,rdi
    1a6f:	75 cf                	jne    1a40 <lab12_xorshift_stream+0x50>
    1a71:	41 89 30             	mov    DWORD PTR [r8],esi
    1a74:	c3                   	ret
    1a75:	0f 1f 00             	nop    DWORD PTR [rax]
    1a78:	41 89 30             	mov    DWORD PTR [r8],esi
    1a7b:	31 c0                	xor    eax,eax
    1a7d:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0x88
 RBX  0xc0b7e95a
 RCX  4
 RDX  0x11
 RDI  0x7fffffffdfbc ◂— 0x712345678
 RSI  0x7fffffffe0d0 ◂— 0x722d726f746e656d ('mentor-r')
 R8   9
 R9   0x88
 RSP  0x7fffffffdf98 —▸ 0x555555555328 (main+680) ◂— add r9, r11
 RIP  0x5555555559f0 (lab12_xorshift_stream) ◂— mov r8, rdi
   0x5555555559f3 <lab12_xorshift_stream+3>     mov    rdi, rsi                RDI => 0x7fffffffe0d0 ◂— 0x722d726f746e656d ('mentor-r')
   0x5555555559f6 <lab12_xorshift_stream+6>     mov    esi, dword ptr [r8]     ESI, [0x7fffffffdfbc] => 0x12345678
   0x5555555559f9 <lab12_xorshift_stream+9>     test   rdx, rdx                0x11 & 0x11     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555559fc <lab12_xorshift_stream+12>  ✘ je     lab12_xorshift_stream+136   <lab12_xorshift_stream+136>
   0x5555555559fe <lab12_xorshift_stream+14>    add    rdx, rdi                 RDX => 0x7fffffffe0e1 (0x11 + 0x7fffffffe0d0)
   0x555555555a01 <lab12_xorshift_stream+17>    xor    eax, eax                 EAX => 0
   0x555555555a03 <lab12_xorshift_stream+19>    nop    word ptr [rax + rax]
   0x555555555a09 <lab12_xorshift_stream+25>    nop    word ptr [rax + rax]
   0x555555555a14 <lab12_xorshift_stream+36>    nop    word ptr [rax + rax]
   0x555555555a1f <lab12_xorshift_stream+47>    nop    word ptr [rax + rax]
=> 0x5555555559f0 <lab12_xorshift_stream>:	mov    r8,rdi
   0x5555555559f3 <lab12_xorshift_stream+3>:	mov    rdi,rsi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab12_xorshift_stream` with entry RVA `0x19f0`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 13 — TLV parser with multiple record types

## Question and target

Given only stripped function `FUN_00101a80`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Reconstruct header-size checks, type/length fields, remaining-length invariant, type-specific handlers, little-endian 32-bit extraction, and complete-consumption loop.

```c
FUNCTION FUN_00101a80
ENTRY 00101a80
SIGNATURE undefined FUN_00101a80(void)
CALLERS 0010216c, 00102374, 0010133d

uint FUN_00101a80(char *param_1,long param_2)

{
  byte *pbVar1;
  undefined1 auVar2 [16];
  byte bVar3;
  undefined1 auVar4 [14];
  undefined1 auVar5 [15];
  undefined1 auVar6 [15];
  undefined1 auVar7 [15];
  undefined1 auVar8 [14];
  undefined1 auVar9 [13];
  undefined1 auVar10 [13];
  undefined1 auVar11 [13];
  uint uVar12;
  undefined1 auVar13 [15];
  undefined1 auVar14 [15];
  undefined1 auVar15 [15];
  undefined1 auVar16 [15];
  undefined1 auVar17 [15];
  unkuint9 Var18;
  undefined1 auVar19 [11];
  undefined1 auVar20 [13];
  undefined1 auVar21 [14];
  undefined1 auVar22 [13];
  char cVar23;
  undefined1 auVar24 [15];
  undefined1 auVar25 [15];
  uint6 uVar26;
  undefined1 (*pauVar27) [16];
  char *pcVar28;
  ulong uVar29;
  ulong uVar30;
  uint uVar31;
  undefined1 (*pauVar32) [16];
  byte bVar33;
  long lVar34;
  int iVar35;
  int iVar36;
  int iVar37;
  int iVar38;
  uint uVar39;

  uVar31 = 0;
joined_r0x00101a89:
  do {
    if (param_2 == 0) {
      return uVar31;
    }
    if (param_2 == 1) {
      return 0xffffffff;
    }
    bVar3 = param_1[1];
    uVar29 = (ulong)bVar3;
    uVar30 = param_2 - 2;
    if (uVar30 < uVar29) {
      return 0xfffffffe;
    }
    if (*param_1 == '\x01') {
      if (bVar3 != 0) {
        if ((byte)(bVar3 - 1) < 0xf) {
          lVar34 = 0;
        }
        else {
          pauVar27 = (undefined1 (*) [16])(param_1 + 2);
          iVar35 = 0;
          iVar36 = 0;
          iVar37 = 0;
          iVar38 = 0;
          bVar33 = bVar3 >> 4;
          pauVar32 = pauVar27 + bVar33;
          do {
            auVar2 = *pauVar27;
            pauVar27 = pauVar27 + 1;
            uVar39 = CONCAT13(0,CONCAT12(auVar2[9],(ushort)auVar2[8]));
            auVar5[0xd] = 0;
            auVar5._0_13_ = auVar2._0_13_;
            auVar5[0xe] = auVar2[7];
            auVar6[0xc] = auVar2[6];
            auVar6._0_12_ = auVar2._0_12_;
            auVar6._13_2_ = auVar5._13_2_;
            auVar7[0xb] = 0;
            auVar7._0_11_ = auVar2._0_11_;
            auVar7._12_3_ = auVar6._12_3_;
            uVar12 = auVar7._11_4_;
            auVar13[10] = auVar2[5];
            auVar13._0_10_ = auVar2._0_10_;
            auVar13._11_4_ = uVar12;
            auVar14[9] = 0;
            auVar14._0_9_ = auVar2._0_9_;
            auVar14._10_5_ = auVar13._10_5_;
            auVar15[8] = auVar2[4];
            auVar15._0_8_ = auVar2._0_8_;
            auVar15._9_6_ = auVar14._9_6_;
            auVar17._7_8_ = 0;
            auVar17._0_7_ = auVar15._8_7_;
            Var18 = CONCAT81(SUB158(auVar17 << 0x40,7),auVar2[3]);
            auVar24._9_6_ = 0;
            auVar24._0_9_ = Var18;
            auVar19._1_10_ = SUB1510(auVar24 << 0x30,5);
            auVar19[0] = auVar2[2];
            auVar25._11_4_ = 0;
            auVar25._0_11_ = auVar19;
            auVar20._1_12_ = SUB1512(auVar25 << 0x20,3);
            auVar20[0] = auVar2[1];
            auVar16[1] = 0;
            auVar16[0] = auVar2[0];
            auVar16._2_13_ = auVar20;
            auVar4._10_2_ = 0;
            auVar4._0_10_ = auVar16._0_10_;
            auVar4._12_2_ = (short)Var18;
            uVar26 = CONCAT42(auVar4._10_4_,auVar19._0_2_);
            auVar21._6_8_ = 0;
            auVar21._0_6_ = uVar26;
            auVar8._4_2_ = auVar20._0_2_;
            auVar8._0_4_ = auVar16._0_4_;
            auVar8._6_8_ = SUB148(auVar21 << 0x40,6);
            auVar9[0xc] = auVar2[0xb];
            auVar9._0_12_ = ZEXT112(auVar2[0xc]) << 0x40;
            auVar10._10_3_ = auVar9._10_3_;
            auVar10._0_10_ = (unkuint10)auVar2[10] << 0x40;
            auVar22._5_8_ = 0;
            auVar22._0_5_ = auVar10._8_5_;
            auVar11[4] = auVar2[9];
            auVar11._0_4_ = uVar39;
            auVar11[5] = 0;
            auVar11._6_7_ = SUB137(auVar22 << 0x40,6);
            iVar35 = iVar35 + (auVar16._0_4_ & 0xffff) + (uint)auVar15._8_2_ + (uVar39 & 0xffff) +
                     (uint)auVar2[0xc];
            iVar36 = iVar36 + auVar8._4_4_ + (uint)auVar13._10_2_ + auVar11._4_4_ +
                     (uint)auVar2[0xd];
            iVar37 = iVar37 + (int)uVar26 + (uVar12 >> 8 & 0xffff) + auVar10._8_4_ +
                     (uint)auVar2[0xe];
            iVar38 = iVar38 + (auVar4._10_4_ >> 0x10) + (uVar12 >> 0x18) +
                     (uint)(uint3)(auVar9._10_3_ >> 0x10) + (uint)auVar2[0xf];
          } while (pauVar27 != pauVar32);
          lVar34 = (ulong)bVar33 << 4;
          uVar31 = uVar31 + iVar35 + iVar37 + iVar36 + iVar38;
          if (bVar3 == (byte)(bVar33 << 4)) goto LAB_00101aad;
        }
        pcVar28 = param_1 + lVar34;
        cVar23 = (char)pcVar28;
        do {
          pbVar1 = (byte *)(pcVar28 + 2);
          pcVar28 = pcVar28 + 1;
          uVar31 = uVar31 + *pbVar1;
        } while ((byte)(((char)lVar34 - cVar23) + (char)pcVar28) < bVar3);
        param_1 = param_1 + uVar29 + 2;
        param_2 = uVar30 - uVar29;
        goto joined_r0x00101a89;
      }
    }
    else if ((*param_1 == '\x02') && (bVar3 == 4)) {
      uVar31 = uVar31 ^ *(uint *)(param_1 + 2);
    }
LAB_00101aad:
    param_1 = param_1 + uVar29 + 2;
    param_2 = uVar30 - uVar29;
  } while( true );
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001a80 <lab13_tlv_sum>:
    1a80:	48 89 f9             	mov    rcx,rdi
    1a83:	45 31 c0             	xor    r8d,r8d
    1a86:	48 85 f6             	test   rsi,rsi
    1a89:	0f 84 34 01 00 00    	je     1bc3 <lab13_tlv_sum+0x143>
    1a8f:	66 0f ef e4          	pxor   xmm4,xmm4
    1a93:	66 0f ef db          	pxor   xmm3,xmm3
    1a97:	eb 22                	jmp    1abb <lab13_tlv_sum+0x3b>
    1a99:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1aa0:	3c 02                	cmp    al,0x2
    1aa2:	75 09                	jne    1aad <lab13_tlv_sum+0x2d>
    1aa4:	80 fa 04             	cmp    dl,0x4
    1aa7:	75 04                	jne    1aad <lab13_tlv_sum+0x2d>
    1aa9:	44 33 41 02          	xor    r8d,DWORD PTR [rcx+0x2]
    1aad:	48 8d 4c 11 02       	lea    rcx,[rcx+rdx*1+0x2]
    1ab2:	48 29 d6             	sub    rsi,rdx
    1ab5:	0f 84 08 01 00 00    	je     1bc3 <lab13_tlv_sum+0x143>
    1abb:	48 83 fe 01          	cmp    rsi,0x1
    1abf:	0f 84 0b 01 00 00    	je     1bd0 <lab13_tlv_sum+0x150>
    1ac5:	0f b6 51 01          	movzx  edx,BYTE PTR [rcx+0x1]
    1ac9:	48 83 ee 02          	sub    rsi,0x2
    1acd:	48 89 d7             	mov    rdi,rdx
    1ad0:	48 39 d6             	cmp    rsi,rdx
    1ad3:	0f 82 07 01 00 00    	jb     1be0 <lab13_tlv_sum+0x160>
    1ad9:	0f b6 01             	movzx  eax,BYTE PTR [rcx]
    1adc:	3c 01                	cmp    al,0x1
    1ade:	75 c0                	jne    1aa0 <lab13_tlv_sum+0x20>
    1ae0:	84 d2                	test   dl,dl
    1ae2:	74 c9                	je     1aad <lab13_tlv_sum+0x2d>
    1ae4:	8d 42 ff             	lea    eax,[rdx-0x1]
    1ae7:	3c 0e                	cmp    al,0xe
    1ae9:	0f 86 fb 00 00 00    	jbe    1bea <lab13_tlv_sum+0x16a>
    1aef:	41 89 d2             	mov    r10d,edx
    1af2:	48 8d 41 02          	lea    rax,[rcx+0x2]
    1af6:	66 0f ef c0          	pxor   xmm0,xmm0
    1afa:	41 c0 ea 04          	shr    r10b,0x4
    1afe:	45 0f b6 ca          	movzx  r9d,r10b
    1b02:	49 c1 e1 04          	shl    r9,0x4
    1b06:	49 01 c1             	add    r9,rax
    1b09:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1b10:	f3 0f 6f 08          	movdqu xmm1,XMMWORD PTR [rax]
    1b14:	48 83 c0 10          	add    rax,0x10
    1b18:	66 0f 6f d1          	movdqa xmm2,xmm1
    1b1c:	66 0f 68 cc          	punpckhbw xmm1,xmm4
    1b20:	66 0f 60 d4          	punpcklbw xmm2,xmm4
    1b24:	66 0f 6f ea          	movdqa xmm5,xmm2
    1b28:	66 0f 69 d3          	punpckhwd xmm2,xmm3
    1b2c:	66 0f 61 eb          	punpcklwd xmm5,xmm3
    1b30:	66 0f fe c5          	paddd  xmm0,xmm5
    1b34:	66 0f fe c2          	paddd  xmm0,xmm2
    1b38:	66 0f 6f d1          	movdqa xmm2,xmm1
    1b3c:	66 0f 69 cb          	punpckhwd xmm1,xmm3
    1b40:	66 0f 61 d3          	punpcklwd xmm2,xmm3
    1b44:	66 0f fe c2          	paddd  xmm0,xmm2
    1b48:	66 0f fe c1          	paddd  xmm0,xmm1
    1b4c:	4c 39 c8             	cmp    rax,r9
    1b4f:	75 bf                	jne    1b10 <lab13_tlv_sum+0x90>
    1b51:	66 0f 6f c8          	movdqa xmm1,xmm0
    1b55:	41 c1 e2 04          	shl    r10d,0x4
    1b59:	66 0f 73 d9 08       	psrldq xmm1,0x8
    1b5e:	66 0f fe c1          	paddd  xmm0,xmm1
    1b62:	66 0f 6f c8          	movdqa xmm1,xmm0
    1b66:	66 0f 73 d9 04       	psrldq xmm1,0x4
    1b6b:	66 0f fe c1          	paddd  xmm0,xmm1
    1b6f:	66 0f 7e c0          	movd   eax,xmm0
    1b73:	41 01 c0             	add    r8d,eax
    1b76:	44 38 d7             	cmp    dil,r10b
    1b79:	0f 84 2e ff ff ff    	je     1aad <lab13_tlv_sum+0x2d>
    1b7f:	41 0f b6 c2          	movzx  eax,r10b
    1b83:	48 01 c8             	add    rax,rcx
    1b86:	41 29 c2             	sub    r10d,eax
    1b89:	90                   	nop
    1b8a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1b91:	00 00 00 00
    1b95:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1b9c:	00 00 00 00
    1ba0:	44 0f b6 48 02       	movzx  r9d,BYTE PTR [rax+0x2]
    1ba5:	48 83 c0 01          	add    rax,0x1
    1ba9:	45 01 c8             	add    r8d,r9d
    1bac:	45 8d 0c 02          	lea    r9d,[r10+rax*1]
    1bb0:	41 38 f9             	cmp    r9b,dil
    1bb3:	72 eb                	jb     1ba0 <lab13_tlv_sum+0x120>
    1bb5:	48 8d 4c 11 02       	lea    rcx,[rcx+rdx*1+0x2]
    1bba:	48 29 d6             	sub    rsi,rdx
    1bbd:	0f 85 f8 fe ff ff    	jne    1abb <lab13_tlv_sum+0x3b>
    1bc3:	44 89 c0             	mov    eax,r8d
    1bc6:	c3                   	ret
    1bc7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    1bce:	00 00
    1bd0:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
    1bd6:	44 89 c0             	mov    eax,r8d
    1bd9:	c3                   	ret
    1bda:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1be0:	41 b8 fe ff ff ff    	mov    r8d,0xfffffffe
    1be6:	44 89 c0             	mov    eax,r8d
    1be9:	c3                   	ret
    1bea:	45 31 d2             	xor    r10d,r10d
    1bed:	eb 90                	jmp    1b7f <lab13_tlv_sum+0xff>

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0x742972f
 RBX  0xc0b7e95a
 RCX  0xcd
 RDX  0x7fffffffe0e1 ◂— 0x11000
 RDI  0x7fffffffe095 ◂— 0x7804020302010301
 RSI  0xb
 R8   0x7fffffffdfbc ◂— 0x7cd8c4692
 R9   0xd7f4b7c2267096be
 RSP  0x7fffffffdf98 —▸ 0x555555555342 (main+706) ◂— xor esi, esi
 RIP  0x555555555a80 (lab13_tlv_sum) ◂— mov rcx, rdi
   0x555555555a83 <lab13_tlv_sum+3>     xor    r8d, r8d     R8D => 0
   0x555555555a86 <lab13_tlv_sum+6>     test   rsi, rsi     0xb & 0xb     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555a89 <lab13_tlv_sum+9>   ✘ je     lab13_tlv_sum+323           <lab13_tlv_sum+323>
   0x555555555a8f <lab13_tlv_sum+15>    pxor   xmm4, xmm4
   0x555555555a93 <lab13_tlv_sum+19>    pxor   xmm3, xmm3
   0x555555555a97 <lab13_tlv_sum+23>    jmp    lab13_tlv_sum+59            <lab13_tlv_sum+59>
   0x555555555abb <lab13_tlv_sum+59>    cmp    rsi, 1         0xb - 0x1     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555abf <lab13_tlv_sum+63>  ✘ je     lab13_tlv_sum+336           <lab13_tlv_sum+336>
   0x555555555ac5 <lab13_tlv_sum+69>    movzx  edx, byte ptr [rcx + 1]     EDX, [0x7fffffffe096] => 3
   0x555555555ac9 <lab13_tlv_sum+73>    sub    rsi, 2                      RSI => 9 (0xb - 0x2)
=> 0x555555555a80 <lab13_tlv_sum>:	mov    rcx,rdi
   0x555555555a83 <lab13_tlv_sum+3>:	xor    r8d,r8d
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab13_tlv_sum` with entry RVA `0x1a80`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 14 — Ring-buffer object and operations

## Question and target

Given only stripped function `FUN_00101bf0`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Infer object layout, operation selector, full/empty checks, masked head/tail wrap, count updates, and three error codes. Two dynamic entries demonstrate push and pop.

```c
FUNCTION FUN_00101bf0
ENTRY 00101bf0
SIGNATURE undefined FUN_00101bf0(void)
CALLERS 00102174, 00102388, 00101355, 00101373

undefined8 FUN_00101bf0(long param_1,int param_2,undefined1 *param_3)

{
  char cVar1;
  byte bVar2;

  if (param_2 == 0) {
    cVar1 = *(char *)(param_1 + 0x12);
    if (cVar1 != '\x10') {
      bVar2 = *(byte *)(param_1 + 0x11);
      *(undefined1 *)(param_1 + (ulong)bVar2) = *param_3;
      *(byte *)(param_1 + 0x11) = bVar2 + 1 & 0xf;
      *(char *)(param_1 + 0x12) = cVar1 + '\x01';
      return 0;
    }
    return 0xffffffff;
  }
  if (param_2 != 1) {
    return 0xfffffffd;
  }
  if (*(char *)(param_1 + 0x12) != '\0') {
    *param_3 = *(undefined1 *)(param_1 + (ulong)*(byte *)(param_1 + 0x10));
    *(char *)(param_1 + 0x12) = *(char *)(param_1 + 0x12) + -1;
    *(byte *)(param_1 + 0x10) = *(char *)(param_1 + 0x10) + 1U & 0xf;
    return 0;
  }
  return 0xfffffffe;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001bf0 <lab14_ring>:
    1bf0:	48 89 d1             	mov    rcx,rdx
    1bf3:	85 f6                	test   esi,esi
    1bf5:	75 29                	jne    1c20 <lab14_ring+0x30>
    1bf7:	0f b6 57 12          	movzx  edx,BYTE PTR [rdi+0x12]
    1bfb:	80 fa 10             	cmp    dl,0x10
    1bfe:	74 56                	je     1c56 <lab14_ring+0x66>
    1c00:	0f b6 47 11          	movzx  eax,BYTE PTR [rdi+0x11]
    1c04:	0f b6 31             	movzx  esi,BYTE PTR [rcx]
    1c07:	83 c2 01             	add    edx,0x1
    1c0a:	0f b6 c8             	movzx  ecx,al
    1c0d:	83 c0 01             	add    eax,0x1
    1c10:	83 e0 0f             	and    eax,0xf
    1c13:	40 88 34 0f          	mov    BYTE PTR [rdi+rcx*1],sil
    1c17:	88 47 11             	mov    BYTE PTR [rdi+0x11],al
    1c1a:	31 c0                	xor    eax,eax
    1c1c:	88 57 12             	mov    BYTE PTR [rdi+0x12],dl
    1c1f:	c3                   	ret
    1c20:	83 fe 01             	cmp    esi,0x1
    1c23:	75 2b                	jne    1c50 <lab14_ring+0x60>
    1c25:	80 7f 12 00          	cmp    BYTE PTR [rdi+0x12],0x0
    1c29:	74 1e                	je     1c49 <lab14_ring+0x59>
    1c2b:	0f b6 47 10          	movzx  eax,BYTE PTR [rdi+0x10]
    1c2f:	0f b6 04 07          	movzx  eax,BYTE PTR [rdi+rax*1]
    1c33:	88 02                	mov    BYTE PTR [rdx],al
    1c35:	0f b6 47 10          	movzx  eax,BYTE PTR [rdi+0x10]
    1c39:	80 6f 12 01          	sub    BYTE PTR [rdi+0x12],0x1
    1c3d:	83 c0 01             	add    eax,0x1
    1c40:	83 e0 0f             	and    eax,0xf
    1c43:	88 47 10             	mov    BYTE PTR [rdi+0x10],al
    1c46:	31 c0                	xor    eax,eax
    1c48:	c3                   	ret
    1c49:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1c4e:	c3                   	ret
    1c4f:	90                   	nop
    1c50:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    1c55:	c3                   	ret
    1c56:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1c5b:	c3                   	ret

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0x1234567e
 RBX  0xc0b7e95a
 RCX  0x7fffffffe0a0 ◂— 0x331564552
 RDX  0x7fffffffdfbb ◂— 0x7cd8c469209
 RDI  0x7fffffffe000 ◂— 0
 RSI  0
 R8   0x1234567e
 R9   3
 RSP  0x7fffffffdf98 —▸ 0x55555555535a (main+730) ◂— lea rdx, [rbp - 0x195]
 RIP  0x555555555bf0 (lab14_ring) ◂— mov rcx, rdx
   0x555555555bf3 <lab14_ring+3>     test   esi, esi     0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555bf5 <lab14_ring+5>   ✘ jne    lab14_ring+48               <lab14_ring+48>
   0x555555555bf7 <lab14_ring+7>     movzx  edx, byte ptr [rdi + 0x12]     EDX, [0x7fffffffe012] => 0
   0x555555555bfb <lab14_ring+11>    cmp    dl, 0x10                       0x0 - 0x10     EFLAGS => 0x287 [ CF PF af zf SF IF df of ac ]
   0x555555555bfe <lab14_ring+14>  ✘ je     lab14_ring+102              <lab14_ring+102>
   0x555555555c00 <lab14_ring+16>    movzx  eax, byte ptr [rdi + 0x11]     EAX, [0x7fffffffe011] => 0
   0x555555555c04 <lab14_ring+20>    movzx  esi, byte ptr [rcx]            ESI, [0x7fffffffdfbb] => 9
   0x555555555c07 <lab14_ring+23>    add    edx, 1                         EDX => 1 (0 + 1)
   0x555555555c0a <lab14_ring+26>    movzx  ecx, al                        ECX => 0
   0x555555555c0d <lab14_ring+29>    add    eax, 1                         EAX => 1 (0 + 1)
=> 0x555555555bf0 <lab14_ring>:	mov    rcx,rdx
   0x555555555bf3 <lab14_ring+3>:	test   esi,esi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab14_ring` with entry RVA `0x1bf0`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Walkthrough 15 — Cross-function checksum gate

## Question and target

Given only stripped function `FUN_00101c60`, recover its contract, data representation, edge cases, and a validation experiment.

## Static result from Ghidra

Recover the call to the earlier hash, a weighted-byte secondary checksum, XOR comparison, and Boolean return. Trace how one function composes another recovered contract.

```c
FUNCTION FUN_00101c60
ENTRY 00101c60
SIGNATURE undefined FUN_00101c60(void)
CALLERS 0010217c, 0010239c, 00101394

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool FUN_00101c60(undefined1 (*param_1) [16],ulong param_2,uint param_3)

{
  byte *pbVar1;
  undefined1 auVar2 [16];
  undefined1 auVar3 [13];
  undefined1 auVar4 [15];
  undefined1 auVar5 [14];
  undefined1 auVar6 [15];
  undefined1 auVar7 [15];
  undefined1 auVar8 [13];
  undefined1 auVar9 [13];
  uint5 uVar10;
  undefined1 auVar11 [13];
  undefined1 auVar12 [15];
  undefined1 auVar13 [14];
  undefined1 auVar14 [13];
  undefined1 auVar15 [15];
  undefined1 auVar16 [14];
  undefined1 auVar17 [15];
  undefined1 auVar18 [13];
  undefined1 auVar19 [15];
  undefined1 auVar20 [15];
  undefined1 auVar21 [13];
  undefined1 auVar22 [15];
  unkuint9 Var23;
  undefined1 auVar24 [11];
  undefined1 auVar25 [14];
  undefined1 auVar26 [15];
  undefined1 auVar27 [15];
  uint6 uVar28;
  uint uVar29;
  ulong uVar30;
  undefined1 (*pauVar31) [16];
  undefined1 auVar32 [16];
  undefined1 auVar33 [16];
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  long lVar36;
  long lVar37;
  ulong uVar38;
  int iVar39;
  uint uVar40;
  int iVar41;
  int iVar42;
  int iVar43;
  uint uVar44;
  ulong uVar45;

  uVar29 = FUN_00101530();
  if (param_2 == 0) goto LAB_00101ed8;
  if (param_2 - 1 < 0xf) {
    uVar30 = 0;
    uVar40 = 0;
LAB_00101ec0:
    do {
      pbVar1 = *param_1 + uVar30;
      iVar39 = (int)uVar30;
      uVar30 = uVar30 + 1;
      uVar40 = uVar40 + (iVar39 + 1) * (uint)*pbVar1;
    } while (uVar30 < param_2);
  }
  else {
    iVar39 = 0;
    iVar41 = 0;
    iVar42 = 0;
    iVar43 = 0;
    uVar30 = param_2 & 0xfffffffffffffff0;
    pauVar31 = param_1;
    lVar36 = _DAT_00102040;
    lVar37 = _UNK_00102048;
    do {
      auVar2 = *pauVar31;
      pauVar31 = pauVar31 + 1;
      uVar40 = CONCAT13(0,CONCAT12(auVar2[9],(ushort)auVar2[8]));
      auVar32._0_4_ = (int)(lVar36 + 8) + 1;
      auVar32._4_4_ = (int)(lVar37 + 8) + 1;
      auVar32._8_4_ = (int)(lVar36 + 10) + 1;
      auVar32._12_4_ = (int)(lVar37 + 10) + 1;
      uVar38 = CONCAT35(0,CONCAT14(auVar2[0xd],(uint)auVar2[0xc]));
      auVar3[8] = auVar2[0xe];
      auVar3._0_8_ = uVar38;
      auVar3._9_3_ = 0;
      auVar3[0xc] = auVar2[0xf];
      auVar8[0xc] = auVar2[0xb];
      auVar8._0_12_ = ZEXT112(auVar2[0xc]) << 0x40;
      auVar9._10_3_ = auVar8._10_3_;
      auVar9._0_10_ = (unkuint10)auVar2[10] << 0x40;
      uVar10 = auVar9._8_5_;
      auVar21._5_8_ = 0;
      auVar21._0_5_ = uVar10;
      auVar11[4] = auVar2[9];
      auVar11._0_4_ = uVar40;
      auVar11[5] = 0;
      auVar11._6_7_ = SUB137(auVar21 << 0x40,6);
      uVar40 = uVar40 & 0xffff;
      auVar14._4_9_ = auVar11._4_9_;
      auVar14._0_4_ = uVar40;
      auVar4[0xd] = 0;
      auVar4._0_13_ = auVar2._0_13_;
      auVar4[0xe] = auVar2[7];
      auVar6[0xc] = auVar2[6];
      auVar6._0_12_ = auVar2._0_12_;
      auVar6._13_2_ = auVar4._13_2_;
      auVar7[0xb] = 0;
      auVar7._0_11_ = auVar2._0_11_;
      auVar7._12_3_ = auVar6._12_3_;
      auVar12[10] = auVar2[5];
      auVar12._0_10_ = auVar2._0_10_;
      auVar12._11_4_ = auVar7._11_4_;
      auVar15[9] = 0;
      auVar15._0_9_ = auVar2._0_9_;
      auVar15._10_5_ = auVar12._10_5_;
      auVar17[8] = auVar2[4];
      auVar17._0_8_ = auVar2._0_8_;
      auVar17._9_6_ = auVar15._9_6_;
      auVar22._7_8_ = 0;
      auVar22._0_7_ = auVar17._8_7_;
      Var23 = CONCAT81(SUB158(auVar22 << 0x40,7),auVar2[3]);
      auVar26._9_6_ = 0;
      auVar26._0_9_ = Var23;
      auVar24._1_10_ = SUB1510(auVar26 << 0x30,5);
      auVar24[0] = auVar2[2];
      auVar27._11_4_ = 0;
      auVar27._0_11_ = auVar24;
      auVar19[2] = auVar2[1];
      auVar19._0_2_ = auVar2._0_2_;
      auVar19._3_12_ = SUB1512(auVar27 << 0x20,3);
      auVar20._2_13_ = auVar19._2_13_;
      auVar20._0_2_ = auVar2._0_2_ & 0xff;
      auVar33._0_4_ = (int)(lVar36 + 0xc) + 1;
      auVar33._4_4_ = (int)(lVar37 + 0xc) + 1;
      auVar33._8_4_ = (int)(lVar36 + 0xe) + 1;
      auVar33._12_4_ = (int)(lVar37 + 0xe) + 1;
      auVar34._0_4_ = (int)(lVar36 + 4) + 1;
      auVar34._4_4_ = (int)(lVar37 + 4) + 1;
      auVar34._8_4_ = (int)(lVar36 + 6) + 1;
      auVar34._12_4_ = (int)(lVar37 + 6) + 1;
      uVar45 = CONCAT26(0,CONCAT24(auVar12._10_2_,(uint)auVar17._8_2_));
      auVar18._8_2_ = auVar6._12_2_;
      auVar18._0_8_ = uVar45;
      auVar18._10_2_ = 0;
      auVar18[0xc] = auVar2[7];
      auVar5._10_2_ = 0;
      auVar5._0_10_ = auVar20._0_10_;
      auVar5._12_2_ = (short)Var23;
      uVar28 = CONCAT42(auVar5._10_4_,auVar24._0_2_);
      auVar25._6_8_ = 0;
      auVar25._0_6_ = uVar28;
      auVar13._4_2_ = auVar19._2_2_;
      auVar13._0_4_ = auVar20._0_4_;
      auVar13._6_8_ = SUB148(auVar25 << 0x40,6);
      uVar44 = auVar20._0_4_ & 0xffff;
      auVar16._4_10_ = auVar13._4_10_;
      auVar16._0_4_ = uVar44;
      auVar35._0_4_ = (int)lVar36 + 1;
      auVar35._4_4_ = (int)lVar37 + 1;
      auVar35._8_4_ = (int)(lVar36 + 2) + 1;
      auVar35._12_4_ = (int)(lVar37 + 2) + 1;
      iVar39 = iVar39 + auVar32._0_4_ * uVar40 + (int)((ulong)auVar33._0_4_ * (uVar38 & 0xffffffff))
                        + (int)((ulong)auVar34._0_4_ * (uVar45 & 0xffffffff)) +
                          auVar35._0_4_ * uVar44;
      iVar41 = iVar41 + (int)((ulong)auVar32._4_4_ * (auVar14._0_8_ >> 0x20)) +
                        auVar33._4_4_ * (uint)auVar2[0xd] +
                        auVar34._4_4_ * (uint)auVar12._10_2_ +
                        (int)((ulong)auVar35._4_4_ * (auVar16._0_8_ >> 0x20));
      iVar42 = iVar42 + (int)((auVar32._8_8_ & 0xffffffff) * ((ulong)uVar10 & 0xffffffff)) +
                        (int)((auVar33._8_8_ & 0xffffffff) * (ulong)auVar2[0xe]) +
                        (int)((auVar34._8_8_ & 0xffffffff) * (ulong)auVar6._12_2_) +
                        (int)((auVar35._8_8_ & 0xffffffff) * ((ulong)uVar28 & 0xffffffff));
      iVar43 = iVar43 + (int)((auVar32._8_8_ >> 0x20) * (ulong)(uVar10 >> 0x20)) +
                        (int)((auVar33._8_8_ >> 0x20) * (ulong)(auVar3._8_5_ >> 0x20)) +
                        (int)((auVar34._8_8_ >> 0x20) * (ulong)(auVar18._8_5_ >> 0x20)) +
                        (int)((auVar35._8_8_ >> 0x20) * (ulong)(auVar5._10_4_ >> 0x10));
      lVar36 = lVar36 + 0x10;
      lVar37 = lVar37 + 0x10;
    } while (pauVar31 != (undefined1 (*) [16])(*param_1 + uVar30));
    uVar40 = iVar39 + iVar42 + iVar41 + iVar43;
    if (uVar30 != param_2) goto LAB_00101ec0;
  }
  uVar29 = uVar29 ^ uVar40;
LAB_00101ed8:
  return param_3 == uVar29;
}
```

## Ground-truth instruction listing

```asm
reversing-walkthrough-lab/build/ch01/ch01_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001c60 <lab15_cross_check>:
    1c60:	55                   	push   rbp
    1c61:	49 89 f0             	mov    r8,rsi
    1c64:	49 89 f9             	mov    r9,rdi
    1c67:	41 89 d2             	mov    r10d,edx
    1c6a:	48 89 e5             	mov    rbp,rsp
    1c6d:	48 83 ec 30          	sub    rsp,0x30
    1c71:	e8 ba f8 ff ff       	call   1530 <lab01_rolling_hash>
    1c76:	89 c6                	mov    esi,eax
    1c78:	4d 85 c0             	test   r8,r8
    1c7b:	0f 84 57 02 00 00    	je     1ed8 <lab15_cross_check+0x278>
    1c81:	49 8d 40 ff          	lea    rax,[r8-0x1]
    1c85:	48 83 f8 0e          	cmp    rax,0xe
    1c89:	0f 86 53 02 00 00    	jbe    1ee2 <lab15_cross_check+0x282>
    1c8f:	bf 08 00 00 00       	mov    edi,0x8
    1c94:	4c 89 c0             	mov    rax,r8
    1c97:	66 0f 76 f6          	pcmpeqd xmm6,xmm6
    1c9b:	4c 89 ca             	mov    rdx,r9
    1c9e:	66 4c 0f 6e e7       	movq   xmm12,rdi
    1ca3:	66 0f ef e4          	pxor   xmm4,xmm4
    1ca7:	66 0f ef ff          	pxor   xmm7,xmm7
    1cab:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    1caf:	bf 0a 00 00 00       	mov    edi,0xa
    1cb4:	49 8d 0c 01          	lea    rcx,[r9+rax*1]
    1cb8:	66 45 0f 6c e4       	punpcklqdq xmm12,xmm12
    1cbd:	66 0f 6f 15 7b 03 00 	movdqa xmm2,XMMWORD PTR [rip+0x37b]        # 2040 <_IO_stdin_used+0x40>
    1cc4:	00
    1cc5:	66 4c 0f 6e df       	movq   xmm11,rdi
    1cca:	66 0f 72 d6 1f       	psrld  xmm6,0x1f
    1ccf:	bf 0c 00 00 00       	mov    edi,0xc
    1cd4:	66 4c 0f 6e d7       	movq   xmm10,rdi
    1cd9:	bf 0e 00 00 00       	mov    edi,0xe
    1cde:	66 45 0f 6c db       	punpcklqdq xmm11,xmm11
    1ce3:	66 4c 0f 6e cf       	movq   xmm9,rdi
    1ce8:	bf 04 00 00 00       	mov    edi,0x4
    1ced:	66 45 0f 6c d2       	punpcklqdq xmm10,xmm10
    1cf2:	66 4c 0f 6e c7       	movq   xmm8,rdi
    1cf7:	bf 06 00 00 00       	mov    edi,0x6
    1cfc:	66 45 0f 6c c9       	punpcklqdq xmm9,xmm9
    1d01:	66 48 0f 6e ef       	movq   xmm5,rdi
    1d06:	bf 02 00 00 00       	mov    edi,0x2
    1d0b:	66 45 0f 6c c0       	punpcklqdq xmm8,xmm8
    1d10:	66 0f 6c ed          	punpcklqdq xmm5,xmm5
    1d14:	0f 29 6d f0          	movaps XMMWORD PTR [rbp-0x10],xmm5
    1d18:	66 48 0f 6e ef       	movq   xmm5,rdi
    1d1d:	bf 10 00 00 00       	mov    edi,0x10
    1d22:	66 0f 6c ed          	punpcklqdq xmm5,xmm5
    1d26:	0f 29 6d e0          	movaps XMMWORD PTR [rbp-0x20],xmm5
    1d2a:	66 48 0f 6e ef       	movq   xmm5,rdi
    1d2f:	66 0f 6c ed          	punpcklqdq xmm5,xmm5
    1d33:	0f 29 6d d0          	movaps XMMWORD PTR [rbp-0x30],xmm5
    1d37:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    1d3e:	00 00
    1d40:	f3 0f 6f 1a          	movdqu xmm3,XMMWORD PTR [rdx]
    1d44:	66 0f 6f c2          	movdqa xmm0,xmm2
    1d48:	66 0f 6f ca          	movdqa xmm1,xmm2
    1d4c:	66 0f ef ed          	pxor   xmm5,xmm5
    1d50:	66 41 0f d4 cb       	paddq  xmm1,xmm11
    1d55:	66 41 0f d4 c4       	paddq  xmm0,xmm12
    1d5a:	48 83 c2 10          	add    rdx,0x10
    1d5e:	66 44 0f 6f f3       	movdqa xmm14,xmm3
    1d63:	66 0f 68 df          	punpckhbw xmm3,xmm7
    1d67:	0f c6 c1 88          	shufps xmm0,xmm1,0x88
    1d6b:	66 0f fe c6          	paddd  xmm0,xmm6
    1d6f:	66 44 0f 6f fb       	movdqa xmm15,xmm3
    1d74:	66 0f 6f c8          	movdqa xmm1,xmm0
    1d78:	66 0f 69 dd          	punpckhwd xmm3,xmm5
    1d7c:	66 44 0f 61 fd       	punpcklwd xmm15,xmm5
    1d81:	66 0f 73 d0 20       	psrlq  xmm0,0x20
    1d86:	66 44 0f 60 f7       	punpcklbw xmm14,xmm7
    1d8b:	66 41 0f f4 cf       	pmuludq xmm1,xmm15
    1d90:	66 41 0f 73 d7 20    	psrlq  xmm15,0x20
    1d96:	66 41 0f f4 c7       	pmuludq xmm0,xmm15
    1d9b:	66 44 0f 6f fa       	movdqa xmm15,xmm2
    1da0:	66 45 0f d4 f9       	paddq  xmm15,xmm9
    1da5:	66 0f 70 c9 08       	pshufd xmm1,xmm1,0x8
    1daa:	66 0f 70 c0 08       	pshufd xmm0,xmm0,0x8
    1daf:	66 0f 62 c8          	punpckldq xmm1,xmm0
    1db3:	66 0f 6f c2          	movdqa xmm0,xmm2
    1db7:	66 41 0f d4 c2       	paddq  xmm0,xmm10
    1dbc:	41 0f c6 c7 88       	shufps xmm0,xmm15,0x88
    1dc1:	66 0f fe c6          	paddd  xmm0,xmm6
    1dc5:	66 44 0f 6f f8       	movdqa xmm15,xmm0
    1dca:	66 0f 73 d0 20       	psrlq  xmm0,0x20
    1dcf:	66 44 0f f4 fb       	pmuludq xmm15,xmm3
    1dd4:	66 0f 73 d3 20       	psrlq  xmm3,0x20
    1dd9:	66 0f f4 c3          	pmuludq xmm0,xmm3
    1ddd:	66 0f 6f 5d f0       	movdqa xmm3,XMMWORD PTR [rbp-0x10]
    1de2:	66 0f d4 da          	paddq  xmm3,xmm2
    1de6:	66 45 0f 70 ff 08    	pshufd xmm15,xmm15,0x8
    1dec:	66 0f 70 c0 08       	pshufd xmm0,xmm0,0x8
    1df1:	66 44 0f 62 f8       	punpckldq xmm15,xmm0
    1df6:	66 0f 6f c2          	movdqa xmm0,xmm2
    1dfa:	66 41 0f d4 c0       	paddq  xmm0,xmm8
    1dff:	66 41 0f fe cf       	paddd  xmm1,xmm15
    1e04:	66 45 0f 6f fe       	movdqa xmm15,xmm14
    1e09:	0f c6 c3 88          	shufps xmm0,xmm3,0x88
    1e0d:	66 0f fe c6          	paddd  xmm0,xmm6
    1e11:	66 44 0f 69 fd       	punpckhwd xmm15,xmm5
    1e16:	66 44 0f 61 f5       	punpcklwd xmm14,xmm5
    1e1b:	66 0f 6f d8          	movdqa xmm3,xmm0
    1e1f:	66 0f 73 d0 20       	psrlq  xmm0,0x20
    1e24:	66 41 0f f4 df       	pmuludq xmm3,xmm15
    1e29:	66 41 0f 73 d7 20    	psrlq  xmm15,0x20
    1e2f:	66 41 0f f4 c7       	pmuludq xmm0,xmm15
    1e34:	66 44 0f 6f 7d e0    	movdqa xmm15,XMMWORD PTR [rbp-0x20]
    1e3a:	66 44 0f d4 fa       	paddq  xmm15,xmm2
    1e3f:	66 0f 70 db 08       	pshufd xmm3,xmm3,0x8
    1e44:	66 0f 70 c0 08       	pshufd xmm0,xmm0,0x8
    1e49:	66 0f 62 d8          	punpckldq xmm3,xmm0
    1e4d:	66 0f 6f c2          	movdqa xmm0,xmm2
    1e51:	66 0f d4 55 d0       	paddq  xmm2,XMMWORD PTR [rbp-0x30]
    1e56:	41 0f c6 c7 88       	shufps xmm0,xmm15,0x88
    1e5b:	66 0f fe c6          	paddd  xmm0,xmm6
    1e5f:	66 0f 6f e8          	movdqa xmm5,xmm0
    1e63:	66 0f 73 d0 20       	psrlq  xmm0,0x20
    1e68:	66 41 0f f4 ee       	pmuludq xmm5,xmm14
    1e6d:	66 41 0f 73 d6 20    	psrlq  xmm14,0x20
    1e73:	66 41 0f f4 c6       	pmuludq xmm0,xmm14
    1e78:	66 0f 70 ed 08       	pshufd xmm5,xmm5,0x8
    1e7d:	66 0f 70 c0 08       	pshufd xmm0,xmm0,0x8
    1e82:	66 0f 62 e8          	punpckldq xmm5,xmm0
    1e86:	66 0f fe dd          	paddd  xmm3,xmm5
    1e8a:	66 0f fe cb          	paddd  xmm1,xmm3
    1e8e:	66 0f fe e1          	paddd  xmm4,xmm1
    1e92:	48 39 ca             	cmp    rdx,rcx
    1e95:	0f 85 a5 fe ff ff    	jne    1d40 <lab15_cross_check+0xe0>
    1e9b:	66 0f 6f c4          	movdqa xmm0,xmm4
    1e9f:	66 0f 73 d8 08       	psrldq xmm0,0x8
    1ea4:	66 0f fe e0          	paddd  xmm4,xmm0
    1ea8:	66 0f 6f c4          	movdqa xmm0,xmm4
    1eac:	66 0f 73 d8 04       	psrldq xmm0,0x4
    1eb1:	66 0f fe e0          	paddd  xmm4,xmm0
    1eb5:	66 0f 7e e2          	movd   edx,xmm4
    1eb9:	4c 39 c0             	cmp    rax,r8
    1ebc:	74 18                	je     1ed6 <lab15_cross_check+0x276>
    1ebe:	66 90                	xchg   ax,ax
    1ec0:	41 0f b6 3c 01       	movzx  edi,BYTE PTR [r9+rax*1]
    1ec5:	8d 48 01             	lea    ecx,[rax+0x1]
    1ec8:	48 83 c0 01          	add    rax,0x1
    1ecc:	0f af cf             	imul   ecx,edi
    1ecf:	01 ca                	add    edx,ecx
    1ed1:	4c 39 c0             	cmp    rax,r8
    1ed4:	72 ea                	jb     1ec0 <lab15_cross_check+0x260>
    1ed6:	31 d6                	xor    esi,edx
    1ed8:	c9                   	leave
    1ed9:	31 c0                	xor    eax,eax
    1edb:	41 39 f2             	cmp    r10d,esi
    1ede:	0f 94 c0             	sete   al
    1ee1:	c3                   	ret
    1ee2:	31 c0                	xor    eax,eax
    1ee4:	31 d2                	xor    edx,edx
    1ee6:	eb d8                	jmp    1ec0 <lab15_cross_check+0x260>

Disassembly of section .fini:
```

## Actual GDB/pwndbg entry evidence

```text
RAX  0
 RBX  0xd7f4b7c23fe7846b
 RCX  0x7fffffffdfbb ◂— 0x7cd8c469209
 RDX  0
 RDI  0x7fffffffe0b0 ◂— 0x722d726f746e656d ('mentor-r')
 RSI  0x10
 R8   0xd7f4b7c23fe7846b
 R9   3
 RSP  0x7fffffffdf98 —▸ 0x555555555399 (main+793) ◂— lea rdx, [rbp - 0x60]
 RIP  0x555555555c60 (lab15_cross_check) ◂— push rbp
   0x555555555c61 <lab15_cross_check+1>     mov    r8, rsi       R8 => 0x10
   0x555555555c64 <lab15_cross_check+4>     mov    r9, rdi       R9 => 0x7fffffffe0b0 ◂— 0x722d726f746e656d ('mentor-r')
   0x555555555c67 <lab15_cross_check+7>     mov    r10d, edx     R10D => 0
   0x555555555c6a <lab15_cross_check+10>    mov    rbp, rsp      RBP => 0x7fffffffdf90 —▸ 0x7fffffffe150 —▸ 0x7fffffffe200 —▸ 0x7fffffffe260 ◂— ...
   0x555555555c6d <lab15_cross_check+13>    sub    rsp, 0x30     RSP => 0x7fffffffdf60 (0x7fffffffdf90 - 0x30)
   0x555555555c71 <lab15_cross_check+17>    call   lab01_rolling_hash          <lab01_rolling_hash>
   0x555555555c76 <lab15_cross_check+22>    mov    esi, eax
   0x555555555c78 <lab15_cross_check+24>    test   r8, r8
   0x555555555c7b <lab15_cross_check+27>    je     lab15_cross_check+632       <lab15_cross_check+632>
   0x555555555c81 <lab15_cross_check+33>    lea    rax, [r8 - 1]
=> 0x555555555c60 <lab15_cross_check>:	push   rbp
   0x555555555c61 <lab15_cross_check+1>:	mov    r8,rsi
```

## Mentor reconstruction

1. **Establish ABI inputs.** Read the SysV argument registers at entry and compare them with the first uses before any overwrite.
2. **Build the CFG.** Mark every conditional, loop back edge, call, indirect target, and return value.
3. **Recover data semantics.** Assign types only from widths, extensions, address arithmetic, and cross-function use.
4. **Translate exact operations.** Preserve 32/64-bit wraparound, signedness, and bounds conditions.
5. **Validate.** The shown pwndbg state confirms the entry contract; the baseline output and caller supply an end-to-end result. Change one boundary input and predict the altered branch before executing it.

## Result

The recovered function is `lab15_cross_check` with entry RVA `0x1c60`. Ghidra’s stripped name has no semantics; the final name is justified by CFG and data flow, not debug symbols. The assembly and runtime state agree with the source contract above.

## Hard follow-up

Recompile at `-O0`, `-O3`, and with Clang. Diff basic blocks and instruction selection while proving that the externally observable contract remains equivalent.

# Twenty Practice Questions

1. Why analyze a stripped copy made from the same debug binary?
2. Why record RVAs rather than runtime VAs?
3. How was the callback signature in lab07 proven?
4. What proves lab05 is lower-bound search?
5. What is the invariant in lab02?
6. How do you distinguish lab04 states from arbitrary constants?
7. What proves Node.next is offset 8/16 as laid out?
8. Why can Ghidra’s C still be wrong?
9. How do repeated recursive breakpoints help lab10?
10. What is the security boundary in lab13?
11. Why is lab12 not necessarily cryptography?
12. How do you recover matrix dimensions?
13. What proves lab09 table entries are function pointers?
14. How do you test lab14 wraparound?
15. What is lost by stripping?
16. Why compile with fno-inline?
17. What does movzx reveal?
18. How do you validate lab03 little-endian fields?
19. Why is one successful input insufficient?
20. What is the final mastery standard?

# Complete Solutions

## 1. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** It preserves identical code/layout while removing names. A separately compiled stripped build can differ because compilation is not guaranteed deterministic across invocations.
4. Validate the answer against at least one opposite or boundary case.

## 2. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** PIE/ASLR changes runtime base. RVA remains stable and maps by runtime_base+RVA.
4. Validate the answer against at least one opposite or boundary case.

## 3. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** The indirect target is called with the current accumulator and array element; its return becomes the next accumulator. Dynamic targets share the same ABI.
4. Validate the answer against at least one opposite or boundary case.

## 4. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Equality is tested only after convergence; the loop moves hi on a[mid]>=key and lo on less.
4. Validate the answer against at least one opposite or boundary case.

## 5. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Before every expansion, count<=cap-w, and input has a complete count/value pair.
4. Validate the answer against at least one opposite or boundary case.

## 6. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Each state controls a distinct character-class transition and only terminal state returns accumulated value.
4. Validate the answer against at least one opposite or boundary case.

## 7. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** The actual assembly width/offset, repeated dereference, null test, and caller construction; exact offsets must be read from listing, not assumed from source order.
4. Validate the answer against at least one opposite or boundary case.

## 8. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Types, signedness, function boundaries, aliases, and structured syntax are inferences. Assembly/runtime evidence is authoritative.
4. Validate the answer against at least one opposite or boundary case.

## 9. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Entry argument sequence exposes n→n/2 until base, establishing recursion and call-tree depth.
4. Validate the answer against at least one opposite or boundary case.

## 10. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Untrusted TLV length must never exceed remaining bytes before handler reads or pointer advance.
4. Validate the answer against at least one opposite or boundary case.

## 11. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Xorshift and XOR create a stream transform, but security requires a threat model and cryptographic analysis; algorithm shape alone is insufficient.
4. Validate the answer against at least one opposite or boundary case.

## 12. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Observe element scale, row-stride update, loop bounds, and caller allocation/layout.
4. Validate the answer against at least one opposite or boundary case.

## 13. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Pointer-sized indexed load followed by indirect control transfer; runtime target resolves into executable mappings and known callback-shaped bodies.
4. Validate the answer against at least one opposite or boundary case.

## 14. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Perform 16 pushes, verify full error on 17th, pop/push across index 15→0, and confirm FIFO order and count.
4. Validate the answer against at least one opposite or boundary case.

## 15. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Names/debug types/source mappings, not machine instructions or necessary runtime behavior.
4. Validate the answer against at least one opposite or boundary case.

## 16. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** It keeps fifteen analyzable function boundaries for the teaching corpus; later optimized/inlined rebuilds test boundary recovery.
4. Validate the answer against at least one opposite or boundary case.

## 17. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** A narrower source is zero-extended, supporting unsigned interpretation and exact source width.
4. Validate the answer against at least one opposite or boundary case.

## 18. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Compare byte offsets and loads, mutate one field byte at a time, and observe decoded value/branch.
4. Validate the answer against at least one opposite or boundary case.

## 19. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** It proves only one path. Opposite and boundary inputs are needed to falsify the recovered condition and error behavior.
4. Validate the answer against at least one opposite or boundary case.

## 20. Solution

1. Identify the machine-level evidence relevant to the question.
2. Reject any claim supported only by a decompiler label or one trace.
3. **Answer:** Predict arguments, branch path, memory effects, and return for an unseen input, then confirm with Ghidra/GDB evidence without consulting source.
4. Validate the answer against at least one opposite or boundary case.


# Evidence Files

- Source: `reversing-walkthrough-lab/ch01/ch01_foundations.c`
- Ghidra export: `evidence/ch01/ghidra-stripped.txt`
- Objdump: `evidence/ch01/objdump.txt`
- pwndbg transcript: `evidence/ch01/pwndbg.txt`

Return to [[Chapter 01 - Foundations]].
