# Chapter 3 — Fifteen Complete Windows-Model Walkthroughs

> [!precision]
> These are executed x86-64 models of Windows concepts, compiled as ELF so GDB/pwndbg can trace them locally. The algorithms—PE bounds, RVA translation, handles, regions, statuses, atomic state, UTF-16, imports—are real and fully executed. Exact Windows loader/ABI conclusions must be validated on PE/Windows and are not falsely attributed to this ELF harness.

## Actual build and output

```text
chapter03 evidence=9260071809083536236 raw=c34 refs=2 bits=11
Ghidra stripped analysis + 15 pwndbg breakpoints completed
```

## Complete source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;

typedef struct { uint32_t va,vsize,raw,raw_size,chars; } Section;
typedef struct { uint64_t object; uint32_t access; uint16_t generation,type; } HandleEntry;
typedef struct { uint64_t start,end;uint32_t protect,state; } Region;
typedef struct { uint64_t rip,rsp;uint64_t gpr[8];uint32_t flags,tid; } ThreadContext;
typedef struct { int32_t status;uint32_t information;uint64_t event,apc; } IoStatus;

NI int lab01_pe_magic(const uint8_t *p,size_t n){
    if(n<0x40||p[0]!='M'||p[1]!='Z')return -1;uint32_t off;memcpy(&off,p+0x3c,4);
    if(off>n-4||memcmp(p+off,"PE\0\0",4))return -2;return (int)off;
}
NI int lab02_rva_to_raw(const Section *s,size_t n,uint32_t rva,uint32_t *raw){
    for(size_t i=0;i<n;i++){uint32_t span=s[i].vsize>s[i].raw_size?s[i].vsize:s[i].raw_size;
        if(rva>=s[i].va && rva-s[i].va<span){uint32_t d=rva-s[i].va;if(d>=s[i].raw_size)return -2;*raw=s[i].raw+d;return 0;}}
    return -1;
}
NI uint64_t lab03_resolve_handle(const HandleEntry *t,size_t n,uint32_t h,uint32_t desired){
    uint32_t index=h>>2;if(index>=n)return 0;const HandleEntry *e=&t[index];
    if(e->generation!=(uint16_t)(h>>16)||(desired&~e->access))return 0;return e->object;
}
NI int lab04_region_lookup(const Region *r,size_t n,uint64_t address){
    size_t lo=0,hi=n;while(lo<hi){size_t m=lo+(hi-lo)/2;if(address<r[m].start)hi=m;else if(address>=r[m].end)lo=m+1;else return (int)m;}return -1;
}
NI uint32_t lab05_page_permissions(uint32_t pte){
    uint32_t out=0;if(pte&1)out|=1;if(pte&2)out|=2;if(!(pte&0x80000000u))out|=4;if(pte&0x100)out|=8;return out;
}
NI uint64_t lab06_section_offset(uint64_t view_base,uint64_t file_offset,uint64_t address){
    if(address<view_base)return UINT64_MAX;return file_offset+(address-view_base);
}
NI int lab07_reference_object(uint32_t *refs,int operation){
    if(operation>0){if(*refs==UINT32_MAX)return -1;return (int)++*refs;}
    if(operation<0){if(*refs==0)return -2;return (int)--*refs;}return (int)*refs;
}
NI uint64_t lab08_context_checksum(const ThreadContext *c){
    uint64_t x=c->rip^c->rsp^((uint64_t)c->flags<<32)^c->tid;for(int i=0;i<8;i++)x=(x<<9)|(x>>55),x^=c->gpr[i];return x;
}
NI uint32_t lab09_interlocked_or(uint32_t *p,uint32_t mask){
    return __atomic_fetch_or(p,mask,__ATOMIC_SEQ_CST);
}
NI int lab10_wait_state(uint32_t signal,uint32_t timeout,uint32_t alerted){
    if(alerted)return 0x101;if(signal)return 0;if(timeout==0)return 0x102;return 0x103;
}
NI int lab11_native_status(int32_t status){
    if(status>=0)return 1;if((uint32_t)status==0xc0000008u)return -8;if((uint32_t)status==0xc0000005u)return -5;return -1;
}
NI uint64_t lab12_iosb_complete(IoStatus *s,int32_t status,uint32_t info,uint64_t event){
    s->status=status;s->information=info;s->event=event;return status>=0?info:0;
}
NI int lab13_unicode_equal(const uint16_t *a,size_t an,const uint16_t *b,size_t bn,int fold){
    if(an!=bn)return 0;for(size_t i=0;i<an;i++){uint16_t x=a[i],y=b[i];if(fold){if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;}if(x!=y)return 0;}return 1;
}
NI int lab14_exception_dispatch(uint32_t code,uint64_t address,const Region *r,size_t n){
    int i=lab04_region_lookup(r,n,address);if(i<0)return -1;if(code==0xc0000005u)return (r[i].protect&2)?1:0;if(code==0x80000003u)return 2;return 3;
}
NI uint32_t lab15_import_lookup(const char *const *names,const uint16_t *ords,size_t n,const char *wanted){
    size_t lo=0,hi=n;while(lo<hi){size_t m=lo+(hi-lo)/2;int c=strcmp(names[m],wanted);if(c<0)lo=m+1;else hi=m;}
    return lo<n&&!strcmp(names[lo],wanted)?ords[lo]:UINT32_MAX;
}

int main(void){
    uint8_t pe[128]={0};pe[0]='M';pe[1]='Z';uint32_t po=64;memcpy(pe+0x3c,&po,4);memcpy(pe+64,"PE\0\0",4);
    Section sec[]={{0x1000,0x600,0x400,0x600,5},{0x2000,0x900,0xa00,0x800,3}};uint32_t raw;
    HandleEntry ht[4]={{0},{0x12345000,7,2,1},{0},{0}};uint32_t h=(2u<<16)|(1u<<2);
    Region reg[]={{0x1000,0x2000,5,1},{0x4000,0x6000,3,1},{0x9000,0xa000,1,1}};
    ThreadContext c={0x401000,0x7fff0000,{1,2,3,4,5,6,7,8},0x202,77};
    IoStatus io={0};uint32_t refs=1,bits=1;uint16_t u1[]={'K','e','r','n','e','l'},u2[]={'k','E','R','N','E','L'};
    const char *names[]={"CloseHandle","CreateFileW","ReadFile","WriteFile"};uint16_t ords[]={7,19,44,51};
    uint64_t total=0;total+=lab01_pe_magic(pe,sizeof pe);total+=lab02_rva_to_raw(sec,2,0x2234,&raw)+raw;
    total+=lab03_resolve_handle(ht,4,h,3);total+=lab04_region_lookup(reg,3,0x4500);
    total+=lab05_page_permissions(0x103);total+=lab06_section_offset(0x400000,0x1000,0x401234);
    total+=lab07_reference_object(&refs,1);total+=lab08_context_checksum(&c);
    total+=lab09_interlocked_or(&bits,0x10);total+=lab10_wait_state(0,10,0);
    total+=lab11_native_status((int32_t)0xc0000008u);total+=lab12_iosb_complete(&io,0,128,0x55);
    total+=lab13_unicode_equal(u1,6,u2,6,1);total+=lab14_exception_dispatch(0xc0000005u,0x4500,reg,3);
    total+=lab15_import_lookup(names,ords,4,"ReadFile");
    evidence_sink=total;printf("chapter03 evidence=%llu raw=%x refs=%u bits=%x\n",(unsigned long long)total,raw,refs,bits);return 0;
}
```

# Walkthrough 01 — PE signature and e_lfanew

## Reversing problem

Recover `FUN_001015c0` without names. Recover DOS magic, bounds-safe e_lfanew load, PE signature, and distinct error codes.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_001015c0
ENTRY 001015c0
SIGNATURE undefined FUN_001015c0(void)
CALLERS 00102124, 00102200, 001012bc

ulong FUN_001015c0(char *param_1,ulong param_2)

{
  ulong uVar1;

  if (((0x3f < param_2) && (*param_1 == 'M')) && (param_1[1] == 'Z')) {
    uVar1 = (ulong)*(uint *)(param_1 + 0x3c);
    if ((uVar1 <= param_2 - 4) && (*(int *)(param_1 + uVar1) == 0x4550)) {
      return uVar1;
    }
    return 0xfffffffe;
  }
  return 0xffffffff;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000015c0 <lab01_pe_magic>:
    15c0:	48 83 fe 3f          	cmp    rsi,0x3f
    15c4:	76 2a                	jbe    15f0 <lab01_pe_magic+0x30>
    15c6:	80 3f 4d             	cmp    BYTE PTR [rdi],0x4d
    15c9:	75 25                	jne    15f0 <lab01_pe_magic+0x30>
    15cb:	80 7f 01 5a          	cmp    BYTE PTR [rdi+0x1],0x5a
    15cf:	75 1f                	jne    15f0 <lab01_pe_magic+0x30>
    15d1:	8b 57 3c             	mov    edx,DWORD PTR [rdi+0x3c]
    15d4:	48 83 ee 04          	sub    rsi,0x4
    15d8:	48 89 d0             	mov    rax,rdx
    15db:	48 39 d6             	cmp    rsi,rdx
    15de:	72 20                	jb     1600 <lab01_pe_magic+0x40>
    15e0:	81 3c 17 50 45 00 00 	cmp    DWORD PTR [rdi+rdx*1],0x4550
    15e7:	75 17                	jne    1600 <lab01_pe_magic+0x40>
    15e9:	c3                   	ret
    15ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    15f0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    15f5:	c3                   	ret
    15f6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    15fd:	00 00 00
    1600:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1605:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x33002c00130007
 RBX  0
 RCX  0x7fffffffdf14 ◂— 0x100000000
 RDX  0x7fffffffe2a8 —▸ 0x7fffffffe67d ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x7fffffffe0a0 ◂— 0x5a4d /* 'MZ' */
 RSI  0x80
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffdef8 —▸ 0x5555555552c1 (main+577) ◂— mov edx, 0x2234
 RIP  0x5555555555c0 (lab01_pe_magic) ◂— cmp rsi, 0x3f
   0x5555555555c4 <lab01_pe_magic+4>   ✘ jbe    lab01_pe_magic+48           <lab01_pe_magic+48>
   0x5555555555c6 <lab01_pe_magic+6>     cmp    byte ptr [rdi], 0x4d     0x4d - 0x4d     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555555c9 <lab01_pe_magic+9>   ✘ jne    lab01_pe_magic+48           <lab01_pe_magic+48>
   0x5555555555cb <lab01_pe_magic+11>    cmp    byte ptr [rdi + 1], 0x5a     0x5a - 0x5a     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555555cf <lab01_pe_magic+15>  ✘ jne    lab01_pe_magic+48           <lab01_pe_magic+48>
   0x5555555555d1 <lab01_pe_magic+17>    mov    edx, dword ptr [rdi + 0x3c]     EDX, [0x7fffffffe0dc] => 0x40
   0x5555555555d4 <lab01_pe_magic+20>    sub    rsi, 4                          RSI => 0x7c (0x80 - 0x4)
   0x5555555555d8 <lab01_pe_magic+24>    mov    rax, rdx                        RAX => 0x40
   0x5555555555db <lab01_pe_magic+27>    cmp    rsi, rdx                        0x7c - 0x40     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555555de <lab01_pe_magic+30>  ✘ jb     lab01_pe_magic+64           <lab01_pe_magic+64>
=> 0x5555555555c0 <lab01_pe_magic>:	cmp    rsi,0x3f
   0x5555555555c4 <lab01_pe_magic+4>:	jbe    0x5555555555f0 <lab01_pe_magic+48>
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab01_pe_magic` is mapped to stripped RVA `0x15c0`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 02 — RVA-to-file translation

## Reversing problem

Recover `FUN_00101610` without names. Recover section stride, max(VirtualSize,RawSize), delta, raw-backed rejection, and output pointer.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101610
ENTRY 00101610
SIGNATURE undefined FUN_00101610(void)
CALLERS 0010212c, 00102214, 001012d5

undefined8 FUN_00101610(uint *param_1,long param_2,uint param_3,int *param_4)

{
  uint uVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;

  lVar2 = 0;
  if (param_2 != 0) {
    do {
      if (*param_1 <= param_3) {
        uVar1 = param_1[3];
        uVar4 = param_3 - *param_1;
        uVar3 = param_1[1];
        if (param_1[1] <= uVar1) {
          uVar3 = uVar1;
        }
        if (uVar4 < uVar3) {
          if (uVar4 < uVar1) {
            *param_4 = uVar4 + param_1[2];
            return 0;
          }
          return 0xfffffffe;
        }
      }
      lVar2 = lVar2 + 1;
      param_1 = param_1 + 5;
    } while (param_2 != lVar2);
  }
  return 0xffffffff;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001610 <lab02_rva_to_raw>:
    1610:	49 89 f0             	mov    r8,rsi
    1613:	49 89 ca             	mov    r10,rcx
    1616:	89 d6                	mov    esi,edx
    1618:	31 c0                	xor    eax,eax
    161a:	4d 85 c0             	test   r8,r8
    161d:	74 2a                	je     1649 <lab02_rva_to_raw+0x39>
    161f:	90                   	nop
    1620:	8b 17                	mov    edx,DWORD PTR [rdi]
    1622:	39 d6                	cmp    esi,edx
    1624:	72 16                	jb     163c <lab02_rva_to_raw+0x2c>
    1626:	41 89 f1             	mov    r9d,esi
    1629:	8b 4f 0c             	mov    ecx,DWORD PTR [rdi+0xc]
    162c:	41 29 d1             	sub    r9d,edx
    162f:	8b 57 04             	mov    edx,DWORD PTR [rdi+0x4]
    1632:	39 d1                	cmp    ecx,edx
    1634:	0f 43 d1             	cmovae edx,ecx
    1637:	41 39 d1             	cmp    r9d,edx
    163a:	72 14                	jb     1650 <lab02_rva_to_raw+0x40>
    163c:	48 83 c0 01          	add    rax,0x1
    1640:	48 83 c7 14          	add    rdi,0x14
    1644:	49 39 c0             	cmp    r8,rax
    1647:	75 d7                	jne    1620 <lab02_rva_to_raw+0x10>
    1649:	b8 ff ff ff ff       	mov    eax,0xffffffff
    164e:	c3                   	ret
    164f:	90                   	nop
    1650:	41 39 c9             	cmp    r9d,ecx
    1653:	73 0a                	jae    165f <lab02_rva_to_raw+0x4f>
    1655:	44 03 4f 08          	add    r9d,DWORD PTR [rdi+0x8]
    1659:	31 c0                	xor    eax,eax
    165b:	45 89 0a             	mov    DWORD PTR [r10],r9d
    165e:	c3                   	ret
    165f:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1664:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x40
 RBX  0
 RCX  0x7fffffffdf14 ◂— 0x100000000
 RDX  0x2234
 RDI  0x7fffffffdf80 ◂— 0x60000001000
 RSI  2
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffdef8 —▸ 0x5555555552da (main+602) ◂— mov ecx, 3
 RIP  0x555555555610 (lab02_rva_to_raw) ◂— mov r8, rsi
   0x555555555613 <lab02_rva_to_raw+3>     mov    r10, rcx     R10 => 0x7fffffffdf14 ◂— 0x100000000
   0x555555555616 <lab02_rva_to_raw+6>     mov    esi, edx     ESI => 0x2234
   0x555555555618 <lab02_rva_to_raw+8>     xor    eax, eax     EAX => 0
   0x55555555561a <lab02_rva_to_raw+10>    test   r8, r8       2 & 2     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x55555555561d <lab02_rva_to_raw+13>  ✘ je     lab02_rva_to_raw+57         <lab02_rva_to_raw+57>
   0x55555555561f <lab02_rva_to_raw+15>    nop
   0x555555555620 <lab02_rva_to_raw+16>    mov    edx, dword ptr [rdi]     EDX, [0x7fffffffdf80] => 0x1000
   0x555555555622 <lab02_rva_to_raw+18>    cmp    esi, edx                 0x2234 - 0x1000     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555624 <lab02_rva_to_raw+20>  ✘ jb     lab02_rva_to_raw+44         <lab02_rva_to_raw+44>
   0x555555555626 <lab02_rva_to_raw+22>    mov    r9d, esi                 R9D => 0x2234
=> 0x555555555610 <lab02_rva_to_raw>:	mov    r8,rsi
   0x555555555613 <lab02_rva_to_raw+3>:	mov    r10,rcx
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab02_rva_to_raw` is mapped to stripped RVA `0x1610`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 03 — Encoded handle-table lookup

## Reversing problem

Recover `FUN_00101670` without names. Decode index/generation bits, bounds, access mask, and returned kernel-object surrogate.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101670
ENTRY 00101670
SIGNATURE undefined FUN_00101670(void)
CALLERS 00102134, 00102228, 001012f9

undefined8 FUN_00101670(long param_1,ulong param_2,uint param_3,uint param_4)

{
  undefined8 *puVar1;

  if (((param_3 >> 2 < param_2) &&
      (puVar1 = (undefined8 *)(param_1 + (ulong)(param_3 >> 2) * 0x10),
      *(short *)((long)puVar1 + 0xc) == (short)(param_3 >> 0x10))) &&
     ((~*(uint *)(puVar1 + 1) & param_4) == 0)) {
    return *puVar1;
  }
  return 0;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001670 <lab03_resolve_handle>:
    1670:	89 d0                	mov    eax,edx
    1672:	c1 e8 02             	shr    eax,0x2
    1675:	48 39 f0             	cmp    rax,rsi
    1678:	73 26                	jae    16a0 <lab03_resolve_handle+0x30>
    167a:	48 c1 e0 04          	shl    rax,0x4
    167e:	c1 ea 10             	shr    edx,0x10
    1681:	48 01 c7             	add    rdi,rax
    1684:	66 39 57 0c          	cmp    WORD PTR [rdi+0xc],dx
    1688:	75 16                	jne    16a0 <lab03_resolve_handle+0x30>
    168a:	8b 47 08             	mov    eax,DWORD PTR [rdi+0x8]
    168d:	f7 d0                	not    eax
    168f:	85 c8                	test   eax,ecx
    1691:	75 0d                	jne    16a0 <lab03_resolve_handle+0x30>
    1693:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    1696:	c3                   	ret
    1697:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    169e:	00 00
    16a0:	31 c0                	xor    eax,eax
    16a2:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  0
 RCX  3
 RDX  0x20004
 RDI  0x7fffffffdfb0 ◂— 0
 RSI  4
 R8   2
 R9   0xc34
 RSP  0x7fffffffdef8 —▸ 0x5555555552fe (main+638) ◂— mov edx, 0x4500
 RIP  0x555555555670 (lab03_resolve_handle) ◂— mov eax, edx
   0x555555555672 <lab03_resolve_handle+2>     shr    eax, 2
   0x555555555675 <lab03_resolve_handle+5>     cmp    rax, rsi     0x8001 - 0x4     EFLAGS => 0x212 [ cf pf AF zf sf IF df of ac ]
   0x555555555678 <lab03_resolve_handle+8>   ✔ jae    lab03_resolve_handle+48     <lab03_resolve_handle+48>
   0x5555555556a0 <lab03_resolve_handle+48>    xor    eax, eax     EAX => 0
   0x5555555556a2 <lab03_resolve_handle+50>    ret                                <main+638>
   0x5555555552fe <main+638>                   mov    edx, 0x4500            EDX => 0x4500
   0x555555555303 <main+643>                   mov    esi, 3                 ESI => 3
   0x555555555308 <main+648>                   lea    rdi, [rbp - 0x170]     RDI => 0x7fffffffdff0 ◂— 0x1000
   0x55555555530f <main+655>                   mov    r9, rax                R9 => 0
   0x555555555312 <main+658>                   call   lab04_region_lookup         <lab04_region_lookup>
=> 0x555555555670 <lab03_resolve_handle>:	mov    eax,edx
   0x555555555672 <lab03_resolve_handle+2>:	shr    eax,0x2
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab03_resolve_handle` is mapped to stripped RVA `0x1670`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 04 — Virtual-address region search

## Reversing problem

Recover `FUN_001016b0` without names. Recover binary search over sorted start/end regions and distinguish gaps from membership.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_001016b0
ENTRY 001016b0
SIGNATURE undefined FUN_001016b0(void)
CALLERS 0010213c, 0010223c, 00101312, 00101913

ulong FUN_001016b0(long param_1,ulong param_2,ulong param_3)

{
  ulong *puVar1;
  ulong uVar2;
  ulong uVar3;

  uVar2 = 0;
  while( true ) {
    do {
      uVar3 = param_2;
      if (uVar3 <= uVar2) {
        return 0xffffffff;
      }
      param_2 = (uVar3 - uVar2 >> 1) + uVar2;
      puVar1 = (ulong *)(param_1 + param_2 * 0x18);
    } while (param_3 < *puVar1);
    if (param_3 < puVar1[1]) break;
    uVar2 = param_2 + 1;
    param_2 = uVar3;
  }
  return param_2;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016b0 <lab04_region_lookup>:
    16b0:	49 89 f8             	mov    r8,rdi
    16b3:	48 89 d7             	mov    rdi,rdx
    16b6:	31 d2                	xor    edx,edx
    16b8:	eb 22                	jmp    16dc <lab04_region_lookup+0x2c>
    16ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    16c0:	48 89 f0             	mov    rax,rsi
    16c3:	48 29 d0             	sub    rax,rdx
    16c6:	48 d1 e8             	shr    rax,1
    16c9:	48 01 d0             	add    rax,rdx
    16cc:	48 8d 0c 40          	lea    rcx,[rax+rax*2]
    16d0:	49 8d 0c c8          	lea    rcx,[r8+rcx*8]
    16d4:	48 3b 39             	cmp    rdi,QWORD PTR [rcx]
    16d7:	73 17                	jae    16f0 <lab04_region_lookup+0x40>
    16d9:	48 89 c6             	mov    rsi,rax
    16dc:	48 39 f2             	cmp    rdx,rsi
    16df:	72 df                	jb     16c0 <lab04_region_lookup+0x10>
    16e1:	b8 ff ff ff ff       	mov    eax,0xffffffff
    16e6:	c3                   	ret
    16e7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    16ee:	00 00
    16f0:	48 3b 79 08          	cmp    rdi,QWORD PTR [rcx+0x8]
    16f4:	72 f0                	jb     16e6 <lab04_region_lookup+0x36>
    16f6:	48 8d 50 01          	lea    rdx,[rax+0x1]
    16fa:	eb e0                	jmp    16dc <lab04_region_lookup+0x2c>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  0
 RCX  3
 RDX  0x4500
 RDI  0x7fffffffdff0 ◂— 0x1000
 RSI  3
 R8   2
 R9   0
 RSP  0x7fffffffdef8 —▸ 0x555555555317 (main+663) ◂— mov edi, 0x103
 RIP  0x5555555556b0 (lab04_region_lookup) ◂— mov r8, rdi
   0x5555555556b3 <lab04_region_lookup+3>     mov    rdi, rdx     RDI => 0x4500
   0x5555555556b6 <lab04_region_lookup+6>     xor    edx, edx     EDX => 0
   0x5555555556b8 <lab04_region_lookup+8>     jmp    lab04_region_lookup+44      <lab04_region_lookup+44>
   0x5555555556dc <lab04_region_lookup+44>    cmp    rdx, rsi     0 - 3     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x5555555556df <lab04_region_lookup+47>  ✔ jb     lab04_region_lookup+16      <lab04_region_lookup+16>
   0x5555555556c0 <lab04_region_lookup+16>    mov    rax, rsi               RAX => 3
   0x5555555556c3 <lab04_region_lookup+19>    sub    rax, rdx               RAX => 3 (3 - 0)
   0x5555555556c6 <lab04_region_lookup+22>    shr    rax, 1
   0x5555555556c9 <lab04_region_lookup+25>    add    rax, rdx               RAX => 1 (1 + 0)
   0x5555555556cc <lab04_region_lookup+28>    lea    rcx, [rax + rax*2]     RCX => 3
=> 0x5555555556b0 <lab04_region_lookup>:	mov    r8,rdi
   0x5555555556b3 <lab04_region_lookup+3>:	mov    rdi,rdx
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab04_region_lookup` is mapped to stripped RVA `0x16b0`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 05 — PTE-like permission decoding

## Reversing problem

Recover `FUN_00101700` without names. Translate individual bits and inverted NX-style semantics into R/W/X/global output flags.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101700
ENTRY 00101700
SIGNATURE undefined FUN_00101700(void)
CALLERS 00102144, 00102250, 00101324

uint FUN_00101700(uint param_1)

{
  uint uVar1;

  uVar1 = param_1 & 3;
  if (-1 < (int)param_1) {
    uVar1 = param_1 & 3 | 4;
  }
  if ((param_1 & 0x100) != 0) {
    uVar1 = uVar1 | 8;
  }
  return uVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001700 <lab05_page_permissions>:
    1700:	89 f8                	mov    eax,edi
    1702:	83 e0 03             	and    eax,0x3
    1705:	89 c2                	mov    edx,eax
    1707:	83 ca 04             	or     edx,0x4
    170a:	85 ff                	test   edi,edi
    170c:	0f 49 c2             	cmovns eax,edx
    170f:	89 c2                	mov    edx,eax
    1711:	83 ca 08             	or     edx,0x8
    1714:	81 e7 00 01 00 00    	and    edi,0x100
    171a:	0f 45 c2             	cmovne eax,edx
    171d:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0
 RCX  0x7fffffffe008 ◂— 0x4000
 RDX  0
 RDI  0x103
 RSI  0x1000
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0
 RSP  0x7fffffffdef8 —▸ 0x555555555329 (main+681) ◂— mov edx, 0x401234
 RIP  0x555555555700 (lab05_page_permissions) ◂— mov eax, edi
   0x555555555702 <lab05_page_permissions+2>     and    eax, 3         EAX => 3 (0x103 & 0x3)
   0x555555555705 <lab05_page_permissions+5>     mov    edx, eax       EDX => 3
   0x555555555707 <lab05_page_permissions+7>     or     edx, 4         EDX => 7 (3 | 4)
   0x55555555570a <lab05_page_permissions+10>    test   edi, edi       0x103 & 0x103     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x55555555570c <lab05_page_permissions+12>  ✔ cmovns eax, edx
   0x55555555570f <lab05_page_permissions+15>    mov    edx, eax       EDX => 7
   0x555555555711 <lab05_page_permissions+17>    or     edx, 8         EDX => 0xf (7 | 8)
   0x555555555714 <lab05_page_permissions+20>    and    edi, 0x100     EDI => 0x100 (0x103 & 0x100)
   0x55555555571a <lab05_page_permissions+26>  ✔ cmovne eax, edx
   0x55555555571d <lab05_page_permissions+29>    ret                                <main+681>
=> 0x555555555700 <lab05_page_permissions>:	mov    eax,edi
   0x555555555702 <lab05_page_permissions+2>:	and    eax,0x3
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab05_page_permissions` is mapped to stripped RVA `0x1700`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 06 — Mapped-view address conversion

## Reversing problem

Recover `FUN_00101720` without names. Recover address>=base invariant and file_offset+(address-base), including UINT64_MAX failure.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101720
ENTRY 00101720
SIGNATURE undefined FUN_00101720(void)
CALLERS 0010214c, 00102264, 00101336

long FUN_00101720(ulong param_1,long param_2,ulong param_3)

{
  param_2 = (param_3 - param_1) + param_2;
  if (param_3 < param_1) {
    param_2 = -1;
  }
  return param_2;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001720 <lab06_section_offset>:
    1720:	48 89 d0             	mov    rax,rdx
    1723:	48 29 f8             	sub    rax,rdi
    1726:	48 01 f0             	add    rax,rsi
    1729:	48 39 fa             	cmp    rdx,rdi
    172c:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
    1733:	48 0f 42 c2          	cmovb  rax,rdx
    1737:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0xf
 RBX  0
 RCX  0x7fffffffe008 ◂— 0x4000
 RDX  0x401234
 RDI  0x400000
 RSI  0x1000
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0
 RSP  0x7fffffffdef8 —▸ 0x55555555533b (main+699) ◂— lea rdi, [rbp - 0x248]
 RIP  0x555555555720 (lab06_section_offset) ◂— mov rax, rdx
   0x555555555723 <lab06_section_offset+3>     sub    rax, rdi                    RAX => 0x1234 (0x401234 - 0x400000)
   0x555555555726 <lab06_section_offset+6>     add    rax, rsi                    RAX => 0x2234 (0x1234 + 0x1000)
   0x555555555729 <lab06_section_offset+9>     cmp    rdx, rdi                    0x401234 - 0x400000     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x55555555572c <lab06_section_offset+12>    mov    rdx, 0xffffffffffffffff     RDX => 0xffffffffffffffff
   0x555555555733 <lab06_section_offset+19>  ✘ cmovb  rax, rdx
   0x555555555737 <lab06_section_offset+23>    ret                                <main+699>
   0x55555555533b <main+699>                   lea    rdi, [rbp - 0x248]          RDI => 0x7fffffffdf18 ◂— 0x100000001
   0x555555555342 <main+706>                   mov    esi, 1                      ESI => 1
   0x555555555347 <main+711>                   add    r9, rax                     R9 => 0x2234 (0x0 + 0x2234)
   0x55555555534a <main+714>                   call   lab07_reference_object      <lab07_reference_object>
=> 0x555555555720 <lab06_section_offset>:	mov    rax,rdx
   0x555555555723 <lab06_section_offset+3>:	sub    rax,rdi
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab06_section_offset` is mapped to stripped RVA `0x1720`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 07 — Reference-count state machine

## Reversing problem

Recover `FUN_00101740` without names. Recover query/increment/decrement operations, overflow/underflow guards, and in-place mutation.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101740
ENTRY 00101740
SIGNATURE undefined FUN_00101740(void)
CALLERS 00102154, 00102278, 0010134a

int FUN_00101740(int *param_1,int param_2)

{
  int iVar1;

  iVar1 = *param_1;
  if (param_2 < 1) {
    if (param_2 != 0) {
      if (iVar1 != 0) {
        *param_1 = iVar1 + -1;
        return iVar1 + -1;
      }
      iVar1 = -2;
    }
    return iVar1;
  }
  if (iVar1 != -1) {
    *param_1 = iVar1 + 1;
    return iVar1 + 1;
  }
  return -1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001740 <lab07_reference_object>:
    1740:	8b 07                	mov    eax,DWORD PTR [rdi]
    1742:	85 f6                	test   esi,esi
    1744:	7e 12                	jle    1758 <lab07_reference_object+0x18>
    1746:	83 f8 ff             	cmp    eax,0xffffffff
    1749:	74 1f                	je     176a <lab07_reference_object+0x2a>
    174b:	83 c0 01             	add    eax,0x1
    174e:	89 07                	mov    DWORD PTR [rdi],eax
    1750:	c3                   	ret
    1751:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1758:	74 0f                	je     1769 <lab07_reference_object+0x29>
    175a:	85 c0                	test   eax,eax
    175c:	74 06                	je     1764 <lab07_reference_object+0x24>
    175e:	83 e8 01             	sub    eax,0x1
    1761:	89 07                	mov    DWORD PTR [rdi],eax
    1763:	c3                   	ret
    1764:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1769:	c3                   	ret
    176a:	b8 ff ff ff ff       	mov    eax,0xffffffff
    176f:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x2234
 RBX  0
 RCX  0x7fffffffe008 ◂— 0x4000
 RDX  0xffffffffffffffff
 RDI  0x7fffffffdf18 ◂— 0x100000001
 RSI  1
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0x2234
 RSP  0x7fffffffdef8 —▸ 0x55555555534f (main+719) ◂— lea rdi, [rbp - 0x120]
 RIP  0x555555555740 (lab07_reference_object) ◂— mov eax, dword ptr [rdi]
   0x555555555742 <lab07_reference_object+2>     test   esi, esi                 1 & 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555744 <lab07_reference_object+4>   ✘ jle    lab07_reference_object+24   <lab07_reference_object+24>
   0x555555555746 <lab07_reference_object+6>     cmp    eax, -1                  1 - -1     EFLAGS => 0x213 [ CF pf AF zf sf IF df of ac ]
   0x555555555749 <lab07_reference_object+9>   ✘ je     lab07_reference_object+42   <lab07_reference_object+42>
   0x55555555574b <lab07_reference_object+11>    add    eax, 1                   EAX => 2 (1 + 1)
   0x55555555574e <lab07_reference_object+14>    mov    dword ptr [rdi], eax     [0x7fffffffdf18] <= 2
   0x555555555750 <lab07_reference_object+16>    ret                                <main+719>
   0x55555555534f <main+719>                     lea    rdi, [rbp - 0x120]       RDI => 0x7fffffffe040 ◂— 0x401000
   0x555555555356 <main+726>                     mov    esi, 0x10                ESI => 0x10
   0x55555555535b <main+731>                     movsxd r10, eax                 R10 => 2
=> 0x555555555740 <lab07_reference_object>:	mov    eax,DWORD PTR [rdi]
   0x555555555742 <lab07_reference_object+2>:	test   esi,esi
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab07_reference_object` is mapped to stripped RVA `0x1740`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 08 — Thread-context structure

## Reversing problem

Recover `FUN_00101770` without names. Infer RIP/RSP, eight GPR slots, flags/TID fields, rotation loop, and structure offsets.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101770
ENTRY 00101770
SIGNATURE undefined FUN_00101770(void)
CALLERS 0010215c, 0010228c, 0010135e

ulong FUN_00101770(ulong *param_1)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *puVar3;

  uVar1 = *param_1 ^ param_1[1] ^ (ulong)*(uint *)((long)param_1 + 0x54) ^
          (ulong)(uint)param_1[10] << 0x20;
  puVar2 = param_1 + 2;
  do {
    puVar3 = puVar2 + 1;
    uVar1 = (uVar1 << 9 | uVar1 >> 0x37) ^ *puVar2;
    puVar2 = puVar3;
  } while (puVar3 != param_1 + 10);
  return uVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001770 <lab08_context_checksum>:
    1770:	8b 57 54             	mov    edx,DWORD PTR [rdi+0x54]
    1773:	48 8b 07             	mov    rax,QWORD PTR [rdi]
    1776:	48 33 47 08          	xor    rax,QWORD PTR [rdi+0x8]
    177a:	48 31 d0             	xor    rax,rdx
    177d:	8b 57 50             	mov    edx,DWORD PTR [rdi+0x50]
    1780:	48 c1 e2 20          	shl    rdx,0x20
    1784:	48 31 d0             	xor    rax,rdx
    1787:	48 8d 57 10          	lea    rdx,[rdi+0x10]
    178b:	48 83 c7 50          	add    rdi,0x50
    178f:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1795:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    179c:	00 00 00 00
    17a0:	48 c1 c0 09          	rol    rax,0x9
    17a4:	48 83 c2 08          	add    rdx,0x8
    17a8:	48 33 42 f8          	xor    rax,QWORD PTR [rdx-0x8]
    17ac:	48 39 fa             	cmp    rdx,rdi
    17af:	75 ef                	jne    17a0 <lab08_context_checksum+0x30>
    17b1:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  2
 RBX  0
 RCX  0x7fffffffe008 ◂— 0x4000
 RDX  0xffffffffffffffff
 RDI  0x7fffffffe040 ◂— 0x401000
 RSI  0x10
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0x2234
 RSP  0x7fffffffdef8 —▸ 0x555555555363 (main+739) ◂— lea rdi, [rbp - 0x244]
 RIP  0x555555555770 (lab08_context_checksum) ◂— mov edx, dword ptr [rdi + 0x54]
   0x555555555773 <lab08_context_checksum+3>     mov    rax, qword ptr [rdi]            RAX, [0x7fffffffe040] => 0x401000
   0x555555555776 <lab08_context_checksum+6>     xor    rax, qword ptr [rdi + 8]        RAX => 0x7fbf1000 (0x401000 ^ 0x7fff0000)
   0x55555555577a <lab08_context_checksum+10>    xor    rax, rdx                        RAX => 0x7fbf104d (0x7fbf1000 ^ 0x4d)
   0x55555555577d <lab08_context_checksum+13>    mov    edx, dword ptr [rdi + 0x50]     EDX, [0x7fffffffe090] => 0x202
   0x555555555780 <lab08_context_checksum+16>    shl    rdx, 0x20
   0x555555555784 <lab08_context_checksum+20>    xor    rax, rdx                        RAX => 0x2027fbf104d (0x7fbf104d ^ 0x20200000000)
   0x555555555787 <lab08_context_checksum+23>    lea    rdx, [rdi + 0x10]               RDX => 0x7fffffffe050 ◂— 1
   0x55555555578b <lab08_context_checksum+27>    add    rdi, 0x50                       RDI => 0x7fffffffe090 (0x7fffffffe040 + 0x50)
   0x55555555578f <lab08_context_checksum+31>    nop    word ptr [rax + rax]
   0x555555555795 <lab08_context_checksum+37>    nop    word ptr [rax + rax]
=> 0x555555555770 <lab08_context_checksum>:	mov    edx,DWORD PTR [rdi+0x54]
   0x555555555773 <lab08_context_checksum+3>:	mov    rax,QWORD PTR [rdi]
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab08_context_checksum` is mapped to stripped RVA `0x1770`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 09 — Atomic interlocked update

## Reversing problem

Recover `FUN_001017c0` without names. Recognize LOCK-prefixed read-modify-write, returned prior value, and sequentially consistent intent.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_001017c0
ENTRY 001017c0
SIGNATURE undefined FUN_001017c0(void)
CALLERS 00102164, 001022a0, 0010136e

uint FUN_001017c0(uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;

  uVar2 = *param_1;
  do {
    uVar1 = uVar2;
    LOCK();
    uVar2 = *param_1;
    bVar3 = uVar1 == uVar2;
    if (bVar3) {
      *param_1 = uVar1 | param_2;
      uVar2 = uVar1;
    }
    UNLOCK();
  } while (!bVar3);
  return uVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017c0 <lab09_interlocked_or>:
    17c0:	8b 07                	mov    eax,DWORD PTR [rdi]
    17c2:	89 c1                	mov    ecx,eax
    17c4:	89 c2                	mov    edx,eax
    17c6:	09 f1                	or     ecx,esi
    17c8:	f0 0f b1 0f          	lock cmpxchg DWORD PTR [rdi],ecx
    17cc:	75 f4                	jne    17c2 <lab09_interlocked_or+0x2>
    17ce:	89 d0                	mov    eax,edx
    17d0:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x8082623f97084308
 RBX  0
 RCX  0x7fffffffe008 ◂— 0x4000
 RDX  0x7fffffffe090 ◂— 0x4d00000202
 RDI  0x7fffffffdf1c ◂— 0xf7f7f74000000001
 RSI  0x10
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0x2234
 RSP  0x7fffffffdef8 —▸ 0x555555555373 (main+755) ◂— xor edx, edx
 RIP  0x5555555557c0 (lab09_interlocked_or) ◂— mov eax, dword ptr [rdi]
   0x5555555557c2 <lab09_interlocked_or+2>     mov    ecx, eax                       ECX => 1
   0x5555555557c4 <lab09_interlocked_or+4>     mov    edx, eax                       EDX => 1
   0x5555555557c6 <lab09_interlocked_or+6>     or     ecx, esi                       ECX => 0x11 (0x1 | 0x10)
   0x5555555557c8 <lab09_interlocked_or+8>     lock cmpxchg dword ptr [rdi], ecx
   0x5555555557cc <lab09_interlocked_or+12>  ✘ jne    lab09_interlocked_or+2      <lab09_interlocked_or+2>
   0x5555555557ce <lab09_interlocked_or+14>    mov    eax, edx                       EAX => 1
   0x5555555557d0 <lab09_interlocked_or+16>    ret                                <main+755>
   0x555555555373 <main+755>                   xor    edx, edx     EDX => 0
   0x555555555375 <main+757>                   xor    edi, edi     EDI => 0
   0x555555555377 <main+759>                   mov    esi, 0xa     ESI => 0xa
=> 0x5555555557c0 <lab09_interlocked_or>:	mov    eax,DWORD PTR [rdi]
   0x5555555557c2 <lab09_interlocked_or+2>:	mov    ecx,eax
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab09_interlocked_or` is mapped to stripped RVA `0x17c0`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 10 — Wait-result priority

## Reversing problem

Recover `FUN_001017e0` without names. Recover alert, signal, zero-timeout, and pending outcomes with ordering-dependent semantics.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_001017e0
ENTRY 001017e0
SIGNATURE undefined FUN_001017e0(void)
CALLERS 0010216c, 001022b4, 00101384

int FUN_001017e0(int param_1,int param_2,int param_3)

{
  int iVar1;

  iVar1 = 0x101;
  if ((param_3 == 0) && (iVar1 = 0x103 - (uint)(param_2 == 0), param_1 != 0)) {
    iVar1 = 0;
  }
  return iVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017e0 <lab10_wait_state>:
    17e0:	b8 01 01 00 00       	mov    eax,0x101
    17e5:	85 d2                	test   edx,edx
    17e7:	75 10                	jne    17f9 <lab10_wait_state+0x19>
    17e9:	83 fe 01             	cmp    esi,0x1
    17ec:	b8 02 01 00 00       	mov    eax,0x102
    17f1:	83 d8 ff             	sbb    eax,0xffffffff
    17f4:	85 ff                	test   edi,edi
    17f6:	0f 45 c2             	cmovne eax,edx
    17f9:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0
 RCX  0x55
 RDX  0
 RDI  0
 RSI  0xa
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   1
 RSP  0x7fffffffdef8 —▸ 0x555555555389 (main+777) ◂— mov edi, 0xc0000008
 RIP  0x5555555557e0 (lab10_wait_state) ◂— mov eax, 0x101
   0x5555555557e5 <lab10_wait_state+5>     test   edx, edx       0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555557e7 <lab10_wait_state+7>   ✘ jne    lab10_wait_state+25         <lab10_wait_state+25>
   0x5555555557e9 <lab10_wait_state+9>     cmp    esi, 1         0xa - 0x1     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555557ec <lab10_wait_state+12>    mov    eax, 0x102     EAX => 0x102
   0x5555555557f1 <lab10_wait_state+17>    sbb    eax, -1
   0x5555555557f4 <lab10_wait_state+20>    test   edi, edi       0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555557f6 <lab10_wait_state+22>  ✘ cmovne eax, edx
   0x5555555557f9 <lab10_wait_state+25>    ret                                <main+777>
   0x555555555389 <main+777>               mov    edi, 0xc0000008     EDI => 0xc0000008
   0x55555555538e <main+782>               xor    esi, esi            ESI => 0
=> 0x5555555557e0 <lab10_wait_state>:	mov    eax,0x101
   0x5555555557e5 <lab10_wait_state+5>:	test   edx,edx
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab10_wait_state` is mapped to stripped RVA `0x17e0`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 11 — NTSTATUS-style classification

## Reversing problem

Recover `FUN_00101800` without names. Use signed success test and exact high-bit error constants to recover status interpretation.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101800
ENTRY 00101800
SIGNATURE undefined FUN_00101800(void)
CALLERS 00102174, 001022c8, 00101398

int FUN_00101800(int param_1)

{
  int iVar1;

  iVar1 = 1;
  if (param_1 < 0) {
    if (param_1 != -0x3ffffff8) {
      return (uint)(param_1 != -0x3ffffffb) * 4 + -5;
    }
    iVar1 = -8;
  }
  return iVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001800 <lab11_native_status>:
    1800:	b8 01 00 00 00       	mov    eax,0x1
    1805:	85 ff                	test   edi,edi
    1807:	79 20                	jns    1829 <lab11_native_status+0x29>
    1809:	81 ff 08 00 00 c0    	cmp    edi,0xc0000008
    180f:	74 13                	je     1824 <lab11_native_status+0x24>
    1811:	31 c0                	xor    eax,eax
    1813:	81 ff 05 00 00 c0    	cmp    edi,0xc0000005
    1819:	0f 95 c0             	setne  al
    181c:	8d 04 85 fb ff ff ff 	lea    eax,[rax*4-0x5]
    1823:	c3                   	ret
    1824:	b8 f8 ff ff ff       	mov    eax,0xfffffff8
    1829:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x103
 RBX  0
 RCX  0x55
 RDX  0x80
 RDI  0xc0000008
 RSI  0
 R8   0x103
 R9   1
 RSP  0x7fffffffdef8 —▸ 0x55555555539d (main+797) ◂— lea rdi, [rbp - 0x240]
 RIP  0x555555555800 (lab11_native_status) ◂— mov eax, 1
   0x555555555805 <lab11_native_status+5>     test   edi, edi     0xc0000008 & 0xc0000008     EFLAGS => 0x282 [ cf pf af zf SF IF df of ac ]
   0x555555555807 <lab11_native_status+7>   ✘ jns    lab11_native_status+41      <lab11_native_status+41>
   0x555555555809 <lab11_native_status+9>     cmp    edi, 0xc0000008     0xc0000008 - 0xc0000008     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x55555555580f <lab11_native_status+15>  ✔ je     lab11_native_status+36      <lab11_native_status+36>
   0x555555555824 <lab11_native_status+36>    mov    eax, 0xfffffff8     EAX => 0xfffffff8
   0x555555555829 <lab11_native_status+41>    ret                                <main+797>
   0x55555555539d <main+797>                  lea    rdi, [rbp - 0x240]               RDI => 0x7fffffffdf20 —▸ 0x7ffff7f7f740 ◂— 0x7ffff7f7f740
   0x5555555553a4 <main+804>                  mov    dword ptr [rbp - 0x254], eax     [0x7fffffffdf0c] <= 0xfffffff8
   0x5555555553aa <main+810>                  call   lab12_iosb_complete         <lab12_iosb_complete>
   0x5555555553af <main+815>                  mov    ecx, 6                           ECX => 6
=> 0x555555555800 <lab11_native_status>:	mov    eax,0x1
   0x555555555805 <lab11_native_status+5>:	test   edi,edi
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab11_native_status` is mapped to stripped RVA `0x1800`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 12 — I/O status block completion

## Reversing problem

Recover `FUN_00101830` without names. Infer field offsets/widths, status-dependent returned information, and caller-owned output object.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101830
ENTRY 00101830
SIGNATURE undefined FUN_00101830(void)
CALLERS 0010217c, 001022dc, 001013aa

int FUN_00101830(int *param_1,int param_2,int param_3,undefined8 param_4)

{
  int iVar1;

  *param_1 = param_2;
  param_1[1] = param_3;
  iVar1 = 0;
  if (-1 < param_2) {
    iVar1 = param_3;
  }
  *(undefined8 *)(param_1 + 2) = param_4;
  return iVar1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001830 <lab12_iosb_complete>:
    1830:	31 c0                	xor    eax,eax
    1832:	85 f6                	test   esi,esi
    1834:	89 37                	mov    DWORD PTR [rdi],esi
    1836:	89 57 04             	mov    DWORD PTR [rdi+0x4],edx
    1839:	0f 49 c2             	cmovns eax,edx
    183c:	48 89 4f 08          	mov    QWORD PTR [rdi+0x8],rcx
    1840:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0xfffffff8
 RBX  0
 RCX  0x55
 RDX  0x80
 RDI  0x7fffffffdf20 —▸ 0x7ffff7f7f740 ◂— 0x7ffff7f7f740
 RSI  0
 R8   0x103
 R9   1
 RSP  0x7fffffffdef8 —▸ 0x5555555553af (main+815) ◂— mov ecx, 6
 RIP  0x555555555830 (lab12_iosb_complete) ◂— xor eax, eax
   0x555555555832 <lab12_iosb_complete+2>     test   esi, esi                     0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555834 <lab12_iosb_complete+4>     mov    dword ptr [rdi], esi         [0x7fffffffdf20] <= 0
   0x555555555836 <lab12_iosb_complete+6>     mov    dword ptr [rdi + 4], edx     [0x7fffffffdf24] <= 0x80
   0x555555555839 <lab12_iosb_complete+9>   ✔ cmovns eax, edx
   0x55555555583c <lab12_iosb_complete+12>    mov    qword ptr [rdi + 8], rcx     [0x7fffffffdf28] <= 0x55
   0x555555555840 <lab12_iosb_complete+16>    ret                                <main+815>
   0x5555555553af <main+815>                  mov    ecx, 6                 ECX => 6
   0x5555555553b4 <main+820>                  mov    esi, 6                 ESI => 6
   0x5555555553b9 <main+825>                  lea    rdx, [rbp - 0x210]     RDX => 0x7fffffffdf50 ◂— 0x4e00520045006b /* 'k' */
   0x5555555553c0 <main+832>                  add    rax, r15               RAX => 0x8082623f970865bc (0x80 + 0x8082623f9708653c)
=> 0x555555555830 <lab12_iosb_complete>:	xor    eax,eax
   0x555555555832 <lab12_iosb_complete+2>:	test   esi,esi
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab12_iosb_complete` is mapped to stripped RVA `0x1830`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 13 — UTF-16-like case folding

## Reversing problem

Recover `FUN_00101850` without names. Recover 16-bit element width, equal-length gate, ASCII folding, and exact comparison loop.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101850
ENTRY 00101850
SIGNATURE undefined FUN_00101850(void)
CALLERS 00102184, 001022f0, 001013ec

undefined8 FUN_00101850(short *param_1,long param_2,short *param_3,long param_4,int param_5)

{
  long lVar1;
  short sVar2;
  short sVar3;
  long lVar4;

  if (param_2 != param_4) {
    return 0;
  }
  if (param_2 != 0) {
    sVar2 = *param_1;
    sVar3 = *param_3;
    lVar4 = 0;
    if (param_5 == 0) {
      lVar4 = 0;
      if (sVar2 != sVar3) {
        return 0;
      }
      do {
        lVar1 = lVar4 + 1;
        if (lVar1 == param_2) {
          return 1;
        }
        if (param_3[lVar1] != param_1[lVar1]) {
          return 0;
        }
        lVar4 = lVar4 + 2;
        if (param_2 == lVar4) {
          return 1;
        }
      } while (param_1[lVar4] == param_3[lVar4]);
      return 0;
    }
    while( true ) {
      if ((ushort)(sVar2 - 0x61U) < 0x1a) {
        sVar2 = sVar2 + -0x20;
      }
      if ((ushort)(sVar3 - 0x61U) < 0x1a) {
        sVar3 = sVar3 + -0x20;
      }
      if (sVar2 != sVar3) {
        return 0;
      }
      lVar4 = lVar4 + 1;
      if (param_2 == lVar4) break;
      sVar2 = param_1[lVar4];
      sVar3 = param_3[lVar4];
    }
  }
  return 1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001850 <lab13_unicode_equal>:
    1850:	49 89 d1             	mov    r9,rdx
    1853:	48 39 ce             	cmp    rsi,rcx
    1856:	75 30                	jne    1888 <lab13_unicode_equal+0x38>
    1858:	48 85 f6             	test   rsi,rsi
    185b:	74 33                	je     1890 <lab13_unicode_equal+0x40>
    185d:	0f b7 07             	movzx  eax,WORD PTR [rdi]
    1860:	0f b7 0a             	movzx  ecx,WORD PTR [rdx]
    1863:	45 31 d2             	xor    r10d,r10d
    1866:	45 85 c0             	test   r8d,r8d
    1869:	74 52                	je     18bd <lab13_unicode_equal+0x6d>
    186b:	44 8d 40 9f          	lea    r8d,[rax-0x61]
    186f:	8d 50 e0             	lea    edx,[rax-0x20]
    1872:	66 41 83 f8 1a       	cmp    r8w,0x1a
    1877:	0f 42 c2             	cmovb  eax,edx
    187a:	8d 51 9f             	lea    edx,[rcx-0x61]
    187d:	66 83 fa 19          	cmp    dx,0x19
    1881:	76 1d                	jbe    18a0 <lab13_unicode_equal+0x50>
    1883:	66 39 c8             	cmp    ax,cx
    1886:	74 20                	je     18a8 <lab13_unicode_equal+0x58>
    1888:	31 c0                	xor    eax,eax
    188a:	c3                   	ret
    188b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1890:	b8 01 00 00 00       	mov    eax,0x1
    1895:	c3                   	ret
    1896:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    189d:	00 00 00
    18a0:	83 e9 20             	sub    ecx,0x20
    18a3:	66 39 c8             	cmp    ax,cx
    18a6:	75 e0                	jne    1888 <lab13_unicode_equal+0x38>
    18a8:	49 83 c2 01          	add    r10,0x1
    18ac:	4c 39 d6             	cmp    rsi,r10
    18af:	74 df                	je     1890 <lab13_unicode_equal+0x40>
    18b1:	42 0f b7 04 57       	movzx  eax,WORD PTR [rdi+r10*2]
    18b6:	43 0f b7 0c 51       	movzx  ecx,WORD PTR [r9+r10*2]
    18bb:	eb ae                	jmp    186b <lab13_unicode_equal+0x1b>
    18bd:	31 d2                	xor    edx,edx
    18bf:	66 39 c8             	cmp    ax,cx
    18c2:	75 c4                	jne    1888 <lab13_unicode_equal+0x38>
    18c4:	48 8d 42 01          	lea    rax,[rdx+0x1]
    18c8:	48 39 f0             	cmp    rax,rsi
    18cb:	74 c3                	je     1890 <lab13_unicode_equal+0x40>
    18cd:	0f b7 0c 47          	movzx  ecx,WORD PTR [rdi+rax*2]
    18d1:	66 41 39 0c 41       	cmp    WORD PTR [r9+rax*2],cx
    18d6:	75 b0                	jne    1888 <lab13_unicode_equal+0x38>
    18d8:	48 83 c2 02          	add    rdx,0x2
    18dc:	48 39 d6             	cmp    rsi,rdx
    18df:	74 af                	je     1890 <lab13_unicode_equal+0x40>
    18e1:	0f b7 04 57          	movzx  eax,WORD PTR [rdi+rdx*2]
    18e5:	41 0f b7 0c 51       	movzx  ecx,WORD PTR [r9+rdx*2]
    18ea:	66 39 c8             	cmp    ax,cx
    18ed:	74 d5                	je     18c4 <lab13_unicode_equal+0x74>
    18ef:	eb 97                	jmp    1888 <lab13_unicode_equal+0x38>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0xfffffffffffffff8
 RBX  0
 RCX  6
 RDX  0x7fffffffdf50 ◂— 0x4e00520045006b /* 'k' */
 RDI  0x7fffffffdf40 ◂— 0x6e00720065004b /* 'K' */
 RSI  6
 R8   1
 R9   1
 RSP  0x7fffffffdef8 —▸ 0x5555555553f1 (main+881) ◂— mov ecx, 3
 RIP  0x555555555850 (lab13_unicode_equal) ◂— mov r9, rdx
   0x555555555853 <lab13_unicode_equal+3>     cmp    rsi, rcx     6 - 6     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555856 <lab13_unicode_equal+6>   ✘ jne    lab13_unicode_equal+56      <lab13_unicode_equal+56>
   0x555555555858 <lab13_unicode_equal+8>     test   rsi, rsi     6 & 6     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x55555555585b <lab13_unicode_equal+11>  ✘ je     lab13_unicode_equal+64      <lab13_unicode_equal+64>
   0x55555555585d <lab13_unicode_equal+13>    movzx  eax, word ptr [rdi]     EAX, [0x7fffffffdf40] => 0x4b
   0x555555555860 <lab13_unicode_equal+16>    movzx  ecx, word ptr [rdx]     ECX, [0x7fffffffdf50] => 0x6b
   0x555555555863 <lab13_unicode_equal+19>    xor    r10d, r10d              R10D => 0
   0x555555555866 <lab13_unicode_equal+22>    test   r8d, r8d                1 & 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555869 <lab13_unicode_equal+25>  ✘ je     lab13_unicode_equal+109     <lab13_unicode_equal+109>
   0x55555555586b <lab13_unicode_equal+27>    lea    r8d, [rax - 0x61]       R8D => 0xffffffffffffffea
=> 0x555555555850 <lab13_unicode_equal>:	mov    r9,rdx
   0x555555555853 <lab13_unicode_equal+3>:	cmp    rsi,rcx
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab13_unicode_equal` is mapped to stripped RVA `0x1850`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 14 — Exception and region dispatch

## Reversing problem

Recover `FUN_00101900` without names. Compose region lookup with access-violation/breakpoint codes and protection-dependent handling.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101900
ENTRY 00101900
SIGNATURE undefined FUN_00101900(void)
CALLERS 0010218c, 00102304, 0010140c

uint FUN_00101900(int param_1,undefined8 param_2,long param_3,undefined8 param_4)

{
  uint uVar1;

  uVar1 = FUN_001016b0(param_3,param_4,param_2);
  if ((int)uVar1 < 0) {
    return 0xffffffff;
  }
  if (param_1 != -0x3ffffffb) {
    return (param_1 != -0x7ffffffd) + 2;
  }
  return *(uint *)(param_3 + 0x10 + (ulong)uVar1 * 0x18) >> 1 & 1;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001900 <lab14_exception_dispatch>:
    1900:	55                   	push   rbp
    1901:	49 89 d2             	mov    r10,rdx
    1904:	41 89 f9             	mov    r9d,edi
    1907:	48 89 f2             	mov    rdx,rsi
    190a:	4c 89 d7             	mov    rdi,r10
    190d:	48 89 ce             	mov    rsi,rcx
    1910:	48 89 e5             	mov    rbp,rsp
    1913:	e8 98 fd ff ff       	call   16b0 <lab04_region_lookup>
    1918:	85 c0                	test   eax,eax
    191a:	78 36                	js     1952 <lab14_exception_dispatch+0x52>
    191c:	41 81 f9 05 00 00 c0 	cmp    r9d,0xc0000005
    1923:	74 1b                	je     1940 <lab14_exception_dispatch+0x40>
    1925:	31 c0                	xor    eax,eax
    1927:	41 81 f9 03 00 00 80 	cmp    r9d,0x80000003
    192e:	5d                   	pop    rbp
    192f:	0f 95 c0             	setne  al
    1932:	83 c0 02             	add    eax,0x2
    1935:	c3                   	ret
    1936:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    193d:	00 00 00
    1940:	89 c0                	mov    eax,eax
    1942:	5d                   	pop    rbp
    1943:	48 8d 04 40          	lea    rax,[rax+rax*2]
    1947:	41 8b 44 c2 10       	mov    eax,DWORD PTR [r10+rax*8+0x10]
    194c:	d1 e8                	shr    eax,1
    194e:	83 e0 01             	and    eax,0x1
    1951:	c3                   	ret
    1952:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1957:	5d                   	pop    rbp
    1958:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0
 RCX  3
 RDX  0x7fffffffdff0 ◂— 0x1000
 RDI  0xc0000005
 RSI  0x4500
 R8   0xb
 R9   0x7fffffffdf50 ◂— 0x4e00520045006b /* 'k' */
 RSP  0x7fffffffdef8 —▸ 0x555555555411 (main+913) ◂— lea rsi, [rbp - 0x228]
 RIP  0x555555555900 (lab14_exception_dispatch) ◂— push rbp
   0x555555555901 <lab14_exception_dispatch+1>     mov    r10, rdx     R10 => 0x7fffffffdff0 ◂— 0x1000
   0x555555555904 <lab14_exception_dispatch+4>     mov    r9d, edi     R9D => 0xc0000005
   0x555555555907 <lab14_exception_dispatch+7>     mov    rdx, rsi     RDX => 0x4500
   0x55555555590a <lab14_exception_dispatch+10>    mov    rdi, r10     RDI => 0x7fffffffdff0 ◂— 0x1000
   0x55555555590d <lab14_exception_dispatch+13>    mov    rsi, rcx     RSI => 3
   0x555555555910 <lab14_exception_dispatch+16>    mov    rbp, rsp     RBP => 0x7fffffffdef0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555913 <lab14_exception_dispatch+19>    call   lab04_region_lookup         <lab04_region_lookup>
   0x555555555918 <lab14_exception_dispatch+24>    test   eax, eax
   0x55555555591a <lab14_exception_dispatch+26>    js     lab14_exception_dispatch+82 <lab14_exception_dispatch+82>
   0x55555555591c <lab14_exception_dispatch+28>    cmp    r9d, 0xc0000005
=> 0x555555555900 <lab14_exception_dispatch>:	push   rbp
   0x555555555901 <lab14_exception_dispatch+1>:	mov    r10,rdx
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab14_exception_dispatch` is mapped to stripped RVA `0x1900`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Walkthrough 15 — Sorted import-name lookup

## Reversing problem

Recover `FUN_00101960` without names. Recover binary search over pointer array, strcmp ordering, parallel ordinal table, and not-found sentinel.

## Ghidra’s actual stripped decompilation

```c
FUNCTION FUN_00101960
ENTRY 00101960
SIGNATURE undefined FUN_00101960(void)
CALLERS 00102194, 00102330, 00101431

ulong FUN_00101960(long param_1,long param_2,ulong param_3,char *param_4)

{
  int iVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;

  uVar3 = 0;
  uVar2 = param_3;
  while (uVar4 = uVar2, uVar3 < uVar4) {
    uVar2 = (uVar4 - uVar3 >> 1) + uVar3;
    iVar1 = strcmp(*(char **)(param_1 + uVar2 * 8),param_4);
    if (iVar1 < 0) {
      uVar3 = uVar2 + 1;
      uVar2 = uVar4;
    }
  }
  if ((uVar3 < param_3) && (iVar1 = strcmp(*(char **)(param_1 + uVar3 * 8),param_4), iVar1 == 0)) {
    return (ulong)*(ushort *)(param_2 + uVar3 * 2);
  }
  return 0xffffffff;
}
```

## Complete disassembly

```asm
reversing-walkthrough-lab/build/ch03/ch03_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001960 <lab15_import_lookup>:
    1960:	55                   	push   rbp
    1961:	48 89 e5             	mov    rbp,rsp
    1964:	41 57                	push   r15
    1966:	49 89 d7             	mov    r15,rdx
    1969:	41 56                	push   r14
    196b:	45 31 f6             	xor    r14d,r14d
    196e:	41 55                	push   r13
    1970:	49 89 fd             	mov    r13,rdi
    1973:	41 54                	push   r12
    1975:	49 89 cc             	mov    r12,rcx
    1978:	53                   	push   rbx
    1979:	48 83 ec 18          	sub    rsp,0x18
    197d:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
    1981:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    1985:	eb 29                	jmp    19b0 <lab15_import_lookup+0x50>
    1987:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    198e:	00 00
    1990:	4c 89 fb             	mov    rbx,r15
    1993:	4c 89 e6             	mov    rsi,r12
    1996:	4c 29 f3             	sub    rbx,r14
    1999:	48 d1 eb             	shr    rbx,1
    199c:	4c 01 f3             	add    rbx,r14
    199f:	49 8b 7c dd 00       	mov    rdi,QWORD PTR [r13+rbx*8+0x0]
    19a4:	e8 a7 f6 ff ff       	call   1050 <strcmp@plt>
    19a9:	85 c0                	test   eax,eax
    19ab:	78 53                	js     1a00 <lab15_import_lookup+0xa0>
    19ad:	49 89 df             	mov    r15,rbx
    19b0:	4d 39 fe             	cmp    r14,r15
    19b3:	72 db                	jb     1990 <lab15_import_lookup+0x30>
    19b5:	4c 3b 75 c8          	cmp    r14,QWORD PTR [rbp-0x38]
    19b9:	73 2d                	jae    19e8 <lab15_import_lookup+0x88>
    19bb:	4b 8b 7c f5 00       	mov    rdi,QWORD PTR [r13+r14*8+0x0]
    19c0:	4c 89 e6             	mov    rsi,r12
    19c3:	e8 88 f6 ff ff       	call   1050 <strcmp@plt>
    19c8:	85 c0                	test   eax,eax
    19ca:	75 1c                	jne    19e8 <lab15_import_lookup+0x88>
    19cc:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
    19d0:	42 0f b7 04 70       	movzx  eax,WORD PTR [rax+r14*2]
    19d5:	48 83 c4 18          	add    rsp,0x18
    19d9:	5b                   	pop    rbx
    19da:	41 5c                	pop    r12
    19dc:	41 5d                	pop    r13
    19de:	41 5e                	pop    r14
    19e0:	41 5f                	pop    r15
    19e2:	5d                   	pop    rbp
    19e3:	c3                   	ret
    19e4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    19e8:	48 83 c4 18          	add    rsp,0x18
    19ec:	b8 ff ff ff ff       	mov    eax,0xffffffff
    19f1:	5b                   	pop    rbx
    19f2:	41 5c                	pop    r12
    19f4:	41 5d                	pop    r13
    19f6:	41 5e                	pop    r14
    19f8:	41 5f                	pop    r15
    19fa:	5d                   	pop    rbp
    19fb:	c3                   	ret
    19fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1a00:	4c 8d 73 01          	lea    r14,[rbx+0x1]
    1a04:	eb aa                	jmp    19b0 <lab15_import_lookup+0x50>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0
 RCX  0x55555555601c ◂— 'ReadFile'
 RDX  4
 RDI  0x7fffffffdf60 —▸ 0x555555556004 ◂— 'CloseHandle'
 RSI  0x7fffffffdf38 ◂— 0x33002c00130007
 R8   0x7fffffffdff0 ◂— 0x1000
 R9   0xc0000005
 RSP  0x7fffffffdef8 —▸ 0x555555555436 (main+950) ◂— lea esi, [rbx + r14]
 RIP  0x555555555960 (lab15_import_lookup) ◂— push rbp
   0x555555555961 <lab15_import_lookup+1>     mov    rbp, rsp       RBP => 0x7fffffffdef0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555964 <lab15_import_lookup+4>     push   r15
   0x555555555966 <lab15_import_lookup+6>     mov    r15, rdx       R15 => 4
   0x555555555969 <lab15_import_lookup+9>     push   r14
   0x55555555596b <lab15_import_lookup+11>    xor    r14d, r14d     R14D => 0
   0x55555555596e <lab15_import_lookup+14>    push   r13
   0x555555555970 <lab15_import_lookup+16>    mov    r13, rdi       R13 => 0x7fffffffdf60 —▸ 0x555555556004 ◂— 'CloseHandle'
   0x555555555973 <lab15_import_lookup+19>    push   r12
   0x555555555975 <lab15_import_lookup+21>    mov    r12, rcx       R12 => 0x55555555601c ◂— 'ReadFile'
   0x555555555978 <lab15_import_lookup+24>    push   rbx
=> 0x555555555960 <lab15_import_lookup>:	push   rbp
   0x555555555961 <lab15_import_lookup+1>:	mov    rbp,rsp
```

## Mentor walkthrough

1. Derive the SysV harness prototype from argument registers; separately record the Windows concept being modeled.
2. Mark all bounds and sentinel paths before naming fields.
3. Convert fixed offsets and strides into tentative structures.
4. Use pwndbg values to validate one path, then select a boundary that forces the opposite path.
5. State exactly which conclusion is platform-independent and which needs PE/Windows confirmation.

## Verified result

`lab15_import_lookup` is mapped to stripped RVA `0x1960`. Its contract is supported by the decompilation, full instruction listing, entry state, caller, and baseline output.

# Twenty Practice Questions

1. What validates e_lfanew safely?
2. Why use max virtual/raw size for membership but raw size for output?
3. How are handle bits separated?
4. What makes the region table sorted?
5. How is NX inversion recognized?
6. Why return UINT64_MAX?
7. What does LOCK OR prove?
8. Why test status as signed?
9. How is UTF-16 width inferred?
10. Why is ASCII case folding not full Unicode?
11. How is IO_STATUS_BLOCK layout recovered?
12. What adds an exception edge?
13. How do ordinal/name parallel arrays appear?
14. How do you verify an atomic return contract?
15. Why can Ghidra infer wrong Windows types on ELF?
16. What is a VAD-like invariant?
17. How do you test handle generation failure?
18. What is raw-backed boundary test?
19. Why analyze conceptual models on Linux?
20. Mastery criterion?

# Complete Solutions

## 1. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Minimum DOS header, offset load only after size check, and off<=n-4 before PE signature read.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 2. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Virtual mapping may include zero-filled bytes that have no file backing; translation must reject that tail.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 3. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Shift/mask operations reveal table index and generation; low tag bits can be discarded.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 4. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Binary search updates based on address relative to start/end and the caller supplies ascending nonoverlapping ranges.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 5. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** The executable output flag is set when the modeled no-execute bit is clear.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 6. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** It is a width-matched sentinel distinct from every valid nonwrapping offset under the model.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 7. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Atomic read-modify-write with cross-thread visibility; instruction returns or preserves prior value depending lowering.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 8. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** NT-style success codes have high bit clear/nonnegative; failures are negative signed 32-bit values.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 9. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** 16-bit loads, pointer/index scale two, and 16-bit NUL/code-unit comparisons.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 10. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Only a-z range receives subtraction; no locale or multi-code-unit mapping exists.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 11. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Repeated fixed-offset stores of 32-,32-,64-bit values and caller allocation establish fields/alignment.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 12. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Dispatch can be reached by runtime fault rather than ordinary call; the model’s explicit call is only a teaching proxy.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 13. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Same converged index selects a string pointer during search and a 16-bit ordinal on success.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 14. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Initialize field, call with mask, compare returned old value and mutated new value.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 15. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Platform data archives and ABI differ; types must be applied from recovered semantics, not target-name wishful thinking.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 16. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Regions are sorted and nonoverlapping; membership is start<=address<end.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 17. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Keep index constant, change high generation bits, and predict a zero result before executing.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 18. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** RVA at VA+RawSize-1 succeeds; VA+RawSize fails when VirtualSize is larger.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 19. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Algorithms and structures can be executed safely; exact Windows ABI/loader claims remain separated and require PE/Windows confirmation.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.

## 20. Solution

1. Identify structure offsets, operand widths, and branch relation.
2. Separate model evidence from platform-specific inference.
3. **Answer:** Translate PE/handle/region/status structures from offsets and prove them with runtime values and boundary cases.
4. Validate with a boundary input in the harness and, where stated, a PE/Windows specimen.


Return to [[Chapter 03 - Windows Fundamentals]].
