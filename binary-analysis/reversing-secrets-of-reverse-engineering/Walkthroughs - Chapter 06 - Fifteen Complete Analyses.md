# Chapter 6 — Fifteen Complete File-Format Walkthroughs

> [!evidence]
> The RVX2 archive is constructed, encrypted, parsed, searched, extracted, mutated, and inspected in the executed harness. Ghidra analyzed the exact stripped binary and pwndbg captured every stage.

## Observed result

```text
chapter06 evidence=6268108775 extracted=ALPHA-CONTENT entries=2
```

## Complete source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;
typedef struct{char magic[4];uint16_t version,flags;uint32_t dir_off,dir_count,total_size,header_crc;}Header;
typedef struct{char name[16];uint32_t off,stored,original,crc;}Entry;

NI uint32_t lab01_crc32ish(const uint8_t*p,size_t n){uint32_t c=0xffffffffu;for(size_t i=0;i<n;i++){c^=p[i];for(int b=0;b<8;b++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return ~c;}
NI uint32_t lab02_derive_key(const char*p){uint32_t h=0x9e3779b9u;for(;*p;p++){h^=(uint8_t)*p;h=(h<<7)|(h>>25);h*=33u;}return h;}
NI void lab03_stream_xor(uint8_t*p,size_t n,uint32_t key){uint32_t x=key;for(size_t i=0;i<n;i++){x=x*1664525u+1013904223u;p[i]^=(uint8_t)(x>>24);}}
NI int lab04_safe_range(size_t total,uint32_t off,uint32_t len){return off<=total&&len<=total-off;}
NI size_t lab05_align16(size_t n){if(n>SIZE_MAX-15)return SIZE_MAX;return (n+15)&~(size_t)15;}
NI int lab06_write_header(uint8_t*out,size_t cap,Header*h){if(cap<sizeof *h)return -1;h->header_crc=0;h->header_crc=lab01_crc32ish((uint8_t*)h,sizeof *h-4);memcpy(out,h,sizeof *h);return 0;}
NI int lab07_read_header(const uint8_t*p,size_t n,Header*out){if(n<sizeof *out)return -1;memcpy(out,p,sizeof *out);if(memcmp(out->magic,"RVX2",4)||out->version!=2)return -2;uint32_t saved=out->header_crc;out->header_crc=0;if(saved!=lab01_crc32ish((uint8_t*)out,sizeof *out-4))return -3;out->header_crc=saved;if(!lab04_safe_range(n,out->dir_off,out->dir_count*sizeof(Entry)))return -4;return 0;}
NI int lab08_read_entry(const uint8_t*p,size_t n,const Header*h,uint32_t index,Entry*out){if(index>=h->dir_count)return -1;size_t off=(size_t)h->dir_off+index*sizeof *out;if(!lab04_safe_range(n,(uint32_t)off,sizeof *out))return -2;memcpy(out,p+off,sizeof *out);if(memchr(out->name,0,sizeof out->name)==0)return -3;if(!lab04_safe_range(n,out->off,out->stored))return -4;return 0;}
NI int lab09_find_entry(const uint8_t*p,size_t n,const Header*h,const char*name,Entry*out){for(uint32_t i=0;i<h->dir_count;i++){Entry e;if(lab08_read_entry(p,n,h,i,&e))return -2;if(!strcmp(e.name,name)){*out=e;return (int)i;}}return -1;}
NI int lab10_extract(const uint8_t*p,size_t n,const Header*h,const char*name,uint8_t*out,size_t cap,uint32_t key){Entry e;if(lab09_find_entry(p,n,h,name,&e)<0)return -1;if(e.original>cap||e.stored<e.original)return -2;memcpy(out,p+e.off,e.stored);lab03_stream_xor(out,e.stored,key);if(lab01_crc32ish(out,e.original)!=e.crc)return -3;return (int)e.original;}
NI size_t lab11_encode_varint(uint8_t*out,uint64_t v){size_t n=0;do{uint8_t b=v&0x7f;v>>=7;if(v)b|=0x80;out[n++]=b;}while(v);return n;}
NI int lab12_decode_varint(const uint8_t*p,size_t n,uint64_t*out){uint64_t v=0;unsigned shift=0;for(size_t i=0;i<n&&i<10;i++){uint8_t b=p[i];if(shift==63&&(b&0xfe))return -2;v|=(uint64_t)(b&0x7f)<<shift;if(!(b&0x80)){*out=v;return (int)i+1;}shift+=7;}return -1;}
NI uint32_t lab13_be32(const uint8_t*p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
NI int lab14_mutation_check(uint8_t*p,size_t n,size_t at,uint8_t value){if(at>=n)return -1;uint8_t old=p[at];p[at]=value;Header h;int r=lab07_read_header(p,n,&h);p[at]=old;return r;}
NI int lab15_inspect(const uint8_t*p,size_t n,uint32_t*entries,uint64_t*payload_bytes){Header h;int r=lab07_read_header(p,n,&h);if(r)return r;uint64_t total=0;for(uint32_t i=0;i<h.dir_count;i++){Entry e;r=lab08_read_entry(p,n,&h,i,&e);if(r)return r;total+=e.original;}*entries=h.dir_count;*payload_bytes=total;return 0;}

int main(void){uint8_t archive[512]={0};Header h={{'R','V','X','2'},2,1,sizeof(Header),2,0,0};Entry e[2]={0};
 strcpy(e[0].name,"alpha.txt");strcpy(e[1].name,"beta.bin");uint8_t a[]="ALPHA-CONTENT",b[]={1,2,3,4,5,6,7,8};
 size_t data=lab05_align16(sizeof(Header)+sizeof e);e[0].off=data;e[0].original=e[0].stored=sizeof a-1;e[0].crc=lab01_crc32ish(a,e[0].original);
 e[1].off=(uint32_t)lab05_align16(data+e[0].stored);e[1].original=e[1].stored=sizeof b;e[1].crc=lab01_crc32ish(b,sizeof b);h.total_size=e[1].off+e[1].stored;
 memcpy(archive+h.dir_off,e,sizeof e);memcpy(archive+e[0].off,a,e[0].stored);memcpy(archive+e[1].off,b,e[1].stored);uint32_t key=lab02_derive_key("mentor");
 lab03_stream_xor(archive+e[0].off,e[0].stored,key);lab03_stream_xor(archive+e[1].off,e[1].stored,key);lab06_write_header(archive,sizeof archive,&h);
 Header read;Entry found;uint8_t out[64];uint8_t var[16];uint64_t decoded,payloads;uint32_t entries;uint64_t total=0;
 total+=lab07_read_header(archive,h.total_size,&read);total+=lab08_read_entry(archive,h.total_size,&read,1,&found);
 total+=lab09_find_entry(archive,h.total_size,&read,"alpha.txt",&found);total+=lab10_extract(archive,h.total_size,&read,"alpha.txt",out,sizeof out,key);
 size_t vn=lab11_encode_varint(var,0x123456789ULL);total+=vn+lab12_decode_varint(var,vn,&decoded)+decoded;
 total+=lab13_be32((uint8_t*)"RVX2");total+=lab14_mutation_check(archive,h.total_size,0,'X');total+=lab15_inspect(archive,h.total_size,&entries,&payloads)+entries+payloads;
 evidence_sink=total;printf("chapter06 evidence=%llu extracted=%.*s entries=%u\n",(unsigned long long)total,13,out,entries);return 0;}
```

# Walkthrough 01 — CRC recovery

## Goal

Recover bitwise polynomial, inversion, byte/bit loops, and exact covered range.

## Ghidra stripped output

```c
FUNCTION FUN_00101580
ENTRY 00101580
SIGNATURE undefined FUN_00101580(void)
CALLERS 00102078, 00102150, 0010119a, 001011ba, 0010169f, 00101711, 0010199e

uint FUN_00101580(byte *param_1,long param_2)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;

  if (param_2 != 0) {
    pbVar3 = param_1 + param_2;
    uVar1 = 0xffffffff;
    do {
      uVar1 = uVar1 ^ *param_1;
      iVar2 = 8;
      do {
        uVar1 = -(uVar1 & 1) & 0xedb88320 ^ uVar1 >> 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      param_1 = param_1 + 1;
    } while (param_1 != pbVar3);
    return ~uVar1;
  }
  return 0;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001580 <lab01_crc32ish>:
    1580:	48 85 f6             	test   rsi,rsi
    1583:	74 3c                	je     15c1 <lab01_crc32ish+0x41>
    1585:	48 01 fe             	add    rsi,rdi
    1588:	b8 ff ff ff ff       	mov    eax,0xffffffff
    158d:	0f 1f 00             	nop    DWORD PTR [rax]
    1590:	0f b6 17             	movzx  edx,BYTE PTR [rdi]
    1593:	31 d0                	xor    eax,edx
    1595:	ba 08 00 00 00       	mov    edx,0x8
    159a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    15a0:	89 c1                	mov    ecx,eax
    15a2:	83 e0 01             	and    eax,0x1
    15a5:	f7 d8                	neg    eax
    15a7:	d1 e9                	shr    ecx,1
    15a9:	25 20 83 b8 ed       	and    eax,0xedb88320
    15ae:	31 c8                	xor    eax,ecx
    15b0:	83 ea 01             	sub    edx,0x1
    15b3:	75 eb                	jne    15a0 <lab01_crc32ish+0x20>
    15b5:	48 83 c7 01          	add    rdi,0x1
    15b9:	48 39 f7             	cmp    rdi,rsi
    15bc:	75 d2                	jne    1590 <lab01_crc32ish+0x10>
    15be:	f7 d0                	not    eax
    15c0:	c3                   	ret
    15c1:	31 c0                	xor    eax,eax
    15c3:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x60
 RBX  0
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555520 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xffffffffffffffff
 RDI  0x7fffffffdec2 ◂— 'ALPHA-CONTENT'
 RSI  0xd
 R8   0x60
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffddc8 —▸ 0x55555555519f (main+255) ◂— lea rdi, [r8 + 0xd]
 RIP  0x555555555580 (lab01_crc32ish) ◂— test rsi, rsi
   0x555555555583 <lab01_crc32ish+3>   ✘ je     lab01_crc32ish+65           <lab01_crc32ish+65>
   0x555555555585 <lab01_crc32ish+5>     add    rsi, rdi                 RSI => 0x7fffffffdecf (0xd + 0x7fffffffdec2)
   0x555555555588 <lab01_crc32ish+8>     mov    eax, 0xffffffff          EAX => 0xffffffff
   0x55555555558d <lab01_crc32ish+13>    nop    dword ptr [rax]
   0x555555555590 <lab01_crc32ish+16>    movzx  edx, byte ptr [rdi]      EDX, [0x7fffffffdec2] => 0x41
   0x555555555593 <lab01_crc32ish+19>    xor    eax, edx                 EAX => 0xffffffbe (0xffffffff ^ 0x41)
   0x555555555595 <lab01_crc32ish+21>    mov    edx, 8                   EDX => 8
   0x55555555559a <lab01_crc32ish+26>    nop    word ptr [rax + rax]
   0x5555555555a0 <lab01_crc32ish+32>    mov    ecx, eax                 ECX => 0xffffffbe
   0x5555555555a2 <lab01_crc32ish+34>    and    eax, 1                   EAX => 0 (0xffffffbe & 0x1)
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab01_crc32ish`, RVA `0x1580`.

# Walkthrough 02 — Password-derived state

## Goal

Recover byte loop, rotate, multiply, terminator, and fixed-width key state.

## Ghidra stripped output

```c
FUNCTION FUN_001015d0
ENTRY 001015d0
SIGNATURE undefined FUN_001015d0(void)
CALLERS 00102080, 00102164, 0010127a

uint FUN_001015d0(byte *param_1)

{
  byte bVar1;
  uint uVar2;

  uVar2 = 0x9e3779b9;
  bVar1 = *param_1;
  while (bVar1 != 0) {
    param_1 = param_1 + 1;
    uVar2 = ((bVar1 ^ uVar2) << 7 | uVar2 >> 0x19) * 0x21;
    bVar1 = *param_1;
  }
  return uVar2;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000015d0 <lab02_derive_key>:
    15d0:	0f b6 07             	movzx  eax,BYTE PTR [rdi]
    15d3:	ba b9 79 37 9e       	mov    edx,0x9e3779b9
    15d8:	84 c0                	test   al,al
    15da:	74 1b                	je     15f7 <lab02_derive_key+0x27>
    15dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    15e0:	31 d0                	xor    eax,edx
    15e2:	48 83 c7 01          	add    rdi,0x1
    15e6:	c1 c0 07             	rol    eax,0x7
    15e9:	89 c2                	mov    edx,eax
    15eb:	c1 e2 05             	shl    edx,0x5
    15ee:	01 c2                	add    edx,eax
    15f0:	0f b6 07             	movzx  eax,BYTE PTR [rdi]
    15f3:	84 c0                	test   al,al
    15f5:	75 e9                	jne    15e0 <lab02_derive_key+0x10>
    15f7:	89 d0                	mov    eax,edx
    15f9:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x544e45544e4f432d ('-CONTENT')
 RBX  0x78
 RCX  0x800000008
 RDX  0
 RDI  0x555555556004 ◂— 0x6100726f746e656d /* 'mentor' */
 RSI  0xd
 R8   0x60
 R9   0x70
 RSP  0x7fffffffddc8 —▸ 0x55555555527f (main+479) ◂— lea rdi, [rbp + r8 - 0x240]
 RIP  0x5555555555d0 (lab02_derive_key) ◂— movzx eax, byte ptr [rdi]
   0x5555555555d3 <lab02_derive_key+3>     mov    edx, 0x9e3779b9         EDX => 0x9e3779b9
   0x5555555555d8 <lab02_derive_key+8>     test   al, al                  0x6d & 0x6d     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x5555555555da <lab02_derive_key+10>  ✘ je     lab02_derive_key+39         <lab02_derive_key+39>
   0x5555555555dc <lab02_derive_key+12>    nop    dword ptr [rax]
   0x5555555555e0 <lab02_derive_key+16>    xor    eax, edx                EAX => 0x9e3779d4 (0x6d ^ 0x9e3779b9)
   0x5555555555e2 <lab02_derive_key+18>    add    rdi, 1                  RDI => 0x555555556005 (0x555555556004 + 0x1)
   0x5555555555e6 <lab02_derive_key+22>    rol    eax, 7
   0x5555555555e9 <lab02_derive_key+25>    mov    edx, eax                EDX => 0x1bbcea4f
   0x5555555555eb <lab02_derive_key+27>    shl    edx, 5
   0x5555555555ee <lab02_derive_key+30>    add    edx, eax                EDX => 0x935a342f (0x779d49e0 + 0x1bbcea4f)
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab02_derive_key`, RVA `0x15d0`.

# Walkthrough 03 — Stateful payload transform

## Goal

Recover LCG state, high-byte extraction, in-place XOR, and symmetric reapplication.

## Ghidra stripped output

```c
FUNCTION FUN_00101600
ENTRY 00101600
SIGNATURE undefined FUN_00101600(void)
CALLERS 00102088, 00102178, 0010128c, 001012a1, 00101993

void FUN_00101600(byte *param_1,long param_2,int param_3)

{
  byte *pbVar1;

  if (param_2 != 0) {
    pbVar1 = param_1 + param_2;
    do {
      param_3 = param_3 * 0x19660d + 0x3c6ef35f;
      *param_1 = *param_1 ^ (byte)((uint)param_3 >> 0x18);
      param_1 = param_1 + 1;
    } while (pbVar1 != param_1);
  }
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001600 <lab03_stream_xor>:
    1600:	48 85 f6             	test   rsi,rsi
    1603:	74 37                	je     163c <lab03_stream_xor+0x3c>
    1605:	48 01 fe             	add    rsi,rdi
    1608:	66 90                	xchg   ax,ax
    160a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1611:	00 00 00 00
    1615:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    161c:	00 00 00 00
    1620:	69 d2 0d 66 19 00    	imul   edx,edx,0x19660d
    1626:	81 c2 5f f3 6e 3c    	add    edx,0x3c6ef35f
    162c:	89 d0                	mov    eax,edx
    162e:	c1 e8 18             	shr    eax,0x18
    1631:	30 07                	xor    BYTE PTR [rdi],al
    1633:	48 83 c7 01          	add    rdi,0x1
    1637:	48 39 fe             	cmp    rsi,rdi
    163a:	75 e4                	jne    1620 <lab03_stream_xor+0x20>
    163c:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x27970424
 RBX  0x78
 RCX  0x800000008
 RDX  0x27970424
 RDI  0x7fffffffdf80 ◂— 'ALPHA-CONTENT'
 RSI  0xd
 R8   0x60
 R9   0x70
 RSP  0x7fffffffddc8 —▸ 0x555555555291 (main+497) ◂— lea rdi, [rbp + r9 - 0x240]
 RIP  0x555555555600 (lab03_stream_xor) ◂— test rsi, rsi
   0x555555555603 <lab03_stream_xor+3>   ✘ je     lab03_stream_xor+60         <lab03_stream_xor+60>
   0x555555555605 <lab03_stream_xor+5>     add    rsi, rdi                 RSI => 0x7fffffffdf8d (0xd + 0x7fffffffdf80)
   0x555555555608 <lab03_stream_xor+8>     nop
   0x55555555560a <lab03_stream_xor+10>    nop    word ptr [rax + rax]
   0x555555555615 <lab03_stream_xor+21>    nop    word ptr [rax + rax]
   0x555555555620 <lab03_stream_xor+32>    imul   edx, edx, 0x19660d
   0x555555555626 <lab03_stream_xor+38>    add    edx, 0x3c6ef35f          EDX => 0xd2448133 (0x95d58dd4 + 0x3c6ef35f)
   0x55555555562c <lab03_stream_xor+44>    mov    eax, edx                 EAX => 0xd2448133
   0x55555555562e <lab03_stream_xor+46>    shr    eax, 0x18
   0x555555555631 <lab03_stream_xor+49>    xor    byte ptr [rdi], al       [0x7fffffffdf80] => 0x93 (0x41 ^ 0xd2)
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab03_stream_xor`, RVA `0x1600`.

# Walkthrough 04 — Overflow-safe bounds predicate

## Goal

Recognize off<=total and len<=total-off instead of overflowing addition.

## Ghidra stripped output

```c
FUNCTION FUN_00101640
ENTRY 00101640
SIGNATURE undefined FUN_00101640(void)
CALLERS 00102090, 0010218c, 0010172d, 0010179f, 001017d9

bool FUN_00101640(ulong param_1,uint param_2,uint param_3)

{
  return param_2 <= param_1 && (ulong)param_3 <= param_1 - param_2;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001640 <lab04_safe_range>:
    1640:	89 f6                	mov    esi,esi
    1642:	31 c0                	xor    eax,eax
    1644:	48 39 f7             	cmp    rdi,rsi
    1647:	72 0d                	jb     1656 <lab04_safe_range+0x16>
    1649:	89 d2                	mov    edx,edx
    164b:	48 29 f7             	sub    rdi,rsi
    164e:	31 c0                	xor    eax,eax
    1650:	48 39 d7             	cmp    rdi,rdx
    1653:	0f 93 c0             	setae  al
    1656:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x4117532e
 RBX  0x78
 RCX  0x53502ff1
 RDX  0x40
 RDI  0x78
 RSI  0x18
 R8   0x7fffffffde30 ◂— 0x1000232585652
 R9   0x78
 RSP  0x7fffffffddb8 —▸ 0x555555555732 (lab07_read_header+98) ◂— pop rbp
 RIP  0x555555555640 (lab04_safe_range) ◂— mov esi, esi
   0x555555555642 <lab04_safe_range+2>      xor    eax, eax     EAX => 0
   0x555555555644 <lab04_safe_range+4>      cmp    rdi, rsi     0x78 - 0x18     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555647 <lab04_safe_range+7>    ✘ jb     lab04_safe_range+22         <lab04_safe_range+22>
   0x555555555649 <lab04_safe_range+9>      mov    edx, edx     EDX => 0x40
   0x55555555564b <lab04_safe_range+11>     sub    rdi, rsi     RDI => 0x60 (0x78 - 0x18)
   0x55555555564e <lab04_safe_range+14>     xor    eax, eax     EAX => 0
   0x555555555650 <lab04_safe_range+16>     cmp    rdi, rdx     0x60 - 0x40     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555653 <lab04_safe_range+19>     setae  al
   0x555555555656 <lab04_safe_range+22>     ret                                <lab07_read_header+98>
   0x555555555732 <lab07_read_header+98>    pop    rbp          RBP => 0x7fffffffe160
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab04_safe_range`, RVA `0x1640`.

# Walkthrough 05 — Checked alignment

## Goal

Recover overflow guard, add-15, mask-low-bits, and failure sentinel.

## Ghidra stripped output

```c
FUNCTION FUN_00101660
ENTRY 00101660
SIGNATURE undefined FUN_00101660(void)
CALLERS 00102098, 001021a0, 0010118b, 001011ab

ulong FUN_00101660(ulong param_1)

{
  ulong uVar1;

  uVar1 = param_1 + 0xf & 0xfffffffffffffff0;
  if (0xfffffffffffffff0 < param_1) {
    uVar1 = 0xffffffffffffffff;
  }
  return uVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001660 <lab05_align16>:
    1660:	48 8d 47 0f          	lea    rax,[rdi+0xf]
    1664:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
    166b:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
    166f:	48 83 ff f1          	cmp    rdi,0xfffffffffffffff1
    1673:	48 0f 43 c2          	cmovae rax,rdx
    1677:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x544e45544e4f43
 RBX  0
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555520 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe0a0 ◂— 0
 RDI  0x58
 RSI  0xd
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffddc8 —▸ 0x555555555190 (main+240) ◂— lea rdi, [rbp - 0x29e]
 RIP  0x555555555660 (lab05_align16) ◂— lea rax, [rdi + 0xf]
   0x555555555664 <lab05_align16+4>     mov    rdx, 0xffffffffffffffff     RDX => 0xffffffffffffffff
   0x55555555566b <lab05_align16+11>    and    rax, 0xfffffffffffffff0     RAX => 0x60 (0x67 & -0x10)
   0x55555555566f <lab05_align16+15>    cmp    rdi, -0xf                   0x58 - -0xf     EFLAGS => 0x203 [ CF pf af zf sf IF df of ac ]
   0x555555555673 <lab05_align16+19>  ✘ cmovae rax, rdx
   0x555555555677 <lab05_align16+23>    ret                                <main+240>
   0x555555555190 <main+240>            lea    rdi, [rbp - 0x29e]          RDI => 0x7fffffffdec2 ◂— 'ALPHA-CONTENT'
   0x555555555197 <main+247>            mov    r8, rax                     R8 => 0x60
   0x55555555519a <main+250>            call   lab01_crc32ish              <lab01_crc32ish>
   0x55555555519f <main+255>            lea    rdi, [r8 + 0xd]
   0x5555555551a3 <main+259>            mov    esi, 8                      ESI => 8
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab05_align16`, RVA `0x1660`.

# Walkthrough 06 — Header serialization

## Goal

Recover capacity, checksum field zeroing, covered prefix, checksum store, and structure copy.

## Ghidra stripped output

```c
FUNCTION FUN_00101680
ENTRY 00101680
SIGNATURE undefined FUN_00101680(void)
CALLERS 001020a0, 001021b4, 001012b9

undefined8 FUN_00101680(undefined8 *param_1,ulong param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  undefined4 uVar2;

  if (0x17 < param_2) {
    *(undefined4 *)((long)param_3 + 0x14) = 0;
    uVar2 = FUN_00101580(param_3,0x14);
    uVar1 = param_3[1];
    *(undefined4 *)((long)param_3 + 0x14) = uVar2;
    *param_1 = *param_3;
    param_1[1] = uVar1;
    param_1[2] = param_3[2];
    return 0;
  }
  return 0xffffffff;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001680 <lab06_write_header>:
    1680:	48 83 fe 17          	cmp    rsi,0x17
    1684:	76 3a                	jbe    16c0 <lab06_write_header+0x40>
    1686:	55                   	push   rbp
    1687:	49 89 d0             	mov    r8,rdx
    168a:	49 89 f9             	mov    r9,rdi
    168d:	be 14 00 00 00       	mov    esi,0x14
    1692:	c7 42 14 00 00 00 00 	mov    DWORD PTR [rdx+0x14],0x0
    1699:	48 89 d7             	mov    rdi,rdx
    169c:	48 89 e5             	mov    rbp,rsp
    169f:	e8 dc fe ff ff       	call   1580 <lab01_crc32ish>
    16a4:	f3 41 0f 6f 00       	movdqu xmm0,XMMWORD PTR [r8]
    16a9:	41 89 40 14          	mov    DWORD PTR [r8+0x14],eax
    16ad:	41 0f 11 01          	movups XMMWORD PTR [r9],xmm0
    16b1:	49 8b 40 10          	mov    rax,QWORD PTR [r8+0x10]
    16b5:	49 89 41 10          	mov    QWORD PTR [r9+0x10],rax
    16b9:	31 c0                	xor    eax,eax
    16bb:	5d                   	pop    rbp
    16bc:	c3                   	ret
    16bd:	0f 1f 00             	nop    DWORD PTR [rax]
    16c0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    16c5:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0xdd
 RBX  0x78
 RCX  0x800000008
 RDX  0x7fffffffde10 ◂— 0x1000232585652
 RDI  0x7fffffffdf20 ◂— 0
 RSI  0x200
 R8   0x60
 R9   0x70
 RSP  0x7fffffffddc8 —▸ 0x5555555552be (main+542) ◂— lea rdx, [rbp - 0x330]
 RIP  0x555555555680 (lab06_write_header) ◂— cmp rsi, 0x17
   0x555555555684 <lab06_write_header+4>   ✘ jbe    lab06_write_header+64       <lab06_write_header+64>
   0x555555555686 <lab06_write_header+6>     push   rbp
   0x555555555687 <lab06_write_header+7>     mov    r8, rdx                       R8 => 0x7fffffffde10 ◂— 0x1000232585652
   0x55555555568a <lab06_write_header+10>    mov    r9, rdi                       R9 => 0x7fffffffdf20 ◂— 0
   0x55555555568d <lab06_write_header+13>    mov    esi, 0x14                     ESI => 0x14
   0x555555555692 <lab06_write_header+18>    mov    dword ptr [rdx + 0x14], 0     [0x7fffffffde24] <= 0
   0x555555555699 <lab06_write_header+25>    mov    rdi, rdx                      RDI => 0x7fffffffde10 ◂— 0x1000232585652
   0x55555555569c <lab06_write_header+28>    mov    rbp, rsp                      RBP => 0x7fffffffddc0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x55555555569f <lab06_write_header+31>    call   lab01_crc32ish              <lab01_crc32ish>
   0x5555555556a4 <lab06_write_header+36>    movdqu xmm0, xmmword ptr [r8]
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab06_write_header`, RVA `0x1680`.

# Walkthrough 07 — Header parser

## Goal

Recover minimum size, magic/version, checksum normalization, directory multiplication/range, and error codes.

## Ghidra stripped output

```c
FUNCTION FUN_001016d0
ENTRY 001016d0
SIGNATURE undefined FUN_001016d0(void)
CALLERS 001020a8, 001021d4, 001012ce, 00101aff, 00101b71

uint FUN_001016d0(undefined8 *param_1,ulong param_2,int *param_3)

{
  undefined8 uVar1;
  int iVar2;
  int iVar3;

  if (param_2 < 0x18) {
    return 0xffffffff;
  }
  uVar1 = param_1[1];
  *(undefined8 *)param_3 = *param_1;
  *(undefined8 *)(param_3 + 2) = uVar1;
  *(undefined8 *)(param_3 + 4) = param_1[2];
  if ((*param_3 == 0x32585652) && ((short)param_3[1] == 2)) {
    iVar3 = param_3[5];
    param_3[5] = 0;
    iVar2 = FUN_00101580(param_3,0x14);
    if (iVar2 == iVar3) {
      param_3[5] = iVar2;
      iVar3 = FUN_00101640(param_2,param_3[2],param_3[3] << 5);
      return -(uint)(iVar3 == 0) & 0xfffffffc;
    }
    return 0xfffffffd;
  }
  return 0xfffffffe;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016d0 <lab07_read_header>:
    16d0:	48 83 fe 17          	cmp    rsi,0x17
    16d4:	76 7a                	jbe    1750 <lab07_read_header+0x80>
    16d6:	f3 0f 6f 07          	movdqu xmm0,XMMWORD PTR [rdi]
    16da:	0f 11 02             	movups XMMWORD PTR [rdx],xmm0
    16dd:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
    16e1:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
    16e5:	81 3a 52 56 58 32    	cmp    DWORD PTR [rdx],0x32585652
    16eb:	75 53                	jne    1740 <lab07_read_header+0x70>
    16ed:	66 83 7a 04 02       	cmp    WORD PTR [rdx+0x4],0x2
    16f2:	75 4c                	jne    1740 <lab07_read_header+0x70>
    16f4:	55                   	push   rbp
    16f5:	44 8b 52 14          	mov    r10d,DWORD PTR [rdx+0x14]
    16f9:	49 89 f1             	mov    r9,rsi
    16fc:	48 89 d7             	mov    rdi,rdx
    16ff:	c7 42 14 00 00 00 00 	mov    DWORD PTR [rdx+0x14],0x0
    1706:	be 14 00 00 00       	mov    esi,0x14
    170b:	49 89 d0             	mov    r8,rdx
    170e:	48 89 e5             	mov    rbp,rsp
    1711:	e8 6a fe ff ff       	call   1580 <lab01_crc32ish>
    1716:	44 39 d0             	cmp    eax,r10d
    1719:	75 45                	jne    1760 <lab07_read_header+0x90>
    171b:	41 8b 50 0c          	mov    edx,DWORD PTR [r8+0xc]
    171f:	41 8b 70 08          	mov    esi,DWORD PTR [r8+0x8]
    1723:	41 89 40 14          	mov    DWORD PTR [r8+0x14],eax
    1727:	4c 89 cf             	mov    rdi,r9
    172a:	c1 e2 05             	shl    edx,0x5
    172d:	e8 0e ff ff ff       	call   1640 <lab04_safe_range>
    1732:	5d                   	pop    rbp
    1733:	83 f8 01             	cmp    eax,0x1
    1736:	19 c0                	sbb    eax,eax
    1738:	83 e0 fc             	and    eax,0xfffffffc
    173b:	c3                   	ret
    173c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1740:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1745:	c3                   	ret
    1746:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    174d:	00 00 00
    1750:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1755:	c3                   	ret
    1756:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    175d:	00 00 00
    1760:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    1765:	5d                   	pop    rbp
    1766:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0
 RBX  0x78
 RCX  0x53502ff1
 RDX  0x7fffffffde30 ◂— 0
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   0x7fffffffde10 ◂— 0x1000232585652
 R9   0x7fffffffdf20 ◂— 0x1000232585652
 RSP  0x7fffffffddc8 —▸ 0x5555555552d3 (main+563) ◂— lea r8, [rbp - 0x310]
 RIP  0x5555555556d0 (lab07_read_header) ◂— cmp rsi, 0x17
   0x5555555556d4 <lab07_read_header+4>   ✘ jbe    lab07_read_header+128       <lab07_read_header+128>
   0x5555555556d6 <lab07_read_header+6>     movdqu xmm0, xmmword ptr [rdi]
   0x5555555556da <lab07_read_header+10>    movups xmmword ptr [rdx], xmm0
   0x5555555556dd <lab07_read_header+13>    mov    rax, qword ptr [rdi + 0x10]     RAX, [0x7fffffffdf30] => 0x4117532e00000078
   0x5555555556e1 <lab07_read_header+17>    mov    qword ptr [rdx + 0x10], rax     [0x7fffffffde40] <= 0x4117532e00000078
   0x5555555556e5 <lab07_read_header+21>    cmp    dword ptr [rdx], 0x32585652     0x32585652 - 0x32585652     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555556eb <lab07_read_header+27>  ✘ jne    lab07_read_header+112       <lab07_read_header+112>
   0x5555555556ed <lab07_read_header+29>    cmp    word ptr [rdx + 4], 2           2 - 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555556f2 <lab07_read_header+34>  ✘ jne    lab07_read_header+112       <lab07_read_header+112>
   0x5555555556f4 <lab07_read_header+36>    push   rbp
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab07_read_header`, RVA `0x16d0`.

# Walkthrough 08 — Directory entry parser

## Goal

Recover index bound, record stride, name termination, data range, and output copy.

## Ghidra stripped output

```c
FUNCTION FUN_00101770
ENTRY 00101770
SIGNATURE undefined FUN_00101770(void)
CALLERS 001020b0, 00102200, 001012f2, 00101888, 00101bc4

uint FUN_00101770(long param_1,undefined8 param_2,long param_3,uint param_4,undefined8 *param_5)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  int iVar3;
  uint uVar4;
  void *pvVar5;
  ulong uVar6;

  if (param_4 < *(uint *)(param_3 + 0xc)) {
    uVar6 = (ulong)param_4 * 0x20 + (ulong)*(uint *)(param_3 + 8);
    iVar3 = FUN_00101640(param_2,uVar6 & 0xffffffff,0x20);
    if (iVar3 == 0) {
      uVar4 = 0xfffffffe;
    }
    else {
      puVar1 = (undefined8 *)(param_1 + uVar6);
      uVar2 = puVar1[1];
      *param_5 = *puVar1;
      param_5[1] = uVar2;
      uVar2 = puVar1[3];
      param_5[2] = puVar1[2];
      param_5[3] = uVar2;
      pvVar5 = memchr(param_5,0,0x10);
      if (pvVar5 == (void *)0x0) {
        uVar4 = 0xfffffffd;
      }
      else {
        iVar3 = FUN_00101640(param_2,*(undefined4 *)(param_5 + 2),
                             *(undefined4 *)((long)param_5 + 0x14));
        uVar4 = -(uint)(iVar3 == 0) & 0xfffffffc;
      }
    }
    return uVar4;
  }
  return 0xffffffff;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001770 <lab08_read_entry>:
    1770:	3b 4a 0c             	cmp    ecx,DWORD PTR [rdx+0xc]
    1773:	0f 83 87 00 00 00    	jae    1800 <lab08_read_entry+0x90>
    1779:	55                   	push   rbp
    177a:	89 c9                	mov    ecx,ecx
    177c:	48 c1 e1 05          	shl    rcx,0x5
    1780:	48 89 e5             	mov    rbp,rsp
    1783:	41 54                	push   r12
    1785:	49 89 f4             	mov    r12,rsi
    1788:	53                   	push   rbx
    1789:	8b 42 08             	mov    eax,DWORD PTR [rdx+0x8]
    178c:	4c 89 c3             	mov    rbx,r8
    178f:	ba 20 00 00 00       	mov    edx,0x20
    1794:	49 89 f8             	mov    r8,rdi
    1797:	4c 89 e7             	mov    rdi,r12
    179a:	48 01 c1             	add    rcx,rax
    179d:	89 ce                	mov    esi,ecx
    179f:	e8 9c fe ff ff       	call   1640 <lab04_safe_range>
    17a4:	85 c0                	test   eax,eax
    17a6:	74 48                	je     17f0 <lab08_read_entry+0x80>
    17a8:	49 8d 04 08          	lea    rax,[r8+rcx*1]
    17ac:	31 f6                	xor    esi,esi
    17ae:	ba 10 00 00 00       	mov    edx,0x10
    17b3:	48 89 df             	mov    rdi,rbx
    17b6:	f3 0f 6f 00          	movdqu xmm0,XMMWORD PTR [rax]
    17ba:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
    17bd:	f3 0f 6f 40 10       	movdqu xmm0,XMMWORD PTR [rax+0x10]
    17c2:	0f 11 43 10          	movups XMMWORD PTR [rbx+0x10],xmm0
    17c6:	e8 95 f8 ff ff       	call   1060 <memchr@plt>
    17cb:	48 85 c0             	test   rax,rax
    17ce:	74 36                	je     1806 <lab08_read_entry+0x96>
    17d0:	8b 53 14             	mov    edx,DWORD PTR [rbx+0x14]
    17d3:	8b 73 10             	mov    esi,DWORD PTR [rbx+0x10]
    17d6:	4c 89 e7             	mov    rdi,r12
    17d9:	e8 62 fe ff ff       	call   1640 <lab04_safe_range>
    17de:	83 f8 01             	cmp    eax,0x1
    17e1:	19 c0                	sbb    eax,eax
    17e3:	83 e0 fc             	and    eax,0xfffffffc
    17e6:	5b                   	pop    rbx
    17e7:	41 5c                	pop    r12
    17e9:	5d                   	pop    rbp
    17ea:	c3                   	ret
    17eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    17f0:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    17f5:	eb ef                	jmp    17e6 <lab08_read_entry+0x76>
    17f7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    17fe:	00 00
    1800:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1805:	c3                   	ret
    1806:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    180b:	eb d9                	jmp    17e6 <lab08_read_entry+0x76>

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0
 RBX  0x78
 RCX  1
 RDX  0x7fffffffde30 ◂— 0x1000232585652
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   0x7fffffffde50 —▸ 0x7fffffffdeb0 —▸ 0x7fffffffdef0 —▸ 0x7fffffffe190 —▸ 0x7fffffffe1d0 ◂— ...
 R9   0x78
 RSP  0x7fffffffddc8 —▸ 0x5555555552f7 (main+599) ◂— lea r8, [rbp - 0x310]
 RIP  0x555555555770 (lab08_read_entry) ◂— cmp ecx, dword ptr [rdx + 0xc]
   0x555555555773 <lab08_read_entry+3>   ✘ jae    lab08_read_entry+144        <lab08_read_entry+144>
   0x555555555779 <lab08_read_entry+9>     push   rbp
   0x55555555577a <lab08_read_entry+10>    mov    ecx, ecx                     ECX => 1
   0x55555555577c <lab08_read_entry+12>    shl    rcx, 5
   0x555555555780 <lab08_read_entry+16>    mov    rbp, rsp                     RBP => 0x7fffffffddc0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555783 <lab08_read_entry+19>    push   r12
   0x555555555785 <lab08_read_entry+21>    mov    r12, rsi                     R12 => 0x78
   0x555555555788 <lab08_read_entry+24>    push   rbx
   0x555555555789 <lab08_read_entry+25>    mov    eax, dword ptr [rdx + 8]     EAX, [0x7fffffffde38] => 0x18
   0x55555555578c <lab08_read_entry+28>    mov    rbx, r8                      RBX => 0x7fffffffde50 —▸ 0x7fffffffdeb0 —▸ 0x7fffffffdef0 —▸ 0x7fffffffe190 ◂— ...
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab08_read_entry`, RVA `0x1770`.

# Walkthrough 09 — Name-based directory search

## Goal

Recover iteration, parser composition, strcmp, found index, and error propagation.

## Ghidra stripped output

```c
FUNCTION FUN_00101810
ENTRY 00101810
SIGNATURE undefined FUN_00101810(void)
CALLERS 001020b8, 00102238, 00101318, 0010194e

int FUN_00101810(undefined8 param_1,undefined8 param_2,long param_3,char *param_4,
                undefined8 *param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  long in_FS_OFFSET;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = *(int *)(param_3 + 0xc);
  if (iVar1 != 0) {
    iVar3 = 0;
    do {
      iVar2 = FUN_00101770(param_1,param_2,param_3,iVar3,&local_68);
      if (iVar2 != 0) {
        iVar3 = -2;
        goto LAB_001018a6;
      }
      iVar2 = strcmp((char *)&local_68,param_4);
      if (iVar2 == 0) {
        *param_5 = local_68;
        param_5[1] = uStack_60;
        param_5[2] = local_58;
        param_5[3] = uStack_50;
        goto LAB_001018a6;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 != iVar1);
  }
  iVar3 = -1;
LAB_001018a6:
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar3;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001810 <lab09_find_entry>:
    1810:	55                   	push   rbp
    1811:	48 89 e5             	mov    rbp,rsp
    1814:	48 83 ec 70          	sub    rsp,0x70
    1818:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    181c:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
    1820:	4c 89 45 90          	mov    QWORD PTR [rbp-0x70],r8
    1824:	64 4c 8b 2c 25 28 00 	mov    r13,QWORD PTR fs:0x28
    182b:	00 00
    182d:	4c 89 6d c8          	mov    QWORD PTR [rbp-0x38],r13
    1831:	44 8b 6a 0c          	mov    r13d,DWORD PTR [rdx+0xc]
    1835:	45 85 ed             	test   r13d,r13d
    1838:	0f 84 92 00 00 00    	je     18d0 <lab09_find_entry+0xc0>
    183e:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1842:	31 db                	xor    ebx,ebx
    1844:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    1848:	49 89 d4             	mov    r12,rdx
    184b:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    184f:	49 89 f6             	mov    r14,rsi
    1852:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1856:	49 89 ff             	mov    r15,rdi
    1859:	eb 1e                	jmp    1879 <lab09_find_entry+0x69>
    185b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1860:	48 8b 75 98          	mov    rsi,QWORD PTR [rbp-0x68]
    1864:	48 8d 7d a0          	lea    rdi,[rbp-0x60]
    1868:	e8 03 f8 ff ff       	call   1070 <strcmp@plt>
    186d:	85 c0                	test   eax,eax
    186f:	74 6f                	je     18e0 <lab09_find_entry+0xd0>
    1871:	83 c3 01             	add    ebx,0x1
    1874:	44 39 eb             	cmp    ebx,r13d
    1877:	74 47                	je     18c0 <lab09_find_entry+0xb0>
    1879:	4c 8d 45 a0          	lea    r8,[rbp-0x60]
    187d:	89 d9                	mov    ecx,ebx
    187f:	4c 89 e2             	mov    rdx,r12
    1882:	4c 89 f6             	mov    rsi,r14
    1885:	4c 89 ff             	mov    rdi,r15
    1888:	e8 e3 fe ff ff       	call   1770 <lab08_read_entry>
    188d:	85 c0                	test   eax,eax
    188f:	74 cf                	je     1860 <lab09_find_entry+0x50>
    1891:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    1895:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    1899:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    189e:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    18a2:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    18a6:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    18aa:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    18b1:	00 00
    18b3:	75 54                	jne    1909 <lab09_find_entry+0xf9>
    18b5:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    18b9:	c9                   	leave
    18ba:	c3                   	ret
    18bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    18c0:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    18c4:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    18c8:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    18cc:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    18d0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    18d5:	eb cf                	jmp    18a6 <lab09_find_entry+0x96>
    18d7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    18de:	00 00
    18e0:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
    18e4:	66 0f 6f 45 a0       	movdqa xmm0,XMMWORD PTR [rbp-0x60]
    18e9:	0f 11 00             	movups XMMWORD PTR [rax],xmm0
    18ec:	66 0f 6f 45 b0       	movdqa xmm0,XMMWORD PTR [rbp-0x50]
    18f1:	0f 11 40 10          	movups XMMWORD PTR [rax+0x10],xmm0
    18f5:	89 d8                	mov    eax,ebx
    18f7:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    18fb:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    18ff:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    1903:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    1907:	eb 9d                	jmp    18a6 <lab09_find_entry+0x96>
    1909:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    190d:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    1911:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1915:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1919:	e8 12 f7 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0
 RBX  0x78
 RCX  0x55555555600b ◂— 'alpha.txt'
 RDX  0x7fffffffde30 ◂— 0x1000232585652
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   0x7fffffffde50 ◂— 'beta.bin'
 R9   0x78
 RSP  0x7fffffffddc8 —▸ 0x55555555531d (main+637) ◂— sub rsp, 8
 RIP  0x555555555810 (lab09_find_entry) ◂— push rbp
   0x555555555811 <lab09_find_entry+1>     mov    rbp, rsp                        RBP => 0x7fffffffddc0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555814 <lab09_find_entry+4>     sub    rsp, 0x70                       RSP => 0x7fffffffdd50 (0x7fffffffddc0 - 0x70)
   0x555555555818 <lab09_find_entry+8>     mov    qword ptr [rbp - 0x18], r13     [0x7fffffffdda8] <= 1
   0x55555555581c <lab09_find_entry+12>    mov    qword ptr [rbp - 0x68], rcx     [0x7fffffffdd58] <= 0x55555555600b ◂— 'alpha.txt'
   0x555555555820 <lab09_find_entry+16>    mov    qword ptr [rbp - 0x70], r8      [0x7fffffffdd50] <= 0x7fffffffde50 ◂— 'beta.bin'
   0x555555555824 <lab09_find_entry+20>    mov    r13, qword ptr fs:[0x28]        R13, [0x7ffff7f7f768] => 0xdc1253a2474ac00
   0x55555555582d <lab09_find_entry+29>    mov    qword ptr [rbp - 0x38], r13     [0x7fffffffdd88] <= 0xdc1253a2474ac00
   0x555555555831 <lab09_find_entry+33>    mov    r13d, dword ptr [rdx + 0xc]     R13D, [0x7fffffffde3c] => 2
   0x555555555835 <lab09_find_entry+37>    test   r13d, r13d                      2 & 2     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555838 <lab09_find_entry+40>  ✘ je     lab09_find_entry+192        <lab09_find_entry+192>
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab09_find_entry`, RVA `0x1810`.

# Walkthrough 10 — Complete extraction

## Goal

Recover find, size/capacity, copy, transform, CRC, and original-length return.

## Ghidra stripped output

```c
FUNCTION FUN_00101920
ENTRY 00101920
SIGNATURE undefined FUN_00101920(void)
CALLERS 001020c0, 0010229c, 0010134d

uint FUN_00101920(long param_1)

{
  long lVar1;
  int iVar2;
  uint uVar3;
  void *in_R8;
  ulong in_R9;
  long in_FS_OFFSET;
  undefined4 in_stack_00000008;
  uint local_58;
  uint local_54;
  uint local_50;
  int local_4c;

  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  iVar2 = FUN_00101810();
  if (iVar2 < 0) {
    uVar3 = 0xffffffff;
  }
  else if ((in_R9 < local_50) || (local_54 < local_50)) {
    uVar3 = 0xfffffffe;
  }
  else {
    memcpy(in_R8,(void *)(param_1 + (ulong)local_58),(ulong)local_54);
    FUN_00101600(in_R8,(ulong)local_54,in_stack_00000008);
    iVar2 = FUN_00101580(in_R8,(ulong)local_50);
    uVar3 = 0xfffffffd;
    if (iVar2 == local_4c) {
      uVar3 = local_50;
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001920 <lab10_extract>:
    1920:	55                   	push   rbp
    1921:	48 89 e5             	mov    rbp,rsp
    1924:	48 83 ec 60          	sub    rsp,0x60
    1928:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    192c:	49 89 fd             	mov    r13,rdi
    192f:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1933:	4d 89 c6             	mov    r14,r8
    1936:	4c 8d 45 a0          	lea    r8,[rbp-0x60]
    193a:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    193e:	64 4c 8b 24 25 28 00 	mov    r12,QWORD PTR fs:0x28
    1945:	00 00
    1947:	4c 89 65 c8          	mov    QWORD PTR [rbp-0x38],r12
    194b:	4d 89 cc             	mov    r12,r9
    194e:	e8 bd fe ff ff       	call   1810 <lab09_find_entry>
    1953:	85 c0                	test   eax,eax
    1955:	0f 88 8c 00 00 00    	js     19e7 <lab10_extract+0xc7>
    195b:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    195f:	44 8b 7d b8          	mov    r15d,DWORD PTR [rbp-0x48]
    1963:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1967:	4d 39 fc             	cmp    r12,r15
    196a:	72 6c                	jb     19d8 <lab10_extract+0xb8>
    196c:	8b 45 b4             	mov    eax,DWORD PTR [rbp-0x4c]
    196f:	44 39 f8             	cmp    eax,r15d
    1972:	72 64                	jb     19d8 <lab10_extract+0xb8>
    1974:	41 89 c4             	mov    r12d,eax
    1977:	8b 45 b0             	mov    eax,DWORD PTR [rbp-0x50]
    197a:	4c 89 f7             	mov    rdi,r14
    197d:	4c 89 e2             	mov    rdx,r12
    1980:	49 8d 74 05 00       	lea    rsi,[r13+rax*1+0x0]
    1985:	e8 f6 f6 ff ff       	call   1080 <memcpy@plt>
    198a:	8b 55 10             	mov    edx,DWORD PTR [rbp+0x10]
    198d:	4c 89 e6             	mov    rsi,r12
    1990:	4c 89 f7             	mov    rdi,r14
    1993:	e8 68 fc ff ff       	call   1600 <lab03_stream_xor>
    1998:	4c 89 fe             	mov    rsi,r15
    199b:	4c 89 f7             	mov    rdi,r14
    199e:	e8 dd fb ff ff       	call   1580 <lab01_crc32ish>
    19a3:	3b 45 bc             	cmp    eax,DWORD PTR [rbp-0x44]
    19a6:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    19ab:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    19af:	41 0f 44 c7          	cmove  eax,r15d
    19b3:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    19b7:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    19bb:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    19c2:	00 00
    19c4:	75 28                	jne    19ee <lab10_extract+0xce>
    19c6:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    19ca:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    19ce:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    19d2:	c9                   	leave
    19d3:	c3                   	ret
    19d4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    19d8:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    19dc:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    19e0:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    19e5:	eb d0                	jmp    19b7 <lab10_extract+0x97>
    19e7:	b8 ff ff ff ff       	mov    eax,0xffffffff
    19ec:	eb c9                	jmp    19b7 <lab10_extract+0x97>
    19ee:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    19f2:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    19f6:	e8 35 f6 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0
 RBX  0x78
 RCX  0x55555555600b ◂— 'alpha.txt'
 RDX  0x7fffffffde30 ◂— 0x1000232585652
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   0x7fffffffdee0 ◂— 0xfffffffffffffff8
 R9   0x40
 RSP  0x7fffffffddb8 —▸ 0x555555555352 (main+690) ◂— lea rdi, [rbp - 0x290]
 RIP  0x555555555920 (lab10_extract) ◂— push rbp
   0x555555555921 <lab10_extract+1>     mov    rbp, rsp                        RBP => 0x7fffffffddb0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555924 <lab10_extract+4>     sub    rsp, 0x60                       RSP => 0x7fffffffdd50 (0x7fffffffddb0 - 0x60)
   0x555555555928 <lab10_extract+8>     mov    qword ptr [rbp - 0x18], r13     [0x7fffffffdd98] <= 1
   0x55555555592c <lab10_extract+12>    mov    r13, rdi                        R13 => 0x7fffffffdf20 ◂— 0x1000232585652
   0x55555555592f <lab10_extract+15>    mov    qword ptr [rbp - 0x10], r14     [0x7fffffffdda0] <= 0
   0x555555555933 <lab10_extract+19>    mov    r14, r8                         R14 => 0x7fffffffdee0 ◂— 0xfffffffffffffff8
   0x555555555936 <lab10_extract+22>    lea    r8, [rbp - 0x60]                R8 => 0x7fffffffdd50 —▸ 0x7fffffffde50 ◂— 'alpha.txt'
   0x55555555593a <lab10_extract+26>    mov    qword ptr [rbp - 0x20], r12     [0x7fffffffdd90] <= 0x27970424
   0x55555555593e <lab10_extract+30>    mov    r12, qword ptr fs:[0x28]        R12, [0x7ffff7f7f768] => 0xdc1253a2474ac00
   0x555555555947 <lab10_extract+39>    mov    qword ptr [rbp - 0x38], r12     [0x7fffffffdd78] <= 0xdc1253a2474ac00
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab10_extract`, RVA `0x1920`.

# Walkthrough 11 — Variable-length integer encoding

## Goal

Recover 7-bit chunks, continuation bit, do-while, and byte count.

## Ghidra stripped output

```c
FUNCTION FUN_00101a00
ENTRY 00101a00
SIGNATURE undefined FUN_00101a00(void)
CALLERS 001020c8, 001022e0, 00101369

long FUN_00101a00(undefined1 *param_1,ulong param_2)

{
  long lVar1;
  long lVar2;
  undefined1 uVar3;
  ulong uVar4;

  uVar4 = param_2 & 0xffffffff;
  uVar3 = (undefined1)uVar4;
  param_2 = param_2 >> 7;
  lVar1 = 1;
  if (param_2 != 0) {
    lVar1 = 0;
    do {
      lVar2 = lVar1;
      param_1[lVar2] = (byte)uVar4 | 0x80;
      uVar4 = param_2 & 0xffffffff;
      uVar3 = (undefined1)uVar4;
      param_2 = param_2 >> 7;
      lVar1 = lVar2 + 1;
    } while (param_2 != 0);
    lVar1 = lVar2 + 2;
    param_1 = param_1 + lVar2 + 1;
  }
  *param_1 = uVar3;
  return lVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001a00 <lab11_encode_varint>:
    1a00:	89 f2                	mov    edx,esi
    1a02:	48 c1 ee 07          	shr    rsi,0x7
    1a06:	b8 01 00 00 00       	mov    eax,0x1
    1a0b:	74 30                	je     1a3d <lab11_encode_varint+0x3d>
    1a0d:	31 c9                	xor    ecx,ecx
    1a0f:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1a15:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1a1c:	00 00 00 00
    1a20:	83 ca 80             	or     edx,0xffffff80
    1a23:	48 89 c8             	mov    rax,rcx
    1a26:	48 83 c1 01          	add    rcx,0x1
    1a2a:	88 54 0f ff          	mov    BYTE PTR [rdi+rcx*1-0x1],dl
    1a2e:	89 f2                	mov    edx,esi
    1a30:	48 c1 ee 07          	shr    rsi,0x7
    1a34:	75 ea                	jne    1a20 <lab11_encode_varint+0x20>
    1a36:	48 83 c0 02          	add    rax,0x2
    1a3a:	48 01 cf             	add    rdi,rcx
    1a3d:	88 17                	mov    BYTE PTR [rdi],dl
    1a3f:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0xd
 RBX  0x78
 RCX  0x4ae4637c
 RDX  0
 RDI  0x7fffffffded0 ◂— 0
 RSI  0x123456789
 R8   0x7fffffffdf20 ◂— 0x1000232585652
 R9   0x40
 RSP  0x7fffffffddb8 —▸ 0x55555555536e (main+718) ◂— lea rdx, [rbp - 0x360]
 RIP  0x555555555a00 (lab11_encode_varint) ◂— mov edx, esi
   0x555555555a02 <lab11_encode_varint+2>     shr    rsi, 7
   0x555555555a06 <lab11_encode_varint+6>     mov    eax, 1       EAX => 1
   0x555555555a0b <lab11_encode_varint+11>  ✘ je     lab11_encode_varint+61      <lab11_encode_varint+61>
   0x555555555a0d <lab11_encode_varint+13>    xor    ecx, ecx                         ECX => 0
   0x555555555a0f <lab11_encode_varint+15>    nop    word ptr [rax + rax]
   0x555555555a15 <lab11_encode_varint+21>    nop    word ptr [rax + rax]
   0x555555555a20 <lab11_encode_varint+32>    or     edx, 0xffffff80                  EDX => 0xffffff89 (0x23456789 | 0xffffff80)
   0x555555555a23 <lab11_encode_varint+35>    mov    rax, rcx                         RAX => 0
   0x555555555a26 <lab11_encode_varint+38>    add    rcx, 1                           RCX => 1 (0 + 1)
   0x555555555a2a <lab11_encode_varint+42>    mov    byte ptr [rdi + rcx - 1], dl     [0x7fffffffded0] <= 0x89
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab11_encode_varint`, RVA `0x1a00`.

# Walkthrough 12 — Hardened varint decoding

## Goal

Recover ten-byte cap, shift, terminal byte, 64-bit overflow check, and error distinction.

## Ghidra stripped output

```c
FUNCTION FUN_00101a40
ENTRY 00101a40
SIGNATURE undefined FUN_00101a40(void)
CALLERS 001020d0, 001022f4, 00101382

int FUN_00101a40(long param_1,long param_2,ulong *param_3)

{
  byte bVar1;
  long lVar2;
  int iVar3;
  ulong uVar4;

  lVar2 = 0;
  iVar3 = 0;
  uVar4 = 0;
  if (param_2 != 0) {
    do {
      bVar1 = *(byte *)(param_1 + lVar2);
      if (iVar3 == 0x3f) {
        if (1 < bVar1) {
          return -2;
        }
        uVar4 = uVar4 | (ulong)(uint)bVar1 << 0x3f;
LAB_00101a92:
        *param_3 = uVar4;
        return (int)lVar2 + 1;
      }
      uVar4 = uVar4 | (ulong)(bVar1 & 0x7f) << ((byte)iVar3 & 0x3f);
      if (-1 < (char)bVar1) goto LAB_00101a92;
      lVar2 = lVar2 + 1;
      iVar3 = iVar3 + 7;
    } while (param_2 != lVar2);
  }
  return -1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001a40 <lab12_decode_varint>:
    1a40:	49 89 f9             	mov    r9,rdi
    1a43:	49 89 f0             	mov    r8,rsi
    1a46:	49 89 d2             	mov    r10,rdx
    1a49:	31 c0                	xor    eax,eax
    1a4b:	31 c9                	xor    ecx,ecx
    1a4d:	31 ff                	xor    edi,edi
    1a4f:	48 85 f6             	test   rsi,rsi
    1a52:	75 28                	jne    1a7c <lab12_decode_varint+0x3c>
    1a54:	eb 5a                	jmp    1ab0 <lab12_decode_varint+0x70>
    1a56:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1a5d:	00 00 00
    1a60:	48 89 d6             	mov    rsi,rdx
    1a63:	83 e6 7f             	and    esi,0x7f
    1a66:	48 d3 e6             	shl    rsi,cl
    1a69:	48 09 f7             	or     rdi,rsi
    1a6c:	84 d2                	test   dl,dl
    1a6e:	79 22                	jns    1a92 <lab12_decode_varint+0x52>
    1a70:	48 83 c0 01          	add    rax,0x1
    1a74:	83 c1 07             	add    ecx,0x7
    1a77:	49 39 c0             	cmp    r8,rax
    1a7a:	74 34                	je     1ab0 <lab12_decode_varint+0x70>
    1a7c:	41 0f b6 14 01       	movzx  edx,BYTE PTR [r9+rax*1]
    1a81:	83 f9 3f             	cmp    ecx,0x3f
    1a84:	75 da                	jne    1a60 <lab12_decode_varint+0x20>
    1a86:	80 fa 01             	cmp    dl,0x1
    1a89:	77 15                	ja     1aa0 <lab12_decode_varint+0x60>
    1a8b:	48 c1 e2 3f          	shl    rdx,0x3f
    1a8f:	48 09 d7             	or     rdi,rdx
    1a92:	49 89 3a             	mov    QWORD PTR [r10],rdi
    1a95:	83 c0 01             	add    eax,0x1
    1a98:	c3                   	ret
    1a99:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1aa0:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1aa5:	c3                   	ret
    1aa6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1aad:	00 00 00
    1ab0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1ab5:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  5
 RBX  0x78
 RCX  4
 RDX  0x7fffffffde00 —▸ 0x7fffffffde80 ◂— 0xd00000060 /* '`' */
 RDI  0x7fffffffded0 ◂— 0x129a95cf89
 RSI  5
 R8   0x7fffffffdf20 ◂— 0x1000232585652
 R9   0x40
 RSP  0x7fffffffddb8 —▸ 0x555555555387 (main+743) ◂— lea rdi, [rip + 0xc87]
 RIP  0x555555555a40 (lab12_decode_varint) ◂— mov r9, rdi
   0x555555555a43 <lab12_decode_varint+3>     mov    r8, rsi      R8 => 5
   0x555555555a46 <lab12_decode_varint+6>     mov    r10, rdx     R10 => 0x7fffffffde00 —▸ 0x7fffffffde80 ◂— 0xd00000060 /* '`' */
   0x555555555a49 <lab12_decode_varint+9>     xor    eax, eax     EAX => 0
   0x555555555a4b <lab12_decode_varint+11>    xor    ecx, ecx     ECX => 0
   0x555555555a4d <lab12_decode_varint+13>    xor    edi, edi     EDI => 0
   0x555555555a4f <lab12_decode_varint+15>    test   rsi, rsi     5 & 5     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555a52 <lab12_decode_varint+18>  ✔ jne    lab12_decode_varint+60      <lab12_decode_varint+60>
   0x555555555a7c <lab12_decode_varint+60>    movzx  edx, byte ptr [r9 + rax]     EDX, [0x7fffffffded0] => 0x89
   0x555555555a81 <lab12_decode_varint+65>    cmp    ecx, 0x3f                    0x0 - 0x3f     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x555555555a84 <lab12_decode_varint+68>  ✔ jne    lab12_decode_varint+32      <lab12_decode_varint+32>
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab12_decode_varint`, RVA `0x1a40`.

# Walkthrough 13 — Big-endian scalar decoding

## Goal

Combine four bytes with shifts while avoiding sign extension.

## Ghidra stripped output

```c
FUNCTION FUN_00101ac0
ENTRY 00101ac0
SIGNATURE undefined FUN_00101ac0(void)
CALLERS 001020d8, 00102308, 001013a4

uint FUN_00101ac0(uint *param_1)

{
  uint uVar1;

  uVar1 = *param_1;
  return uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 | uVar1 << 0x18;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001ac0 <lab13_be32>:
    1ac0:	8b 07                	mov    eax,DWORD PTR [rdi]
    1ac2:	0f c8                	bswap  eax
    1ac4:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  5
 RBX  0x78
 RCX  0x58
 RDX  0
 RDI  0x555555556015 ◂— 0x32585652 /* 'RVX2' */
 RSI  0x78
 R8   5
 R9   0x7fffffffded0 ◂— 0x129a95cf89
 RSP  0x7fffffffddb8 —▸ 0x5555555553a9 (main+777) ◂— lea rdi, [rbp - 0x240]
 RIP  0x555555555ac0 (lab13_be32) ◂— mov eax, dword ptr [rdi]
   0x555555555ac2 <lab13_be32+2>    bswap  eax
   0x555555555ac4 <lab13_be32+4>    ret                                <main+777>
   0x5555555553a9 <main+777>        lea    rdi, [rbp - 0x240]               RDI => 0x7fffffffdf20 ◂— 0x1000232585652
   0x5555555553b0 <main+784>        mov    dword ptr [rbp - 0x380], eax     [0x7fffffffdde0] <= 0x52565832
   0x5555555553b6 <main+790>        call   lab14_mutation_check        <lab14_mutation_check>
   0x5555555553bb <main+795>        lea    rcx, [rbp - 0x358]
   0x5555555553c2 <main+802>        mov    esi, ebx
   0x5555555553c4 <main+804>        lea    rdx, [rbp - 0x364]
   0x5555555553cb <main+811>        lea    rdi, [rbp - 0x240]
   0x5555555553d2 <main+818>        mov    dword ptr [rbp - 0x384], eax
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab13_be32`, RVA `0x1ac0`.

# Walkthrough 14 — Differential corruption experiment

## Goal

Recover temporary byte mutation, parser call, restoration, and returned failure class.

## Ghidra stripped output

```c
FUNCTION FUN_00101ad0
ENTRY 00101ad0
SIGNATURE undefined FUN_00101ad0(void)
CALLERS 001020e0, 0010231c, 001013b6

undefined8 FUN_00101ad0(long param_1,ulong param_2,ulong param_3,undefined1 param_4)

{
  undefined1 uVar1;
  undefined8 uVar2;
  undefined1 *puVar3;
  long in_FS_OFFSET;
  undefined1 local_38 [24];
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_3 < param_2) {
    puVar3 = (undefined1 *)(param_1 + param_3);
    uVar1 = *puVar3;
    *puVar3 = param_4;
    uVar2 = FUN_001016d0(param_1,param_2,local_38);
    *puVar3 = uVar1;
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001ad0 <lab14_mutation_check>:
    1ad0:	55                   	push   rbp
    1ad1:	48 89 e5             	mov    rbp,rsp
    1ad4:	48 83 ec 30          	sub    rsp,0x30
    1ad8:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1adf:	00 00
    1ae1:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    1ae5:	31 c0                	xor    eax,eax
    1ae7:	48 39 f2             	cmp    rdx,rsi
    1aea:	73 34                	jae    1b20 <lab14_mutation_check+0x50>
    1aec:	4c 8d 1c 17          	lea    r11,[rdi+rdx*1]
    1af0:	48 89 5d f8          	mov    QWORD PTR [rbp-0x8],rbx
    1af4:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
    1af8:	41 0f b6 1b          	movzx  ebx,BYTE PTR [r11]
    1afc:	41 88 0b             	mov    BYTE PTR [r11],cl
    1aff:	e8 cc fb ff ff       	call   16d0 <lab07_read_header>
    1b04:	41 88 1b             	mov    BYTE PTR [r11],bl
    1b07:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    1b0b:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    1b0f:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    1b16:	00 00
    1b18:	75 0d                	jne    1b27 <lab14_mutation_check+0x57>
    1b1a:	c9                   	leave
    1b1b:	c3                   	ret
    1b1c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1b20:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1b25:	eb e4                	jmp    1b0b <lab14_mutation_check+0x3b>
    1b27:	48 89 5d f8          	mov    QWORD PTR [rbp-0x8],rbx
    1b2b:	e8 00 f5 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0x52565832
 RBX  0x78
 RCX  0x58
 RDX  0
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   5
 R9   0x7fffffffded0 ◂— 0x129a95cf89
 RSP  0x7fffffffddb8 —▸ 0x5555555553bb (main+795) ◂— lea rcx, [rbp - 0x358]
 RIP  0x555555555ad0 (lab14_mutation_check) ◂— push rbp
   0x555555555ad1 <lab14_mutation_check+1>     mov    rbp, rsp                        RBP => 0x7fffffffddb0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555ad4 <lab14_mutation_check+4>     sub    rsp, 0x30                       RSP => 0x7fffffffdd80 (0x7fffffffddb0 - 0x30)
   0x555555555ad8 <lab14_mutation_check+8>     mov    rax, qword ptr fs:[0x28]        RAX, [0x7ffff7f7f768] => 0xdc1253a2474ac00
   0x555555555ae1 <lab14_mutation_check+17>    mov    qword ptr [rbp - 0x18], rax     [0x7fffffffdd98] <= 0xdc1253a2474ac00
   0x555555555ae5 <lab14_mutation_check+21>    xor    eax, eax                        EAX => 0
   0x555555555ae7 <lab14_mutation_check+23>    cmp    rdx, rsi                        0x0 - 0x78     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ac ]
   0x555555555aea <lab14_mutation_check+26>  ✘ jae    lab14_mutation_check+80     <lab14_mutation_check+80>
   0x555555555aec <lab14_mutation_check+28>    lea    r11, [rdi + rdx]             R11 => 0x7fffffffdf20 ◂— 0x1000232585652
   0x555555555af0 <lab14_mutation_check+32>    mov    qword ptr [rbp - 8], rbx     [0x7fffffffdda8] <= 0x78
   0x555555555af4 <lab14_mutation_check+36>    lea    rdx, [rbp - 0x30]            RDX => 0x7fffffffdd80 —▸ 0x7ffff7feee5b ◂— 0x675f6f7364765f5f ('__vdso_g')
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab14_mutation_check`, RVA `0x1ad0`.

# Walkthrough 15 — Whole archive inspection

## Goal

Compose header/entry parsing, accumulate original lengths, output counts, and fail fast.

## Ghidra stripped output

```c
FUNCTION FUN_00101b30
ENTRY 00101b30
SIGNATURE undefined FUN_00101b30(void)
CALLERS 001020e8, 00102344, 001013d8

int FUN_00101b30(undefined8 param_1,undefined8 param_2,int *param_3,long *param_4)

{
  int iVar1;
  int iVar2;
  long lVar3;
  int iVar4;
  long in_FS_OFFSET;
  int local_8c;
  undefined1 local_88 [12];
  int local_7c;
  undefined1 local_68 [24];
  uint local_50;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_7c = 0;
  iVar2 = FUN_001016d0(param_1,param_2,local_88);
  iVar1 = local_7c;
  local_8c = iVar2;
  if (iVar2 == 0) {
    if (local_7c == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = 0;
      iVar4 = 0;
      do {
        local_7c = iVar1;
        local_8c = FUN_00101770(param_1,param_2,local_88,iVar4,local_68);
        if (local_8c != 0) goto LAB_00101bdf;
        iVar4 = iVar4 + 1;
        lVar3 = lVar3 + (ulong)local_50;
      } while (iVar1 != iVar4);
    }
    *param_3 = iVar1;
    *param_4 = lVar3;
    local_8c = iVar2;
  }
LAB_00101bdf:
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_8c;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch06/ch06_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001b30 <lab15_inspect>:
    1b30:	55                   	push   rbp
    1b31:	48 89 e5             	mov    rbp,rsp
    1b34:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
    1b3b:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    1b3f:	49 89 fc             	mov    r12,rdi
    1b42:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1b46:	49 89 f5             	mov    r13,rsi
    1b49:	48 89 95 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rdx
    1b50:	48 8d 55 80          	lea    rdx,[rbp-0x80]
    1b54:	48 89 8d 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rcx
    1b5b:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1b62:	00 00
    1b64:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
    1b68:	31 c0                	xor    eax,eax
    1b6a:	c7 45 8c 00 00 00 00 	mov    DWORD PTR [rbp-0x74],0x0
    1b71:	e8 5a fb ff ff       	call   16d0 <lab07_read_header>
    1b76:	89 85 7c ff ff ff    	mov    DWORD PTR [rbp-0x84],eax
    1b7c:	85 c0                	test   eax,eax
    1b7e:	75 5f                	jne    1bdf <lab15_inspect+0xaf>
    1b80:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1b84:	44 8b 75 8c          	mov    r14d,DWORD PTR [rbp-0x74]
    1b88:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1b8c:	45 85 f6             	test   r14d,r14d
    1b8f:	0f 84 8d 00 00 00    	je     1c22 <lab15_inspect+0xf2>
    1b95:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1b99:	31 db                	xor    ebx,ebx
    1b9b:	45 31 ff             	xor    r15d,r15d
    1b9e:	eb 0f                	jmp    1baf <lab15_inspect+0x7f>
    1ba0:	8b 45 b8             	mov    eax,DWORD PTR [rbp-0x48]
    1ba3:	41 83 c7 01          	add    r15d,0x1
    1ba7:	48 01 c3             	add    rbx,rax
    1baa:	45 39 fe             	cmp    r14d,r15d
    1bad:	74 51                	je     1c00 <lab15_inspect+0xd0>
    1baf:	4c 8d 45 a0          	lea    r8,[rbp-0x60]
    1bb3:	44 89 f9             	mov    ecx,r15d
    1bb6:	48 8d 55 80          	lea    rdx,[rbp-0x80]
    1bba:	4c 89 ee             	mov    rsi,r13
    1bbd:	4c 89 e7             	mov    rdi,r12
    1bc0:	44 89 75 8c          	mov    DWORD PTR [rbp-0x74],r14d
    1bc4:	e8 a7 fb ff ff       	call   1770 <lab08_read_entry>
    1bc9:	85 c0                	test   eax,eax
    1bcb:	74 d3                	je     1ba0 <lab15_inspect+0x70>
    1bcd:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    1bd1:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    1bd5:	89 85 7c ff ff ff    	mov    DWORD PTR [rbp-0x84],eax
    1bdb:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    1bdf:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    1be3:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1bea:	00 00
    1bec:	75 38                	jne    1c26 <lab15_inspect+0xf6>
    1bee:	8b 85 7c ff ff ff    	mov    eax,DWORD PTR [rbp-0x84]
    1bf4:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    1bf8:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    1bfc:	c9                   	leave
    1bfd:	c3                   	ret
    1bfe:	66 90                	xchg   ax,ax
    1c00:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    1c04:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
    1c0b:	44 89 30             	mov    DWORD PTR [rax],r14d
    1c0e:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
    1c15:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    1c19:	48 89 18             	mov    QWORD PTR [rax],rbx
    1c1c:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    1c20:	eb bd                	jmp    1bdf <lab15_inspect+0xaf>
    1c22:	31 db                	xor    ebx,ebx
    1c24:	eb de                	jmp    1c04 <lab15_inspect+0xd4>
    1c26:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1c2a:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1c2e:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1c32:	e8 f9 f3 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## pwndbg evidence

```text
RAX  0xfffffffe
 RBX  0x78
 RCX  0x7fffffffde08 —▸ 0x7ffff7fc1c88 ◂— 0x3a5a8
 RDX  0x7fffffffddfc ◂— 0x2345678900007fff
 RDI  0x7fffffffdf20 ◂— 0x1000232585652
 RSI  0x78
 R8   5
 R9   0x7fffffffded0 ◂— 0x129a95cf89
 RSP  0x7fffffffddb8 —▸ 0x5555555553dd (main+829) ◂— mov r9, qword ptr [rbp - 0x358]
 RIP  0x555555555b30 (lab15_inspect) ◂— push rbp
   0x555555555b31 <lab15_inspect+1>     mov    rbp, rsp                        RBP => 0x7fffffffddb0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555b34 <lab15_inspect+4>     sub    rsp, 0xa0                       RSP => 0x7fffffffdd10 (0x7fffffffddb0 - 0xa0)
   0x555555555b3b <lab15_inspect+11>    mov    qword ptr [rbp - 0x20], r12     [0x7fffffffdd90] <= 5
   0x555555555b3f <lab15_inspect+15>    mov    r12, rdi                        R12 => 0x7fffffffdf20 ◂— 0x1000232585652
   0x555555555b42 <lab15_inspect+18>    mov    qword ptr [rbp - 0x18], r13     [0x7fffffffdd98] <= 0x123456789
   0x555555555b46 <lab15_inspect+22>    mov    r13, rsi                        R13 => 0x78
   0x555555555b49 <lab15_inspect+25>    mov    qword ptr [rbp - 0x90], rdx     [0x7fffffffdd20] <= 0x7fffffffddfc ◂— 0x2345678900007fff
   0x555555555b50 <lab15_inspect+32>    lea    rdx, [rbp - 0x80]               RDX => 0x7fffffffdd30 ◂— 0x78 /* 'x' */
   0x555555555b54 <lab15_inspect+36>    mov    qword ptr [rbp - 0x98], rcx     [0x7fffffffdd18] <= 0x7fffffffde08 —▸ 0x7ffff7fc1c88 ◂— 0x3a5a8
   0x555555555b5b <lab15_inspect+43>    mov    rax, qword ptr fs:[0x28]        RAX, [0x7ffff7f7f768] => 0xdc1253a2474ac00
```

## Reconstruction and verification

1. Identify input buffer, total size, cursor/offset, and output object.
2. Mark every checked arithmetic and representation transformation.
3. Infer fields only from their uses in several functions.
4. Validate with the constructed two-entry archive and the mutation path.
5. Add truncated, exact-boundary, wrong-key, and overflow cases before declaring the format solved.

**Verified function:** `lab15_inspect`, RVA `0x1b30`.

# Twenty Practice Questions

1. How prove CRC polynomial?
2. Why zero checksum before hashing?
3. Why is stream XOR symmetric?
4. What distinguishes stored/original size?
5. How infer Entry stride?
6. Why test NUL in fixed name?
7. What is safe range formula?
8. Why guard align addition?
9. How detect endian?
10. Why cap varint at ten bytes?
11. What makes a parser complete?
12. Why create differential specimens?
13. How validate header CRC range?
14. Why propagate entry parser errors?
15. What does extracted baseline prove?
16. How test wrong key?
17. Why separate format inference from cryptographic strength?
18. What is an edge archive?
19. How does Ghidra help schema recovery?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Match conditional XOR constant and LSB-first shift recurrence against test vectors.
4. Create a specimen that changes only the relevant property.

## 2. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Writer and reader must compute over the same normalized header representation.
4. Create a specimen that changes only the relevant property.

## 3. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Same keystream XOR applied twice restores bytes.
4. Create a specimen that changes only the relevant property.

## 4. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Stored controls archive read/transform; original controls returned plaintext and CRC range.
4. Create a specimen that changes only the relevant property.

## 5. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Index multiplication and directory pointer advance equal sizeof Entry.
4. Create a specimen that changes only the relevant property.

## 6. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** strcmp requires termination inside the field.
4. Create a specimen that changes only the relevant property.

## 7. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** off<=total and len<=total-off.
4. Create a specimen that changes only the relevant property.

## 8. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** n+15 can wrap before masking.
4. Create a specimen that changes only the relevant property.

## 9. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Byte shifts/order and known magic/value tests.
4. Create a specimen that changes only the relevant property.

## 10. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** A 64-bit value needs at most ten 7-bit groups, with constraints on the last.
4. Create a specimen that changes only the relevant property.

## 11. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** All offsets, sizes, counts, names, integrity, and transformations are validated.
4. Create a specimen that changes only the relevant property.

## 12. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** One changed variable localizes responsible bytes and code.
4. Create a specimen that changes only the relevant property.

## 13. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Break at CRC call and inspect pointer/length; mutate inside and outside range.
4. Create a specimen that changes only the relevant property.

## 14. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** A search must not treat malformed directory as simple not-found.
4. Create a specimen that changes only the relevant property.

## 15. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** The recovered chain yields ALPHA-CONTENT for the known key and archive.
4. Create a specimen that changes only the relevant property.

## 16. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Predict CRC mismatch after transform while bounds/name still pass.
4. Create a specimen that changes only the relevant property.

## 17. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Compatibility does not establish security.
4. Create a specimen that changes only the relevant property.

## 18. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Zero entries, exact boundary payload, maximal name, corrupted count/offset, or truncated varint.
4. Create a specimen that changes only the relevant property.

## 19. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Repeated offsets/strides and callers support structures, but dynamic/file bytes validate them.
4. Create a specimen that changes only the relevant property.

## 20. Solution

1. Locate the bytes and consuming instructions.
2. State the required bounds/representation invariant.
3. **Answer:** Write an independent bounds-safe dumper/extractor matching valid cases and rejecting malformed corpus.
4. Create a specimen that changes only the relevant property.


Return to [[Chapter 06 - Deciphering File Formats]].
