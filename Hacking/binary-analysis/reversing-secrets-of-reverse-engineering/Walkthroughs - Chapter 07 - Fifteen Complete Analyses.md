# Chapter 7 — Fifteen Complete Vulnerability Walkthroughs

> [!scope]
> Every defect is in a deliberately vulnerable local program. Proof stops at a benign sanitizer/watchpoint result; no deployed target or weaponized payload is involved.

## Actual evidence summary

```text
ASan mode 1: stack-buffer-overflow
mode 2: heap-buffer-overflow
mode 3: wrapped small allocation
mode 4: negative-size-param
mode 5: one-byte stack-buffer-overflow
mode 6: controlled format interpreted
mode 7: heap-use-after-free
mode 9: decoded=../secret result=1
mode 10: stack-buffer-underflow
mode 11: truncated=4464
mode 12: wrapped-check=1
```

## Complete vulnerable source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;

NI int lab01_stack_copy(const char*s){char b[16];strcpy(b,s);return (unsigned char)b[0];}
NI int lab02_heap_copy(const char*s){struct U{char name[16];uint32_t role;};struct U*u=malloc(sizeof*u);if(!u)return-1;u->role=0x11223344;strcpy(u->name,s);int r=(int)u->role;free(u);return r;}
NI void *lab03_mul_alloc(uint32_t count,uint32_t size){uint32_t bytes=count*size;return malloc(bytes);}
NI int lab04_signed_length(char*dst,size_t cap,const char*src,int32_t n){if(n<(int32_t)cap){memcpy(dst,src,(size_t)n);return 0;}return-1;}
NI int lab05_off_by_one(char*dst,size_t cap,const char*src,size_t n){if(n<=cap){memcpy(dst,src,n);dst[n]=0;return 0;}return-1;}
NI int lab06_format_string(const char*user){return printf(user);}
NI int lab07_use_after_free(int use_after){struct Item{uint32_t tag,value;}*p=malloc(sizeof*p);if(!p)return-1;p->tag=7;p->value=99;free(p);return use_after?(int)p->value:0;}
NI int lab08_double_free(int twice){void*p=malloc(32);if(!p)return-1;free(p);if(twice)free(p);return 0;}
NI int lab09_decode_filter(const char*raw,char*out,size_t cap){if(strstr(raw,".."))return-1;size_t w=0;for(size_t i=0;raw[i];i++){unsigned v;if(raw[i]=='%'&&sscanf(raw+i+1,"%2x",&v)==1){if(w+1>=cap)return-2;out[w++]=(char)v;i+=2;}else{if(w+1>=cap)return-2;out[w++]=raw[i];}}out[w]=0;return strstr(out,"..")?1:0;}
NI int lab10_index_read(const int*a,size_t n,int index){if(index<(int)n)return a[index];return-1;}
NI uint16_t lab11_truncate_size(size_t n){return(uint16_t)n;}
NI int lab12_add_overflow(uint32_t off,uint32_t len,uint32_t total){return off+len<=total;}
NI int lab13_uninitialized(int choose){int x;if(choose)x=42;return x+1;}
NI int lab14_partial_validation(const uint8_t*p,size_t n){if(n<2)return-1;uint16_t len;memcpy(&len,p,2);if(len<n)return p[len];return-2;}
NI int lab15_fixed_copy(char*dst,size_t cap,const char*src){size_t n=strnlen(src,cap);if(n==cap)return-1;memcpy(dst,src,n+1);return(int)n;}

int main(void){char d[32]={0},decoded[64];int a[]={10,20,30};uint8_t rec[]={3,0,'A','B','C','D'};uint64_t total=0;
 total+=lab01_stack_copy("SAFE");total+=lab02_heap_copy("SAFE");void*p=lab03_mul_alloc(4,8);free(p);
 total+=lab04_signed_length(d,sizeof d,"ABCD",4);total+=lab05_off_by_one(d,sizeof d,"ABC",3);
 total+=lab06_format_string("safe-format\n");total+=lab07_use_after_free(0);total+=lab08_double_free(0);
 total+=lab09_decode_filter("safe%20path",decoded,sizeof decoded);total+=lab10_index_read(a,3,1);
 total+=lab11_truncate_size(70000);total+=lab12_add_overflow(4,8,16);total+=lab13_uninitialized(1);
 total+=lab14_partial_validation(rec,sizeof rec);total+=lab15_fixed_copy(d,sizeof d,"fixed");
 evidence_sink=total;printf("chapter07 evidence=%llu decoded=%s\n",(unsigned long long)total,decoded);return 0;}
```

## Complete trigger harness

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int lab01_stack_copy(const char*);int lab02_heap_copy(const char*);void*lab03_mul_alloc(uint32_t,uint32_t);
int lab04_signed_length(char*,size_t,const char*,int32_t);int lab05_off_by_one(char*,size_t,const char*,size_t);
int lab06_format_string(const char*);int lab07_use_after_free(int);int lab08_double_free(int);
int lab09_decode_filter(const char*,char*,size_t);int lab10_index_read(const int*,size_t,int);
uint16_t lab11_truncate_size(size_t);int lab12_add_overflow(uint32_t,uint32_t,uint32_t);
int lab13_uninitialized(int);int lab14_partial_validation(const uint8_t*,size_t);int lab15_fixed_copy(char*,size_t,const char*);
int main(int argc,char**argv){if(argc<2)return 2;int mode=atoi(argv[1]);char d[16]={0},out[64];int a[3]={10,20,30};uint8_t rec[2]={0xff,0xff};
 switch(mode){
 case 1:return lab01_stack_copy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
 case 2:return lab02_heap_copy("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
 case 3:{void*p=lab03_mul_alloc(0x40000001u,4);printf("wrapped allocation=%p\n",p);free(p);return 0;}
 case 4:return lab04_signed_length(d,sizeof d,"CCCC",-1);
 case 5:return lab05_off_by_one(d,sizeof d,"DDDDDDDDDDDDDDDD",16);
 case 6:return lab06_format_string("controlled-format-%p\n");
 case 7:return lab07_use_after_free(1);
 case 8:return lab08_double_free(1);
 case 9:{int r=lab09_decode_filter("%2e%2e/secret",out,sizeof out);printf("decoded=%s result=%d\n",out,r);return 0;}
 case 10:return lab10_index_read(a,3,-1);
 case 11:printf("truncated=%u\n",lab11_truncate_size(70000));return 0;
 case 12:printf("wrapped-check=%d\n",lab12_add_overflow(0xfffffff0u,0x40u,0x100u));return 0;
 case 13:return lab13_uninitialized(0);
 case 14:return lab14_partial_validation(rec,sizeof rec);
 case 15:return lab15_fixed_copy(d,sizeof d,"safe");
 default:return 3;}
}
```

# Walkthrough 01 — Stack buffer overflow

## Root-cause hypothesis

Unbounded strcpy into 16-byte local; ASan mode 1 records stack-buffer-overflow.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001011a9
ENTRY 001011a9
SIGNATURE undefined FUN_001011a9(void)
CALLERS 00102078, 00102158, 001014d4

char FUN_001011a9(char *param_1)

{
  char local_18 [16];

  strcpy(local_18,param_1);
  return local_18[0];
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011a9 <lab01_stack_copy>:
    11a9:	55                   	push   rbp
    11aa:	48 89 e5             	mov    rbp,rsp
    11ad:	48 83 ec 10          	sub    rsp,0x10
    11b1:	48 89 fe             	mov    rsi,rdi
    11b4:	48 8d 7d f0          	lea    rdi,[rbp-0x10]
    11b8:	e8 83 fe ff ff       	call   1040 <strcpy@plt>
    11bd:	0f b6 45 f0          	movzx  eax,BYTE PTR [rbp-0x10]
    11c1:	c9                   	leave
    11c2:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe2a8 —▸ 0x7fffffffe67d ◂— 0x5454495243414c41 ('ALACRITT')
 RBX  0
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555150 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe2a8 —▸ 0x7fffffffe67d ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
 RSI  0x7fffffffe298 —▸ 0x7fffffffe63a ◂— 0x74782f656d6f682f ('/home/xt')
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555554d9 (main+79) ◂— mov ebx, eax
 RIP  0x5555555551a9 (lab01_stack_copy) ◂— push rbp
   0x5555555551aa <lab01_stack_copy+1>     mov    rbp, rsp              RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555551ad <lab01_stack_copy+4>     sub    rsp, 0x10             RSP => 0x7fffffffe0a0 {b} (0x7fffffffe0b0 - 0x10)
   0x5555555551b1 <lab01_stack_copy+8>     mov    rsi, rdi              RSI => 0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
   0x5555555551b4 <lab01_stack_copy+11>    lea    rdi, [rbp - 0x10]     RDI => 0x7fffffffe0a0 ◂— 0x10
   0x5555555551b8 <lab01_stack_copy+15>    call   strcpy@plt                  <strcpy@plt>
   0x5555555551bd <lab01_stack_copy+20>    movzx  eax, byte ptr [rbp - 0x10]
   0x5555555551c1 <lab01_stack_copy+24>    leave
   0x5555555551c2 <lab01_stack_copy+25>    ret
   0x5555555551c4 <lab02_heap_copy+1>      mov    rbp, rsp
=> 0x5555555551a9 <lab01_stack_copy>:	push   rbp
```

## Triggered evidence

```text
=================================================================
==463416==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7bd24d6f0030 at pc 0x7fd250abc54e bp 0x7ffddfcc7900 sp 0x7ffddfcc70b8
WRITE of size 33 at 0x7bd24d6f0030 thread T0
    #0 0x7fd250abc54d  (/usr/lib/libasan.so.8+0xbc54d) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x5579b34a6838 in lab01_stack_copy reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:10
    #2 0x5579b34a6563 in main reversing-walkthrough-lab/ch07/ch07_trigger.c:14
    #3 0x7fd24fe27740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7fd24fe27878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x5579b34a6214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

Address 0x7bd24d6f0030 is located in stack of thread T0 at offset 48 in frame
    #0 0x5579b34a67d1 in lab01_stack_copy reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:10

  This frame has 1 object(s):
    [32, 48) 'b' (line 10) <== Memory access at offset 48 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:10 in lab01_stack_copy
Shadow bytes around the buggy address:
  0x7bd24d6efd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6efe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6efe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6eff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6eff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7bd24d6f0000: f1 f1 f1 f1 00 00[f3]f3 00 00 00 00 00 00 00 00
  0x7bd24d6f0080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6f0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6f0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6f0200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7bd24d6f0280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab01_stack_copy`, RVA `0x11a9`.

# Walkthrough 02 — Intra-object/heap overflow

## Root-cause hypothesis

Unbounded name copy crosses 16-byte field and allocation; ASan mode 2 records heap-buffer-overflow.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001011c3
ENTRY 001011c3
SIGNATURE undefined FUN_001011c3(void)
CALLERS 00102080, 00102178, 001014de

undefined4 FUN_001011c3(char *param_1)

{
  char *__dest;
  undefined4 uVar1;

  __dest = malloc(0x14);
  if (__dest == (char *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    builtin_strncpy(__dest + 0x10,"D3\"\x11",4);
    strcpy(__dest,param_1);
    uVar1 = *(undefined4 *)(__dest + 0x10);
    free(__dest);
  }
  return uVar1;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011c3 <lab02_heap_copy>:
    11c3:	55                   	push   rbp
    11c4:	48 89 e5             	mov    rbp,rsp
    11c7:	48 8d 64 24 f0       	lea    rsp,[rsp-0x10]
    11cc:	4c 89 65 f8          	mov    QWORD PTR [rbp-0x8],r12
    11d0:	49 89 fc             	mov    r12,rdi
    11d3:	bf 14 00 00 00       	mov    edi,0x14
    11d8:	e8 b3 fe ff ff       	call   1090 <malloc@plt>
    11dd:	48 85 c0             	test   rax,rax
    11e0:	74 32                	je     1214 <lab02_heap_copy+0x51>
    11e2:	48 89 5d f0          	mov    QWORD PTR [rbp-0x10],rbx
    11e6:	48 89 c3             	mov    rbx,rax
    11e9:	c7 40 10 44 33 22 11 	mov    DWORD PTR [rax+0x10],0x11223344
    11f0:	4c 89 e6             	mov    rsi,r12
    11f3:	48 89 c7             	mov    rdi,rax
    11f6:	e8 45 fe ff ff       	call   1040 <strcpy@plt>
    11fb:	44 8b 63 10          	mov    r12d,DWORD PTR [rbx+0x10]
    11ff:	48 89 df             	mov    rdi,rbx
    1202:	e8 29 fe ff ff       	call   1030 <free@plt>
    1207:	48 8b 5d f0          	mov    rbx,QWORD PTR [rbp-0x10]
    120b:	44 89 e0             	mov    eax,r12d
    120e:	4c 8b 65 f8          	mov    r12,QWORD PTR [rbp-0x8]
    1212:	c9                   	leave
    1213:	c3                   	ret
    1214:	41 bc ff ff ff ff    	mov    r12d,0xffffffff
    121a:	eb ef                	jmp    120b <lab02_heap_copy+0x48>

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x53
 RBX  0x53
 RCX  0x454641
 RDX  4
 RDI  0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
 RSI  0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555554e3 (main+89) ◂— movsxd rbx, ebx
 RIP  0x5555555551c3 (lab02_heap_copy) ◂— push rbp
   0x5555555551b4 <lab01_stack_copy+11>    lea    rdi, [rbp - 0x10]     RDI => 0x7fffffffe0a0 ◂— 0x10
   0x5555555551b8 <lab01_stack_copy+15>    call   strcpy@plt                  <strcpy@plt>
   0x5555555551bd <lab01_stack_copy+20>    movzx  eax, byte ptr [rbp - 0x10]
   0x5555555551c1 <lab01_stack_copy+24>    leave
   0x5555555551c2 <lab01_stack_copy+25>    ret
   0x5555555551c4 <lab02_heap_copy+1>      mov    rbp, rsp                       RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555551c7 <lab02_heap_copy+4>      lea    rsp, [rsp - 0x10]              RSP => 0x7fffffffe0a0 ◂— 0x45464153 /* 'SAFE' */
   0x5555555551cc <lab02_heap_copy+9>      mov    qword ptr [rbp - 8], r12       [0x7fffffffe0a8] <= 0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
   0x5555555551d0 <lab02_heap_copy+13>     mov    r12, rdi                       R12 => 0x55555555600b ◂— 0x4342410045464153 /* 'SAFE' */
   0x5555555551d3 <lab02_heap_copy+16>     mov    edi, 0x14                      EDI => 0x14
```

## Triggered evidence

```text
=================================================================
==463418==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b66531e0054 at pc 0x7f36550bc54e bp 0x7ffe45ad64b0 sp 0x7ffe45ad5c68
WRITE of size 33 at 0x7b66531e0054 thread T0
    #0 0x7f36550bc54d  (/usr/lib/libasan.so.8+0xbc54d) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x561d5ae9792a in lab02_heap_copy reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:11
    #2 0x561d5ae97571 in main reversing-walkthrough-lab/ch07/ch07_trigger.c:15
    #3 0x7f3654427740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7f3654427878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x561d5ae97214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

0x7b66531e0054 is located 0 bytes after 20-byte region [0x7b66531e0040,0x7b66531e0054)
allocated by thread T0 here:
    #0 0x7f365512c161 in malloc (/usr/lib/libasan.so.8+0x12c161) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x561d5ae978d8 in lab02_heap_copy reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:11
    #2 0x561d5ae97571 in main reversing-walkthrough-lab/ch07/ch07_trigger.c:15
    #3 0x7f3654427740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7f3654427878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x561d5ae97214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

SUMMARY: AddressSanitizer: heap-buffer-overflow reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:11 in lab02_heap_copy
Shadow bytes around the buggy address:
  0x7b66531dfd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b66531dfe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b66531dfe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b66531dff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b66531dff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7b66531e0000: fa fa 00 00 00 fa fa fa 00 00[04]fa fa fa fa fa
  0x7b66531e0080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b66531e0100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b66531e0180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b66531e0200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b66531e0280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab02_heap_copy`, RVA `0x11c3`.

# Walkthrough 03 — Integer-overflow allocation

## Root-cause hypothesis

32-bit count*size wraps; mode 3 shows a small successful allocation for huge logical count.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010121c
ENTRY 0010121c
SIGNATURE undefined FUN_0010121c(void)
CALLERS 00102088, 001021a0, 001014f5

void FUN_0010121c(int param_1,int param_2)

{
  malloc((ulong)(uint)(param_1 * param_2));
  return;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000121c <lab03_mul_alloc>:
    121c:	55                   	push   rbp
    121d:	48 89 e5             	mov    rbp,rsp
    1220:	0f af fe             	imul   edi,esi
    1223:	e8 68 fe ff ff       	call   1090 <malloc@plt>
    1228:	5d                   	pop    rbp
    1229:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x11223344
 RBX  0x11223397
 RCX  0x555555559
 RDX  0xf
 RDI  4
 RSI  8
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x20
 RSP  0x7fffffffe0b8 —▸ 0x5555555554fa (main+112) ◂— mov rdi, rax
 RIP  0x55555555521c (lab03_mul_alloc) ◂— push rbp
   0x55555555521d <lab03_mul_alloc+1>        mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555220 <lab03_mul_alloc+4>        imul   edi, esi
   0x555555555223 <lab03_mul_alloc+7>        call   malloc@plt                  <malloc@plt>
   0x555555555228 <lab03_mul_alloc+12>       pop    rbp
   0x555555555229 <lab03_mul_alloc+13>       ret
   0x55555555522c <lab04_signed_length+2>    jge    lab04_signed_length+26      <lab04_signed_length+26>
   0x55555555522e <lab04_signed_length+4>    push   rbp
   0x55555555522f <lab04_signed_length+5>    mov    rbp, rsp
   0x555555555232 <lab04_signed_length+8>    mov    rsi, rdx
=> 0x55555555521c <lab03_mul_alloc>:	push   rbp
```

## Triggered evidence

```text
wrapped allocation=0x7b36fa9e0010
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab03_mul_alloc`, RVA `0x121c`.

# Walkthrough 04 — Signed-to-size conversion

## Root-cause hypothesis

Negative n passes signed upper check then becomes huge size_t; ASan mode 4 reports negative-size-param.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010122a
ENTRY 0010122a
SIGNATURE undefined FUN_0010122a(void)
CALLERS 00102090, 001021c0, 0010151a

undefined8 FUN_0010122a(void *param_1,int param_2,void *param_3,int param_4)

{
  if (param_4 < param_2) {
    memcpy(param_1,param_3,(long)param_4);
    return 0;
  }
  return 0xffffffff;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000122a <lab04_signed_length>:
    122a:	39 f1                	cmp    ecx,esi
    122c:	7d 16                	jge    1244 <lab04_signed_length+0x1a>
    122e:	55                   	push   rbp
    122f:	48 89 e5             	mov    rbp,rsp
    1232:	48 89 d6             	mov    rsi,rdx
    1235:	48 63 d1             	movsxd rdx,ecx
    1238:	e8 43 fe ff ff       	call   1080 <memcpy@plt>
    123d:	b8 00 00 00 00       	mov    eax,0x0
    1242:	5d                   	pop    rbp
    1243:	c3                   	ret
    1244:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1249:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  1
 RBX  0x11223397
 RCX  4
 RDX  0x555555556010 ◂— 0x4342410044434241 /* 'ABCD' */
 RDI  0x7fffffffe120 ◂— 0xb700000006
 RSI  0x20
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x30
 RSP  0x7fffffffe0b8 —▸ 0x55555555551f (main+149) ◂— cdqe
 RIP  0x55555555522a (lab04_signed_length) ◂— cmp ecx, esi
   0x55555555521d <lab03_mul_alloc+1>         mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555220 <lab03_mul_alloc+4>         imul   edi, esi
   0x555555555223 <lab03_mul_alloc+7>         call   malloc@plt                  <malloc@plt>
   0x555555555228 <lab03_mul_alloc+12>        pop    rbp
   0x555555555229 <lab03_mul_alloc+13>        ret
   0x55555555522c <lab04_signed_length+2>   ✘ jge    lab04_signed_length+26      <lab04_signed_length+26>
   0x55555555522e <lab04_signed_length+4>     push   rbp
   0x55555555522f <lab04_signed_length+5>     mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555232 <lab04_signed_length+8>     mov    rsi, rdx     RSI => 0x555555556010 ◂— 0x4342410044434241 /* 'ABCD' */
   0x555555555235 <lab04_signed_length+11>    movsxd rdx, ecx     RDX => 4
```

## Triggered evidence

```text
=================================================================
==463422==ERROR: AddressSanitizer: negative-size-param: (size=-1)
    #0 0x7f0089d29818 in memcpy (/usr/lib/libasan.so.8+0x129818) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x55c5cfcdf9ed in lab04_signed_length reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:13
    #2 0x55c5cfcdf60f in main reversing-walkthrough-lab/ch07/ch07_trigger.c:17
    #3 0x7f0089027740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7f0089027878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x55c5cfcdf214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

0x55c5cfce11a0 is located 0 bytes inside of global variable '*.LC5' defined in 'reversing-walkthrough-lab/ch07/ch07_trigger.c' (0x55c5cfce11a0) of size 5
  '*.LC5' is ascii string 'CCCC'
SUMMARY: AddressSanitizer: negative-size-param reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:13 in lab04_signed_length
==463422==ABORTING
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab04_signed_length`, RVA `0x122a`.

# Walkthrough 05 — Terminator off-by-one

## Root-cause hypothesis

n==cap permits data copy and writes dst[cap]; ASan mode 5 reports one-byte stack overflow.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010124a
ENTRY 0010124a
SIGNATURE undefined FUN_0010124a(void)
CALLERS 00102098, 001021e0, 00101538

undefined8 FUN_0010124a(void *param_1,ulong param_2,void *param_3,ulong param_4)

{
  if (param_4 <= param_2) {
    memcpy(param_1,param_3,param_4);
    *(undefined1 *)((long)param_1 + param_4) = 0;
    return 0;
  }
  return 0xffffffff;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000124a <lab05_off_by_one>:
    124a:	48 39 ce             	cmp    rsi,rcx
    124d:	72 27                	jb     1276 <lab05_off_by_one+0x2c>
    124f:	55                   	push   rbp
    1250:	48 89 e5             	mov    rbp,rsp
    1253:	41 54                	push   r12
    1255:	53                   	push   rbx
    1256:	49 89 fc             	mov    r12,rdi
    1259:	48 89 d6             	mov    rsi,rdx
    125c:	48 89 cb             	mov    rbx,rcx
    125f:	48 89 ca             	mov    rdx,rcx
    1262:	e8 19 fe ff ff       	call   1080 <memcpy@plt>
    1267:	41 c6 04 1c 00       	mov    BYTE PTR [r12+rbx*1],0x0
    126c:	b8 00 00 00 00       	mov    eax,0x0
    1271:	5b                   	pop    rbx
    1272:	41 5c                	pop    r12
    1274:	5d                   	pop    rbp
    1275:	c3                   	ret
    1276:	b8 ff ff ff ff       	mov    eax,0xffffffff
    127b:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0
 RBX  0x11223397
 RCX  3
 RDX  0x555555556015 ◂— 0x6566617300434241 /* 'ABC' */
 RDI  0x7fffffffe120 ◂— 0xb744434241
 RSI  0x20
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x30
 RSP  0x7fffffffe0b8 —▸ 0x55555555553d (main+179) ◂— movsxd r12, eax
 RIP  0x55555555524a (lab05_off_by_one) ◂— cmp rsi, rcx
   0x55555555524d <lab05_off_by_one+3>   ✘ jb     lab05_off_by_one+44         <lab05_off_by_one+44>
   0x55555555524f <lab05_off_by_one+5>     push   rbp
   0x555555555250 <lab05_off_by_one+6>     mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555253 <lab05_off_by_one+9>     push   r12
   0x555555555255 <lab05_off_by_one+11>    push   rbx
   0x555555555256 <lab05_off_by_one+12>    mov    r12, rdi     R12 => 0x7fffffffe120 ◂— 0xb744434241
   0x555555555259 <lab05_off_by_one+15>    mov    rsi, rdx     RSI => 0x555555556015 ◂— 0x6566617300434241 /* 'ABC' */
   0x55555555525c <lab05_off_by_one+18>    mov    rbx, rcx     RBX => 3
   0x55555555525f <lab05_off_by_one+21>    mov    rdx, rcx     RDX => 3
   0x555555555262 <lab05_off_by_one+24>    call   memcpy@plt                  <memcpy@plt>
```

## Triggered evidence

```text
=================================================================
==463424==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7b02aeef0070 at pc 0x55a93f3b0ae6 bp 0x7fffc5b4a750 sp 0x7fffc5b4a740
WRITE of size 1 at 0x7b02aeef0070 thread T0
    #0 0x55a93f3b0ae5 in lab05_off_by_one reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:14
    #1 0x55a93f3b062e in main reversing-walkthrough-lab/ch07/ch07_trigger.c:18
    #2 0x7f02b1427740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #3 0x7f02b1427878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x55a93f3b0214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

Address 0x7b02aeef0070 is located in stack of thread T0 at offset 112 in frame
    #0 0x55a93f3b02f8 in main reversing-walkthrough-lab/ch07/ch07_trigger.c:12

  This frame has 4 object(s):
    [48, 60) 'a' (line 12)
    [80, 82) 'rec' (line 12)
    [96, 112) 'd' (line 12) <== Memory access at offset 112 overflows this variable
    [128, 192) 'out' (line 12)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:14 in lab05_off_by_one
Shadow bytes around the buggy address:
  0x7b02aeeefd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeeefe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeeefe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeeeff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeeeff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7b02aeef0000: f1 f1 f1 f1 f1 f1 00 04 f2 f2 02 f2 00 00[f2]f2
  0x7b02aeef0080: 00 00 00 00 00 00 00 00 f3 f3 f3 f3 f3 f3 f3 f3
  0x7b02aeef0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeef0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeef0200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b02aeef0280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab05_off_by_one`, RVA `0x124a`.

# Walkthrough 06 — User-controlled format

## Root-cause hypothesis

Input pointer is passed as printf format; mode 6 prints a process pointer from controlled %p.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010127c
ENTRY 0010127c
SIGNATURE undefined FUN_0010127c(void)
CALLERS 001020a0, 00102208, 0010154a

void FUN_0010127c(char *param_1)

{
  printf(param_1);
  return;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000127c <lab06_format_string>:
    127c:	55                   	push   rbp
    127d:	48 89 e5             	mov    rbp,rsp
    1280:	b8 00 00 00 00       	mov    eax,0x0
    1285:	e8 d6 fd ff ff       	call   1060 <printf@plt>
    128a:	5d                   	pop    rbp
    128b:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0
 RBX  0x11223397
 RCX  0x41
 RDX  3
 RDI  0x555555556019 ◂— 'safe-format\n'
 RSI  0x4342
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x30
 RSP  0x7fffffffe0b8 —▸ 0x55555555554f (main+197) ◂— movsxd rbx, eax
 RIP  0x55555555527c (lab06_format_string) ◂— push rbp
   0x55555555527d <lab06_format_string+1>      mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555280 <lab06_format_string+4>      mov    eax, 0       EAX => 0
   0x555555555285 <lab06_format_string+9>      call   printf@plt                  <printf@plt>
   0x55555555528a <lab06_format_string+14>     pop    rbp
   0x55555555528b <lab06_format_string+15>     ret
   0x55555555528d <lab07_use_after_free+1>     mov    rbp, rsp
   0x555555555290 <lab07_use_after_free+4>     lea    rsp, [rsp - 0x10]
   0x555555555295 <lab07_use_after_free+9>     mov    qword ptr [rbp - 8], r12
   0x555555555299 <lab07_use_after_free+13>    mov    r12d, edi
=> 0x55555555527c <lab06_format_string>:	push   rbp
```

## Triggered evidence

```text
controlled-format-0x1000205b16dd
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab06_format_string`, RVA `0x127c`.

# Walkthrough 07 — Use after free

## Root-cause hypothesis

Conditional read follows free; ASan mode 7 records heap-use-after-free.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010128c
ENTRY 0010128c
SIGNATURE undefined FUN_0010128c(void)
CALLERS 001020a8, 00102228, 0010155a

undefined4 FUN_0010128c(int param_1)

{
  undefined4 uVar1;
  void *__ptr;

  __ptr = malloc(8);
  if (__ptr == (void *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    free(__ptr);
    if (param_1 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(undefined4 *)((long)__ptr + 4);
    }
  }
  return uVar1;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000128c <lab07_use_after_free>:
    128c:	55                   	push   rbp
    128d:	48 89 e5             	mov    rbp,rsp
    1290:	48 8d 64 24 f0       	lea    rsp,[rsp-0x10]
    1295:	4c 89 65 f8          	mov    QWORD PTR [rbp-0x8],r12
    1299:	41 89 fc             	mov    r12d,edi
    129c:	bf 08 00 00 00       	mov    edi,0x8
    12a1:	e8 ea fd ff ff       	call   1090 <malloc@plt>
    12a6:	48 85 c0             	test   rax,rax
    12a9:	74 24                	je     12cf <lab07_use_after_free+0x43>
    12ab:	48 89 5d f0          	mov    QWORD PTR [rbp-0x10],rbx
    12af:	48 89 c3             	mov    rbx,rax
    12b2:	48 89 c7             	mov    rdi,rax
    12b5:	e8 76 fd ff ff       	call   1030 <free@plt>
    12ba:	44 89 e0             	mov    eax,r12d
    12bd:	45 85 e4             	test   r12d,r12d
    12c0:	74 14                	je     12d6 <lab07_use_after_free+0x4a>
    12c2:	8b 43 04             	mov    eax,DWORD PTR [rbx+0x4]
    12c5:	48 8b 5d f0          	mov    rbx,QWORD PTR [rbp-0x10]
    12c9:	4c 8b 65 f8          	mov    r12,QWORD PTR [rbp-0x8]
    12cd:	c9                   	leave
    12ce:	c3                   	ret
    12cf:	b8 ff ff ff ff       	mov    eax,0xffffffff
    12d4:	eb f3                	jmp    12c9 <lab07_use_after_free+0x3d>
    12d6:	48 8b 5d f0          	mov    rbx,QWORD PTR [rbp-0x10]
    12da:	eb ed                	jmp    12c9 <lab07_use_after_free+0x3d>

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0xc
 RBX  0x112233a3
 RCX  0
 RDX  0
 RDI  0
 RSI  0x7fffffffdf00 ◂— 'safe-format\n'
 R8   0
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x55555555555f (main+213) ◂— movsxd r12, eax
 RIP  0x55555555528c (lab07_use_after_free) ◂— push rbp
   0x55555555527d <lab06_format_string+1>      mov    rbp, rsp     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555280 <lab06_format_string+4>      mov    eax, 0       EAX => 0
   0x555555555285 <lab06_format_string+9>      call   printf@plt                  <printf@plt>
   0x55555555528a <lab06_format_string+14>     pop    rbp
   0x55555555528b <lab06_format_string+15>     ret
   0x55555555528d <lab07_use_after_free+1>     mov    rbp, rsp                     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555290 <lab07_use_after_free+4>     lea    rsp, [rsp - 0x10]            RSP => 0x7fffffffe0a0 —▸ 0x7fffffffe0b0 —▸ 0x7fffffffe160 ◂— ...
   0x555555555295 <lab07_use_after_free+9>     mov    qword ptr [rbp - 8], r12     [0x7fffffffe0a8] <= 0x11223397
   0x555555555299 <lab07_use_after_free+13>    mov    r12d, edi                    R12D => 0
   0x55555555529c <lab07_use_after_free+16>    mov    edi, 8                       EDI => 8
```

## Triggered evidence

```text
=================================================================
==463428==ERROR: AddressSanitizer: heap-use-after-free on address 0x7b68c8fe0014 at pc 0x55d6591a1c1e bp 0x7fff264a6560 sp 0x7fff264a6550
READ of size 4 at 0x7b68c8fe0014 thread T0
    #0 0x55d6591a1c1d in lab07_use_after_free reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:16
    #1 0x55d6591a164e in main reversing-walkthrough-lab/ch07/ch07_trigger.c:20
    #2 0x7f48ca227740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #3 0x7f48ca227878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x55d6591a1214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

0x7b68c8fe0014 is located 4 bytes inside of 8-byte region [0x7b68c8fe0010,0x7b68c8fe0018)
freed by thread T0 here:
    #0 0x7f48caf2af31  (/usr/lib/libasan.so.8+0x12af31) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x55d6591a1b7c in lab07_use_after_free reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:16
    #2 0x55d6591a164e in main reversing-walkthrough-lab/ch07/ch07_trigger.c:20
    #3 0x7f48ca227740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7f48ca227878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x55d6591a1214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

previously allocated by thread T0 here:
    #0 0x7f48caf2c161 in malloc (/usr/lib/libasan.so.8+0x12c161) (BuildId: ee5fbab73143ab257a66a33afe0f038a4af7a74e)
    #1 0x55d6591a1b37 in lab07_use_after_free reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:16
    #2 0x55d6591a164e in main reversing-walkthrough-lab/ch07/ch07_trigger.c:20
    #3 0x7f48ca227740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x7f48ca227878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #5 0x55d6591a1214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

SUMMARY: AddressSanitizer: heap-use-after-free reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:16 in lab07_use_after_free
Shadow bytes around the buggy address:
  0x7b68c8fdfd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b68c8fdfe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b68c8fdfe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b68c8fdff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b68c8fdff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7b68c8fe0000: fa fa[fd]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b68c8fe0080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab07_use_after_free`, RVA `0x128c`.

# Walkthrough 08 — Double-free source and optimization

## Root-cause hypothesis

Source condition permits second free, while optimized build can exploit UB and erase/rewrite behavior; compare O0/ASan.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001012dc
ENTRY 001012dc
SIGNATURE undefined FUN_001012dc(void)
CALLERS 001020b0, 00102258, 0010156a

undefined8 FUN_001012dc(void)

{
  return 0;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000012dc <lab08_double_free>:
    12dc:	b8 00 00 00 00       	mov    eax,0x0
    12e1:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0
 RBX  0x112233a3
 RCX  0x555555559
 RDX  0xf
 RDI  0
 RSI  0xc44649b318271177
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x20
 RSP  0x7fffffffe0b8 —▸ 0x55555555556f (main+229) ◂— movsxd rbx, eax
 RIP  0x5555555552dc (lab08_double_free) ◂— mov eax, 0
   0x5555555552e1 <lab08_double_free+5>    ret                                <main+229>
   0x55555555556f <main+229>               movsxd rbx, eax               RBX => 0
   0x555555555572 <main+232>               add    rbx, r12               RBX => 0x112233a3 (0x0 + 0x112233a3)
   0x555555555575 <main+235>               lea    r12, [rbp - 0x80]      R12 => 0x7fffffffe0e0 ◂— 0x100
   0x555555555579 <main+239>               mov    edx, 0x40              EDX => 0x40
   0x55555555557e <main+244>               mov    rsi, r12               RSI => 0x7fffffffe0e0 ◂— 0x100
   0x555555555581 <main+247>               lea    rdi, [rip + 0xa9e]     RDI => 0x555555556026 ◂— 'safe%20path'
   0x555555555588 <main+254>               call   lab09_decode_filter         <lab09_decode_filter>
   0x55555555558d <main+259>               movsxd r14, eax
   0x555555555590 <main+262>               add    r14, rbx
```

## Triggered evidence

```text
The optimized build’s undefined behavior did not produce a sanitizer diagnostic in this mode; compare source, assembly, and an O0 build rather than claiming a runtime event that was not observed.
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab08_double_free`, RVA `0x12dc`.

# Walkthrough 09 — Canonicalization/filter bypass

## Root-cause hypothesis

Raw input lacks literal .., decoder creates ../secret; mode 9 records result=1.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001012e2
ENTRY 001012e2
SIGNATURE undefined FUN_001012e2(void)
CALLERS 001020b8, 0010226c, 00101588

ulong FUN_001012e2(char *param_1,char *param_2,ulong param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  char local_3c [12];

  pcVar3 = strstr(param_1,"..");
  if (pcVar3 == (char *)0x0) {
    cVar1 = *param_1;
    lVar6 = 0;
    uVar4 = 1;
    pcVar3 = param_1;
    if (cVar1 == '\0') {
      uVar5 = 0;
    }
    else {
      do {
        uVar5 = uVar4;
        if ((cVar1 == '%') &&
           (iVar2 = __isoc23_sscanf(param_1 + lVar6 + 1,&DAT_00102007,local_3c), iVar2 == 1)) {
          if (param_3 <= uVar5) {
            return 0xfffffffe;
          }
          lVar6 = lVar6 + 2;
          cVar1 = local_3c[0];
        }
        else {
          if (param_3 <= uVar5) {
            return 0xfffffffe;
          }
          cVar1 = *pcVar3;
        }
        param_2[uVar5 - 1] = cVar1;
        lVar6 = lVar6 + 1;
        pcVar3 = param_1 + lVar6;
        cVar1 = *pcVar3;
        uVar4 = uVar5 + 1;
      } while (cVar1 != '\0');
    }
    param_2[uVar5] = '\0';
    pcVar3 = strstr(param_2,"..");
    uVar4 = (ulong)(pcVar3 != (char *)0x0);
  }
  else {
    uVar4 = 0xffffffff;
  }
  return uVar4;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000012e2 <lab09_decode_filter>:
    12e2:	55                   	push   rbp
    12e3:	48 89 e5             	mov    rbp,rsp
    12e6:	48 8d 64 24 b0       	lea    rsp,[rsp-0x50]
    12eb:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    12ef:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    12f3:	49 89 fe             	mov    r14,rdi
    12f6:	49 89 f7             	mov    r15,rsi
    12f9:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    12fd:	48 8d 35 00 0d 00 00 	lea    rsi,[rip+0xd00]        # 2004 <_IO_stdin_used+0x4>
    1304:	e8 97 fd ff ff       	call   10a0 <strstr@plt>
    1309:	48 85 c0             	test   rax,rax
    130c:	0f 85 ce 00 00 00    	jne    13e0 <lab09_decode_filter+0xfe>
    1312:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1316:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    131a:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    131e:	41 0f b6 06          	movzx  eax,BYTE PTR [r14]
    1322:	4d 89 f5             	mov    r13,r14
    1325:	bb 01 00 00 00       	mov    ebx,0x1
    132a:	41 bc 00 00 00 00    	mov    r12d,0x0
    1330:	84 c0                	test   al,al
    1332:	75 63                	jne    1397 <lab09_decode_filter+0xb5>
    1334:	bb 00 00 00 00       	mov    ebx,0x0
    1339:	41 c6 04 1f 00       	mov    BYTE PTR [r15+rbx*1],0x0
    133e:	48 8d 35 bf 0c 00 00 	lea    rsi,[rip+0xcbf]        # 2004 <_IO_stdin_used+0x4>
    1345:	4c 89 ff             	mov    rdi,r15
    1348:	e8 53 fd ff ff       	call   10a0 <strstr@plt>
    134d:	48 85 c0             	test   rax,rax
    1350:	0f 95 c0             	setne  al
    1353:	0f b6 c0             	movzx  eax,al
    1356:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    135a:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    135e:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    1362:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    1366:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    136a:	c9                   	leave
    136b:	c3                   	ret
    136c:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    1370:	48 39 c3             	cmp    rbx,rax
    1373:	73 58                	jae    13cd <lab09_decode_filter+0xeb>
    1375:	41 0f b6 45 00       	movzx  eax,BYTE PTR [r13+0x0]
    137a:	41 88 44 1f ff       	mov    BYTE PTR [r15+rbx*1-0x1],al
    137f:	49 83 c4 01          	add    r12,0x1
    1383:	4f 8d 2c 26          	lea    r13,[r14+r12*1]
    1387:	41 0f b6 45 00       	movzx  eax,BYTE PTR [r13+0x0]
    138c:	48 8d 53 01          	lea    rdx,[rbx+0x1]
    1390:	84 c0                	test   al,al
    1392:	74 a5                	je     1339 <lab09_decode_filter+0x57>
    1394:	48 89 d3             	mov    rbx,rdx
    1397:	3c 25                	cmp    al,0x25
    1399:	75 d1                	jne    136c <lab09_decode_filter+0x8a>
    139b:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
    139f:	4b 8d 7c 26 01       	lea    rdi,[r14+r12*1+0x1]
    13a4:	48 8d 35 5c 0c 00 00 	lea    rsi,[rip+0xc5c]        # 2007 <_IO_stdin_used+0x7>
    13ab:	b8 00 00 00 00       	mov    eax,0x0
    13b0:	e8 9b fc ff ff       	call   1050 <__isoc23_sscanf@plt>
    13b5:	83 f8 01             	cmp    eax,0x1
    13b8:	75 b2                	jne    136c <lab09_decode_filter+0x8a>
    13ba:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    13be:	48 39 c3             	cmp    rbx,rax
    13c1:	73 0a                	jae    13cd <lab09_decode_filter+0xeb>
    13c3:	0f b6 45 cc          	movzx  eax,BYTE PTR [rbp-0x34]
    13c7:	49 83 c4 02          	add    r12,0x2
    13cb:	eb ad                	jmp    137a <lab09_decode_filter+0x98>
    13cd:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    13d2:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    13d6:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    13da:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    13de:	eb 82                	jmp    1362 <lab09_decode_filter+0x80>
    13e0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    13e5:	e9 78 ff ff ff       	jmp    1362 <lab09_decode_filter+0x80>

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0
 RBX  0x112233a3
 RCX  0x555555559
 RDX  0x40
 RDI  0x555555556026 ◂— 'safe%20path'
 RSI  0x7fffffffe0e0 ◂— 0x100
 R8   0x555555559030 ◂— 0x555555559030
 R9   0x20
 RSP  0x7fffffffe0b8 —▸ 0x55555555558d (main+259) ◂— movsxd r14, eax
 RIP  0x5555555552e2 (lab09_decode_filter) ◂— push rbp
   0x5555555552e3 <lab09_decode_filter+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555552e6 <lab09_decode_filter+4>     lea    rsp, [rsp - 0x50]               RSP => 0x7fffffffe060 —▸ 0x7fffffffe070 —▸ 0x7fffffffe0a0 ◂— ...
   0x5555555552eb <lab09_decode_filter+9>     mov    qword ptr [rbp - 0x10], r14     [{b}] <= 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— ...
   0x5555555552ef <lab09_decode_filter+13>    mov    qword ptr [rbp - 8], r15        [0x7fffffffe0a8] <= 0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555150 (__do_global_dtors_aux) ◂— endbr64
   0x5555555552f3 <lab09_decode_filter+17>    mov    r14, rdi                        R14 => 0x555555556026 ◂— 'safe%20path'
   0x5555555552f6 <lab09_decode_filter+20>    mov    r15, rsi                        R15 => 0x7fffffffe0e0 ◂— 0x100
   0x5555555552f9 <lab09_decode_filter+23>    mov    qword ptr [rbp - 0x48], rdx     [0x7fffffffe068] <= 0x40
   0x5555555552fd <lab09_decode_filter+27>    lea    rsi, [rip + 0xd00]              RSI => 0x555555556004 ◂— 0x5300783225002e2e /* '..' */
   0x555555555304 <lab09_decode_filter+34>    call   strstr@plt                  <strstr@plt>
   0x555555555309 <lab09_decode_filter+39>    test   rax, rax
```

## Triggered evidence

```text
decoded=../secret result=1
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab09_decode_filter`, RVA `0x12e2`.

# Walkthrough 10 — Negative-index underflow

## Root-cause hypothesis

Only index<n signed check exists; -1 passes and reads before array; ASan mode 10 records stack-buffer-underflow.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001013ea
ENTRY 001013ea
SIGNATURE undefined FUN_001013ea(void)
CALLERS 001020c0, 001022ac, 001015a4

undefined4 FUN_001013ea(long param_1,int param_2,int param_3)

{
  if (param_3 < param_2) {
    return *(undefined4 *)(param_1 + (long)param_3 * 4);
  }
  return 0xffffffff;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013ea <lab10_index_read>:
    13ea:	39 f2                	cmp    edx,esi
    13ec:	7d 07                	jge    13f5 <lab10_index_read+0xb>
    13ee:	48 63 d2             	movsxd rdx,edx
    13f1:	8b 04 97             	mov    eax,DWORD PTR [rdi+rdx*4]
    13f4:	c3                   	ret
    13f5:	b8 ff ff ff ff       	mov    eax,0xffffffff
    13fa:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0
 RBX  0x112233a3
 RCX  0
 RDX  1
 RDI  0x7fffffffe0d4 ◂— 0x140000000a /* '\n' */
 RSI  3
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x5555555555a9 (main+287) ◂— movsxd rbx, eax
 RIP  0x5555555553ea (lab10_index_read) ◂— cmp edx, esi
   0x5555555553ec <lab10_index_read+2>   ✘ jge    lab10_index_read+11         <lab10_index_read+11>
   0x5555555553ee <lab10_index_read+4>     movsxd rdx, edx                         RDX => 1
   0x5555555553f1 <lab10_index_read+7>     mov    eax, dword ptr [rdi + rdx*4]     EAX, [0x7fffffffe0d8] => 0x14
   0x5555555553f4 <lab10_index_read+10>    ret                                <main+287>
   0x5555555555a9 <main+287>               movsxd rbx, eax         RBX => 0x14
   0x5555555555ac <main+290>               add    rbx, r14         RBX => 0x112233b7 (0x14 + 0x112233a3)
   0x5555555555af <main+293>               mov    edi, 0x11170     EDI => 0x11170
   0x5555555555b4 <main+298>               call   lab11_truncate_size         <lab11_truncate_size>
   0x5555555555b9 <main+303>               movzx  r14d, ax
   0x5555555555bd <main+307>               add    r14, rbx
```

## Triggered evidence

```text
=================================================================
==463434==ERROR: AddressSanitizer: stack-buffer-underflow on address 0x7b5c7b0f002c at pc 0x55cb6fba3265 bp 0x7ffe49a26c60 sp 0x7ffe49a26c50
READ of size 4 at 0x7b5c7b0f002c thread T0
    #0 0x55cb6fba3264 in lab10_index_read reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:19
    #1 0x55cb6fba26ab in main reversing-walkthrough-lab/ch07/ch07_trigger.c:23
    #2 0x7f5c7d627740  (/usr/lib/libc.so.6+0x27740) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #3 0x7f5c7d627878 in __libc_start_main (/usr/lib/libc.so.6+0x27878) (BuildId: 020d6f7c33b2413f4fe10814c4729dce1387f049)
    #4 0x55cb6fba2214 in _start (/home/xtrmn8/books/reversing-walkthrough-lab/build/ch07/ch07_asan+0x3214) (BuildId: f51c54f701ccc4105febafb2caaf1369eefd0bff)

Address 0x7b5c7b0f002c is located in stack of thread T0 at offset 44 in frame
    #0 0x55cb6fba22f8 in main reversing-walkthrough-lab/ch07/ch07_trigger.c:12

  This frame has 4 object(s):
    [48, 60) 'a' (line 12) <== Memory access at offset 44 underflows this variable
    [80, 82) 'rec' (line 12)
    [96, 112) 'd' (line 12)
    [128, 192) 'out' (line 12)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-underflow reversing-walkthrough-lab/ch07/ch07_vulnerabilities.c:19 in lab10_index_read
Shadow bytes around the buggy address:
  0x7b5c7b0efd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0efe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0efe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0eff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0eff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7b5c7b0f0000: f1 f1 f1 f1 f1[f1]00 04 f2 f2 02 f2 00 00 f2 f2
  0x7b5c7b0f0080: 00 00 00 00 00 00 00 00 f3 f3 f3 f3 f3 f3 f3 f3
  0x7b5c7b0f0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0f0180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0f0200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b5c7b0f0280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab10_index_read`, RVA `0x13ea`.

# Walkthrough 11 — Narrowing truncation

## Root-cause hypothesis

size_t 70000 becomes uint16_t 4464 in recorded mode 11.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001013fb
ENTRY 001013fb
SIGNATURE undefined FUN_001013fb(void)
CALLERS 001020c8, 001022c0, 001015b4

undefined4 FUN_001013fb(undefined4 param_1)

{
  return param_1;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013fb <lab11_truncate_size>:
    13fb:	89 f8                	mov    eax,edi
    13fd:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x14
 RBX  0x112233b7
 RCX  0
 RDX  1
 RDI  0x11170
 RSI  3
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x5555555555b9 (main+303) ◂— movzx r14d, ax
 RIP  0x5555555553fb (lab11_truncate_size) ◂— mov eax, edi
   0x5555555553fd <lab11_truncate_size+2>    ret                                <main+303>
   0x5555555555b9 <main+303>                 movzx  r14d, ax      R14D => 0x1170
   0x5555555555bd <main+307>                 add    r14, rbx      R14 => 0x11224527 (0x1170 + 0x112233b7)
   0x5555555555c0 <main+310>                 mov    edx, 0x10     EDX => 0x10
   0x5555555555c5 <main+315>                 mov    esi, 8        ESI => 8
   0x5555555555ca <main+320>                 mov    edi, 4        EDI => 4
   0x5555555555cf <main+325>                 call   lab12_add_overflow          <lab12_add_overflow>
   0x5555555555d4 <main+330>                 movsxd rbx, eax
   0x5555555555d7 <main+333>                 add    rbx, r14
   0x5555555555da <main+336>                 mov    edi, 1        EDI => 1
```

## Triggered evidence

```text
truncated=4464
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab11_truncate_size`, RVA `0x13fb`.

# Walkthrough 12 — Wrapped addition check

## Root-cause hypothesis

off+len wraps below total; recorded mode 12 returns wrapped-check=1.

## Ghidra stripped decompilation

```c
FUNCTION FUN_001013fe
ENTRY 001013fe
SIGNATURE undefined FUN_001013fe(void)
CALLERS 001020d0, 001022d4, 001015cf

bool FUN_001013fe(int param_1,int param_2,uint param_3)

{
  return (uint)(param_1 + param_2) <= param_3;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013fe <lab12_add_overflow>:
    13fe:	01 f7                	add    edi,esi
    1400:	39 fa                	cmp    edx,edi
    1402:	0f 93 c0             	setae  al
    1405:	0f b6 c0             	movzx  eax,al
    1408:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x11170
 RBX  0x112233b7
 RCX  0
 RDX  0x10
 RDI  4
 RSI  8
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x5555555555d4 (main+330) ◂— movsxd rbx, eax
 RIP  0x5555555553fe (lab12_add_overflow) ◂— add edi, esi
   0x555555555400 <lab12_add_overflow+2>     cmp    edx, edi     0x10 - 0xc     EFLAGS => 0x212 [ cf pf AF zf sf IF df of ac ]
   0x555555555402 <lab12_add_overflow+4>     setae  al
   0x555555555405 <lab12_add_overflow+7>     movzx  eax, al      EAX => 1
   0x555555555408 <lab12_add_overflow+10>    ret                                <main+330>
   0x5555555555d4 <main+330>                 movsxd rbx, eax     RBX => 1
   0x5555555555d7 <main+333>                 add    rbx, r14     RBX => 0x11224528 (0x1 + 0x11224527)
   0x5555555555da <main+336>                 mov    edi, 1       EDI => 1
   0x5555555555df <main+341>                 call   lab13_uninitialized         <lab13_uninitialized>
   0x5555555555e4 <main+346>                 movsxd r14, eax
   0x5555555555e7 <main+349>                 add    r14, rbx
```

## Triggered evidence

```text
wrapped-check=1
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab12_add_overflow`, RVA `0x13fe`.

# Walkthrough 13 — Uninitialized value/undefined behavior

## Root-cause hypothesis

x is not defined on one source path; optimization may collapse behavior, illustrating why binary and source semantics diverge under UB.

## Ghidra stripped decompilation

```c
FUNCTION FUN_00101409
ENTRY 00101409
SIGNATURE undefined FUN_00101409(void)
CALLERS 001020d8, 001022e8, 001015df

undefined8 FUN_00101409(void)

{
  return 0x2b;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001409 <lab13_uninitialized>:
    1409:	b8 2b 00 00 00       	mov    eax,0x2b
    140e:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  1
 RBX  0x11224528
 RCX  0
 RDX  0x10
 RDI  1
 RSI  8
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x5555555555e4 (main+346) ◂— movsxd r14, eax
 RIP  0x555555555409 (lab13_uninitialized) ◂— mov eax, 0x2b
   0x55555555540e <lab13_uninitialized+5>    ret                                <main+346>
   0x5555555555e4 <main+346>                 movsxd r14, eax              R14 => 0x2b
   0x5555555555e7 <main+349>                 add    r14, rbx              R14 => 0x11224553 (0x2b + 0x11224528)
   0x5555555555ea <main+352>                 lea    rdi, [rbp - 0x92]     RDI => 0x7fffffffe0ce ◂— 0xa444342410003
   0x5555555555f1 <main+359>                 mov    esi, 6                ESI => 6
   0x5555555555f6 <main+364>                 call   lab14_partial_validation    <lab14_partial_validation>
   0x5555555555fb <main+369>                 movsxd rbx, eax
   0x5555555555fe <main+372>                 add    rbx, r14
   0x555555555601 <main+375>                 lea    rdx, [rip + 0xa2a]     RDX => 0x555555556032 ◂— 0x6863006465786966 /* 'fixed' */
   0x555555555608 <main+382>                 mov    esi, 0x20              ESI => 0x20
```

## Triggered evidence

```text
The optimized build’s undefined behavior did not produce a sanitizer diagnostic in this mode; compare source, assembly, and an O0 build rather than claiming a runtime event that was not observed.
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab13_uninitialized`, RVA `0x1409`.

# Walkthrough 14 — Length-field boundary error

## Root-cause hypothesis

Checks len<n but then indexes p[len]; recover exact accepted range and malformed length behavior.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010140f
ENTRY 0010140f
SIGNATURE undefined FUN_0010140f(void)
CALLERS 001020e0, 001022fc, 001015f6

ulong FUN_0010140f(ushort *param_1,ulong param_2)

{
  if (param_2 < 2) {
    return 0xffffffff;
  }
  if (*param_1 < param_2) {
    return (ulong)*(byte *)((long)param_1 + (ulong)*param_1);
  }
  return 0xfffffffe;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000140f <lab14_partial_validation>:
    140f:	48 83 fe 01          	cmp    rsi,0x1
    1413:	76 0d                	jbe    1422 <lab14_partial_validation+0x13>
    1415:	0f b7 07             	movzx  eax,WORD PTR [rdi]
    1418:	48 39 f0             	cmp    rax,rsi
    141b:	73 0b                	jae    1428 <lab14_partial_validation+0x19>
    141d:	0f b6 04 07          	movzx  eax,BYTE PTR [rdi+rax*1]
    1421:	c3                   	ret
    1422:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1427:	c3                   	ret
    1428:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    142d:	c3                   	ret

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x2b
 RBX  0x11224528
 RCX  0
 RDX  0x10
 RDI  0x7fffffffe0ce ◂— 0xa444342410003
 RSI  6
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x5555555555fb (main+369) ◂— movsxd rbx, eax
 RIP  0x55555555540f (lab14_partial_validation) ◂— cmp rsi, 1
   0x555555555413 <lab14_partial_validation+4>   ✘ jbe    lab14_partial_validation+19 <lab14_partial_validation+19>
   0x555555555415 <lab14_partial_validation+6>     movzx  eax, word ptr [rdi]     EAX, [0x7fffffffe0ce] => 3
   0x555555555418 <lab14_partial_validation+9>     cmp    rax, rsi                3 - 6     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x55555555541b <lab14_partial_validation+12>  ✘ jae    lab14_partial_validation+25 <lab14_partial_validation+25>
   0x55555555541d <lab14_partial_validation+14>    movzx  eax, byte ptr [rdi + rax]     EAX, [0x7fffffffe0d1] => 0x42
   0x555555555421 <lab14_partial_validation+18>    ret                                <main+369>
   0x5555555555fb <main+369>                       movsxd rbx, eax               RBX => 0x42
   0x5555555555fe <main+372>                       add    rbx, r14               RBX => 0x11224595 (0x42 + 0x11224553)
   0x555555555601 <main+375>                       lea    rdx, [rip + 0xa2a]     RDX => 0x555555556032 ◂— 0x6863006465786966 /* 'fixed' */
   0x555555555608 <main+382>                       mov    esi, 0x20              ESI => 0x20
```

## Triggered evidence

```text
The optimized build’s undefined behavior did not produce a sanitizer diagnostic in this mode; compare source, assembly, and an O0 build rather than claiming a runtime event that was not observed.
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab14_partial_validation`, RVA `0x140f`.

# Walkthrough 15 — Correct capacity-aware contrast

## Root-cause hypothesis

strnlen rejects nonterminated/oversized input and copies n+1 only when it fits.

## Ghidra stripped decompilation

```c
FUNCTION FUN_0010142e
ENTRY 0010142e
SIGNATURE undefined FUN_0010142e(void)
CALLERS 001020e8, 00102310, 00101610

ulong FUN_0010142e(void *param_1,size_t param_2,char *param_3)

{
  size_t sVar1;
  ulong uVar2;

  sVar1 = strnlen(param_3,param_2);
  if (param_2 == sVar1) {
    uVar2 = 0xffffffff;
  }
  else {
    memcpy(param_1,param_3,sVar1 + 1);
    uVar2 = sVar1 & 0xffffffff;
  }
  return uVar2;
}
```

## Complete vulnerable assembly

```asm
reversing-walkthrough-lab/build/ch07/ch07_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

000000000000142e <lab15_fixed_copy>:
    142e:	55                   	push   rbp
    142f:	48 89 e5             	mov    rbp,rsp
    1432:	48 8d 64 24 e0       	lea    rsp,[rsp-0x20]
    1437:	4c 89 65 e8          	mov    QWORD PTR [rbp-0x18],r12
    143b:	4c 89 6d f0          	mov    QWORD PTR [rbp-0x10],r13
    143f:	4c 89 75 f8          	mov    QWORD PTR [rbp-0x8],r14
    1443:	49 89 fe             	mov    r14,rdi
    1446:	49 89 f4             	mov    r12,rsi
    1449:	49 89 d5             	mov    r13,rdx
    144c:	48 89 d7             	mov    rdi,rdx
    144f:	e8 1c fc ff ff       	call   1070 <strnlen@plt>
    1454:	49 39 c4             	cmp    r12,rax
    1457:	74 2a                	je     1483 <lab15_fixed_copy+0x55>
    1459:	48 89 5d e0          	mov    QWORD PTR [rbp-0x20],rbx
    145d:	48 89 c3             	mov    rbx,rax
    1460:	48 8d 50 01          	lea    rdx,[rax+0x1]
    1464:	4c 89 ee             	mov    rsi,r13
    1467:	4c 89 f7             	mov    rdi,r14
    146a:	e8 11 fc ff ff       	call   1080 <memcpy@plt>
    146f:	89 d8                	mov    eax,ebx
    1471:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    1475:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    1479:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    147d:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    1481:	c9                   	leave
    1482:	c3                   	ret
    1483:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1488:	eb eb                	jmp    1475 <lab15_fixed_copy+0x47>

Disassembly of section .fini:
```

## Normal-path pwndbg entry

```text
RAX  0x42
 RBX  0x11224595
 RCX  0
 RDX  0x555555556032 ◂— 0x6863006465786966 /* 'fixed' */
 RDI  0x7fffffffe120 ◂— 0xb700434241 /* 'ABC' */
 RSI  0x20
 R8   0xf3f3fe00
 R9   2
 RSP  0x7fffffffe0b8 —▸ 0x555555555615 (main+395) ◂— movsxd rsi, eax
 RIP  0x55555555542e (lab15_fixed_copy) ◂— push rbp
   0x55555555542f <lab15_fixed_copy+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555432 <lab15_fixed_copy+4>     lea    rsp, [rsp - 0x20]               RSP => 0x7fffffffe090 —▸ 0x7fffffffe0e0 ◂— 'safe path'
   0x555555555437 <lab15_fixed_copy+9>     mov    qword ptr [rbp - 0x18], r12     [0x7fffffffe098] <= 0x7fffffffe0e0 ◂— 'safe path'
   0x55555555543b <lab15_fixed_copy+13>    mov    qword ptr [rbp - 0x10], r13     [{b}] <= 0x7fffffffe120 ◂— 0xb700434241 /* 'ABC' */
   0x55555555543f <lab15_fixed_copy+17>    mov    qword ptr [rbp - 8], r14        [0x7fffffffe0a8] <= 0x11224553
   0x555555555443 <lab15_fixed_copy+21>    mov    r14, rdi                        R14 => 0x7fffffffe120 ◂— 0xb700434241 /* 'ABC' */
   0x555555555446 <lab15_fixed_copy+24>    mov    r12, rsi                        R12 => 0x20
   0x555555555449 <lab15_fixed_copy+27>    mov    r13, rdx                        R13 => 0x555555556032 ◂— 0x6863006465786966 /* 'fixed' */
   0x55555555544c <lab15_fixed_copy+30>    mov    rdi, rdx                        RDI => 0x555555556032 ◂— 0x6863006465786966 /* 'fixed' */
   0x55555555544f <lab15_fixed_copy+33>    call   strnlen@plt                 <strnlen@plt>
```

## Triggered evidence

```text
The optimized build’s undefined behavior did not produce a sanitizer diagnostic in this mode; compare source, assembly, and an O0 build rather than claiming a runtime event that was not observed.
```

## Step-by-step finding

1. Identify the attacker-controlled source and exact destination/lifetime.
2. Write the required invariant with units and signedness.
3. Locate the missing or invalid check in assembly.
4. Use the minimal trigger and stop at the first invalid access or recorded logic violation.
5. Separate the confirmed primitive from possible impact and explain mitigations.
6. Replace the operation/check with the fixed invariant and add below/at/above-boundary regressions.

**Finding:** `lab15_fixed_copy`, RVA `0x142e`.

# Twenty Practice Questions

1. What is the stack-copy invariant?
2. Why is heap role corruption a heap overflow?
3. How prove multiplication overflow?
4. Why does n=-1 pass?
5. Off-by-one correct condition?
6. What makes format input dangerous?
7. How identify first UAF read?
8. Why can double free vanish at O2?
9. Filter repair?
10. Negative index repair?
11. 70000 truncated to?
12. Safe add-range check?
13. Why is crash site not root cause?
14. What must a vulnerability report separate?
15. Why use ASan and pwndbg?
16. Does NX fix overflow?
17. What does a canary cover?
18. Why include fixed copy?
19. What is benign proof?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** strlen(src)+1<=16.
4. Give the root-cause fix and three boundary regressions.

## 2. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** The write exceeds the allocated/name subobject boundary even if adjacent field is in the same allocation.
4. Give the root-cause fix and three boundary regressions.

## 3. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Compare mathematical product with 32-bit EAX result and malloc argument.
4. Give the root-cause fix and three boundary regressions.

## 4. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Signed -1 is less than positive cap before conversion to size_t.
4. Give the root-cause fix and three boundary regressions.

## 5. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** n<cap when appending dst[n]=0, plus cap>0.
4. Give the root-cause fix and three boundary regressions.

## 6. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** It controls printf grammar rather than a %s data argument.
4. Give the root-cause fix and three boundary regressions.

## 7. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Break/watch after free or use ASan report at field load.
4. Give the root-cause fix and three boundary regressions.

## 8. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Undefined behavior permits compiler assumptions/transformations; inspect an O0 teaching build for direct manifestation.
4. Give the root-cause fix and three boundary regressions.

## 9. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Strictly decode/canonicalize first, validate canonical form, use same buffer.
4. Give the root-cause fix and three boundary regressions.

## 10. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Require index>=0 and (size_t)index<n before access.
4. Give the root-cause fix and three boundary regressions.

## 11. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** 4464 modulo 65536.
4. Give the root-cause fix and three boundary regressions.

## 12. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** off<=total and len<=total-off.
4. Give the root-cause fix and three boundary regressions.

## 13. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Corruption may happen earlier; root cause is first invariant-violating access.
4. Give the root-cause fix and three boundary regressions.

## 14. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Root cause, reachability, primitive/control, impact, and mitigations.
4. Give the root-cause fix and three boundary regressions.

## 15. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** ASan pinpoints invalid access class; pwndbg exposes exact machine state and maps it to Ghidra.
4. Give the root-cause fix and three boundary regressions.

## 16. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** No; it changes consequences, not the invalid write.
4. Give the root-cause fix and three boundary regressions.

## 17. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Many stack overwrites crossing the guard, not all object/noncontrol corruption.
4. Give the root-cause fix and three boundary regressions.

## 18. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** It makes the correct invariant and compiled checks directly comparable.
4. Give the root-cause fix and three boundary regressions.

## 19. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Marker/sanitizer first invalid access without weaponized payload.
4. Give the root-cause fix and three boundary regressions.

## 20. Solution

1. State the object, capacity/lifetime, source, and units.
2. Identify the first invalid instruction or logic result.
3. **Answer:** Find root cause blind, trigger minimally, explain assembly/mitigations, fix source, and pass boundary regressions.
4. Give the root-cause fix and three boundary regressions.


Return to [[Chapter 07 - Auditing Program Binaries]].
