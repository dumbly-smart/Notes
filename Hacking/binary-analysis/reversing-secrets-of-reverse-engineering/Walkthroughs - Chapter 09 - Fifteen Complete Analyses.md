# Chapter 9 — Fifteen Complete Protection-Technology Walkthroughs

> [!scope]
> These are self-authored protection models for defensive architecture study. They are not third-party license bypasses.

## Baseline

```text
chapter09 evidence=5008423205
```

## Complete source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;
NI uint32_t h32(const uint8_t*p,size_t n){uint32_t h=0x811c9dc5u;for(size_t i=0;i<n;i++)h=(h^p[i])*16777619u;return h;}
NI int lab01_serial_checksum(const char*s,uint32_t serial){return (h32((const uint8_t*)s,strlen(s))^0x5a17c9e3u)==serial;}
NI int lab02_signed_claim(const uint8_t*claim,size_t n,uint32_t signature){return h32(claim,n)==signature;}
NI uint32_t lab03_challenge_response(uint32_t challenge,uint32_t device){uint32_t x=challenge^device^0x91e10da5u;for(int i=0;i<8;i++)x=(x<<5)|(x>>27),x+=0x7f4a7c15u;return x;}
NI int lab04_device_binding(uint64_t stored,uint64_t cpu,uint64_t disk){uint64_t x=(cpu^(disk<<17|disk>>47))*0x9e3779b97f4a7c15ULL;return x==stored;}
NI int lab05_expiry(uint64_t now,uint64_t issued,uint64_t duration){return now>=issued&&now-issued<=duration;}
NI uint32_t lab06_features(uint32_t licensed,uint32_t requested){return requested&licensed;}
NI int lab07_nonce_replay(uint64_t nonce,const uint64_t*seen,size_t n){for(size_t i=0;i<n;i++)if(seen[i]==nonce)return 0;return 1;}
NI uint32_t lab08_watermark(uint32_t user,uint32_t build,uint32_t copy){uint32_t x=user*0x45d9f3bu^build*33u^copy;return x^(x>>16);}
NI int lab09_clock_rollback(uint64_t now,uint64_t last,uint64_t tolerance){return now+tolerance>=last;}
NI int lab10_usage_limit(uint32_t used,uint32_t requested,uint32_t limit){if(used>limit)return 0;return requested<=limit-used;}
NI int lab11_receipt(const uint8_t*body,size_t n,uint32_t mac,uint32_t product){return n>=4&&h32(body,n-4)==mac&&*(const uint32_t*)(body+n-4)==product;}
NI uint32_t lab12_token_oracle(uint32_t challenge,uint32_t secret){return (challenge*secret)^((challenge<<11)|(challenge>>21));}
NI int lab13_code_integrity(const uint8_t*p,size_t n,uint32_t expected){return h32(p,n)==expected;}
NI void lab14_config_crypt(uint8_t*p,size_t n,uint32_t key){for(size_t i=0;i<n;i++){key=key*1664525u+1013904223u;p[i]^=key>>24;}}
NI int lab15_composite(const char*user,uint32_t serial,uint64_t now,uint64_t issued,uint32_t licensed,uint32_t requested){
 if(!lab01_serial_checksum(user,serial))return-1;if(!lab05_expiry(now,issued,86400))return-2;if(lab06_features(licensed,requested)!=requested)return-3;return 1;}
int main(void){const char*u="MENTOR";uint32_t serial=h32((const uint8_t*)u,strlen(u))^0x5a17c9e3u;uint8_t claim[]="CLAIM";
 uint32_t sig=h32(claim,sizeof claim-1);uint64_t cpu=7,disk=11,stored=(cpu^(disk<<17|disk>>47))*0x9e3779b97f4a7c15ULL;
 uint64_t seen[]={1,2,3};uint8_t receipt[12]={1,2,3,4,5,6,7,8,0x34,0x12,0,0};uint32_t mac=h32(receipt,8);
 uint8_t cfg[]="CONFIG";uint64_t total=0;total+=lab01_serial_checksum(u,serial);total+=lab02_signed_claim(claim,5,sig);
 total+=lab03_challenge_response(9,10);total+=lab04_device_binding(stored,cpu,disk);total+=lab05_expiry(1000,900,200);
 total+=lab06_features(7,5);total+=lab07_nonce_replay(4,seen,3);total+=lab08_watermark(12,34,56);
 total+=lab09_clock_rollback(100,105,10);total+=lab10_usage_limit(7,2,10);total+=lab11_receipt(receipt,12,mac,0x1234);
 total+=lab12_token_oracle(3,0x12345);total+=lab13_code_integrity(claim,5,sig);lab14_config_crypt(cfg,sizeof cfg-1,7);
 total+=lab15_composite(u,serial,1000,900,7,5);evidence_sink=total;printf("chapter09 evidence=%llu\n",(unsigned long long)total);return 0;}
```

# Walkthrough 01 — Local serial checksum

## Protection question

Recover user normalization boundary, hash call, XOR constant, and equality.

## Ghidra decompilation

```c
FUNCTION FUN_001013e0
ENTRY 001013e0
SIGNATURE undefined FUN_001013e0(void)
CALLERS 0010206c, 0010215c, 00101105, 001015d7

bool FUN_001013e0(char *param_1,uint param_2)

{
  uint uVar1;
  size_t sVar2;

  sVar2 = strlen(param_1);
  uVar1 = FUN_001013a0(param_1,sVar2);
  return (uVar1 ^ 0x5a17c9e3) == param_2;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000013e0 <lab01_serial_checksum>:
    13e0:	55                   	push   rbp
    13e1:	48 89 e5             	mov    rbp,rsp
    13e4:	53                   	push   rbx
    13e5:	89 f3                	mov    ebx,esi
    13e7:	48 83 ec 18          	sub    rsp,0x18
    13eb:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    13ef:	e8 3c fc ff ff       	call   1030 <strlen@plt>
    13f4:	48 8b 7d e8          	mov    rdi,QWORD PTR [rbp-0x18]
    13f8:	48 89 c6             	mov    rsi,rax
    13fb:	e8 a0 ff ff ff       	call   13a0 <h32>
    1400:	35 e3 c9 17 5a       	xor    eax,0x5a17c9e3
    1405:	39 d8                	cmp    eax,ebx
    1407:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    140b:	c9                   	leave
    140c:	0f 94 c0             	sete   al
    140f:	0f b6 c0             	movzx  eax,al
    1412:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x2804678d
 RBX  0x24effc4f
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555340 (__do_global_dtors_aux) ◂— endbr64
 RDX  8
 RDI  0x555555556004 ◂— 0x6300524f544e454d /* 'MENTOR' */
 RSI  0x1587a9bf
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x55555555510a (main+170) ◂— mov edx, ebx
 RIP  0x5555555553e0 (lab01_serial_checksum) ◂— push rbp
   0x5555555553e1 <lab01_serial_checksum+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0f0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555553e4 <lab01_serial_checksum+4>     push   rbx
   0x5555555553e5 <lab01_serial_checksum+5>     mov    ebx, esi                        EBX => 0x1587a9bf
   0x5555555553e7 <lab01_serial_checksum+7>     sub    rsp, 0x18                       RSP => 0x7fffffffe0d0 (0x7fffffffe0e8 - 0x18)
   0x5555555553eb <lab01_serial_checksum+11>    mov    qword ptr [rbp - 0x18], rdi     [0x7fffffffe0d8] <= 0x555555556004 ◂— 0x6300524f544e454d /* 'MENTOR' */
   0x5555555553ef <lab01_serial_checksum+15>    call   strlen@plt                  <strlen@plt>
   0x5555555553f4 <lab01_serial_checksum+20>    mov    rdi, qword ptr [rbp - 0x18]
   0x5555555553f8 <lab01_serial_checksum+24>    mov    rsi, rax
   0x5555555553fb <lab01_serial_checksum+27>    call   h32                         <h32>
   0x555555555400 <lab01_serial_checksum+32>    xor    eax, 0x5a17c9e3
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab01_serial_checksum`, RVA `0x13e0`.

# Walkthrough 02 — Claim authenticity surrogate

## Protection question

Recover body pointer/length, digest, signature comparison, and explain why real systems need asymmetric signatures.

## Ghidra decompilation

```c
FUNCTION FUN_00101420
ENTRY 00101420
SIGNATURE undefined FUN_00101420(void)
CALLERS 00102074, 0010217c, 00101118

bool FUN_00101420(undefined8 param_1,undefined8 param_2,int param_3)

{
  int iVar1;

  iVar1 = FUN_001013a0();
  return iVar1 == param_3;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001420 <lab02_signed_claim>:
    1420:	55                   	push   rbp
    1421:	89 d1                	mov    ecx,edx
    1423:	48 89 e5             	mov    rbp,rsp
    1426:	e8 75 ff ff ff       	call   13a0 <h32>
    142b:	5d                   	pop    rbp
    142c:	39 c8                	cmp    eax,ecx
    142e:	0f 94 c0             	sete   al
    1431:	0f b6 c0             	movzx  eax,al
    1434:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555340 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x24effc4f
 RDI  0x7fffffffe11f ◂— 0x4f43004d49414c43 /* 'CLAIM' */
 RSI  5
 R8   1
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x55555555511d (main+189) ◂— mov esi, 0xa
 RIP  0x555555555420 (lab02_signed_claim) ◂— push rbp
   0x555555555421 <lab02_signed_claim+1>        mov    ecx, edx     ECX => 0x24effc4f
   0x555555555423 <lab02_signed_claim+3>        mov    rbp, rsp     RBP => 0x7fffffffe0f0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555426 <lab02_signed_claim+6>        call   h32                         <h32>
   0x55555555542b <lab02_signed_claim+11>       pop    rbp
   0x55555555542c <lab02_signed_claim+12>       cmp    eax, ecx
   0x55555555542e <lab02_signed_claim+14>       sete   al
   0x555555555431 <lab02_signed_claim+17>       movzx  eax, al
   0x555555555434 <lab02_signed_claim+20>       ret
   0x555555555435                               nop    word ptr [rax + rax]
=> 0x555555555420 <lab02_signed_claim>:	push   rbp
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab02_signed_claim`, RVA `0x1420`.

# Walkthrough 03 — Challenge-response transform

## Protection question

Recover challenge/device mixing, eight-round rotate/add recurrence, and returned token.

## Ghidra decompilation

```c
FUNCTION FUN_00101440
ENTRY 00101440
SIGNATURE undefined FUN_00101440(void)
CALLERS 0010207c, 0010219c, 0010112d

uint FUN_00101440(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;

  iVar2 = 8;
  uVar1 = param_1 ^ param_2 ^ 0x91e10da5;
  do {
    uVar1 = (uVar1 << 5 | uVar1 >> 0x1b) + 0x7f4a7c15;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return uVar1;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001440 <lab03_challenge_response>:
    1440:	89 f8                	mov    eax,edi
    1442:	ba 08 00 00 00       	mov    edx,0x8
    1447:	31 f0                	xor    eax,esi
    1449:	35 a5 0d e1 91       	xor    eax,0x91e10da5
    144e:	66 90                	xchg   ax,ax
    1450:	c1 c0 05             	rol    eax,0x5
    1453:	05 15 7c 4a 7f       	add    eax,0x7f4a7c15
    1458:	83 ea 01             	sub    edx,0x1
    145b:	75 f3                	jne    1450 <lab03_challenge_response+0x10>
    145d:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  2
 RDX  0x4d
 RDI  9
 RSI  0xa
 R8   1
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x555555555132 (main+210) ◂— mov edx, 0xb
 RIP  0x555555555440 (lab03_challenge_response) ◂— mov eax, edi
   0x55555555542c <lab02_signed_claim+12>          cmp    eax, ecx
   0x55555555542e <lab02_signed_claim+14>          sete   al
   0x555555555431 <lab02_signed_claim+17>          movzx  eax, al
   0x555555555434 <lab02_signed_claim+20>          ret
   0x555555555435                                  nop    word ptr [rax + rax]
   0x555555555442 <lab03_challenge_response+2>     mov    edx, 8                   EDX => 8
   0x555555555447 <lab03_challenge_response+7>     xor    eax, esi                 EAX => 3 (0x9 ^ 0xa)
   0x555555555449 <lab03_challenge_response+9>     xor    eax, 0x91e10da5          EAX => 0x91e10da6 (0x3 ^ 0x91e10da5)
   0x55555555544e <lab03_challenge_response+14>    nop
   0x555555555450 <lab03_challenge_response+16>    rol    eax, 5
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab03_challenge_response`, RVA `0x1440`.

# Walkthrough 04 — Device-binding fingerprint

## Protection question

Recover CPU/disk combination, 64-bit rotate/multiply, and stored comparison.

## Ghidra decompilation

```c
FUNCTION FUN_00101460
ENTRY 00101460
SIGNATURE undefined FUN_00101460(void)
CALLERS 00102084, 001021b0, 00101149

bool FUN_00101460(long param_1,ulong param_2,ulong param_3)

{
  return ((param_3 << 0x11 | param_3 >> 0x2f) ^ param_2) * -0x61c8864680b583eb - param_1 == 0;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001460 <lab04_device_binding>:
    1460:	48 b8 15 7c 4a 7f b9 	movabs rax,0x9e3779b97f4a7c15
    1467:	79 37 9e
    146a:	48 c1 c2 11          	rol    rdx,0x11
    146e:	48 31 f2             	xor    rdx,rsi
    1471:	48 0f af d0          	imul   rdx,rax
    1475:	31 c0                	xor    eax,eax
    1477:	48 39 fa             	cmp    rdx,rdi
    147a:	0f 94 c0             	sete   al
    147d:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0xf61fc04a
 RBX  0x24effc4f
 RCX  2
 RDX  0xb
 RDI  0xc975447924d76493
 RSI  7
 R8   0xf61fc04a
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x55555555514e (main+238) ◂— mov edx, 0xc8
 RIP  0x555555555460 (lab04_device_binding) ◂— movabs rax, 0x9e3779b97f4a7c15
   0x55555555546a <lab04_device_binding+10>    rol    rdx, 0x11
   0x55555555546e <lab04_device_binding+14>    xor    rdx, rsi                    RDX => 0x160007 (0x160000 ^ 0x7)
   0x555555555471 <lab04_device_binding+17>    imul   rdx, rax
   0x555555555475 <lab04_device_binding+21>    xor    eax, eax                    EAX => 0
   0x555555555477 <lab04_device_binding+23>    cmp    rdx, rdi                    0xc975447924d76493 - 0xc975447924d76493     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x55555555547a <lab04_device_binding+26>    sete   al
   0x55555555547d <lab04_device_binding+29>    ret                                <main+238>
   0x55555555514e <main+238>                   mov    edx, 0xc8                   EDX => 0xc8
   0x555555555153 <main+243>                   mov    esi, 0x384                  ESI => 0x384
   0x555555555158 <main+248>                   add    r8, rcx                     R8 => 0xf61fc04c (0xf61fc04a + 0x2)
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab04_device_binding`, RVA `0x1460`.

# Walkthrough 05 — Overflow-aware time window

## Protection question

Recover now>=issued and now-issued<=duration rather than unsafe issued+duration.

## Ghidra decompilation

```c
FUNCTION FUN_00101480
ENTRY 00101480
SIGNATURE undefined FUN_00101480(void)
CALLERS 0010208c, 001021c4, 00101162, 001015eb

bool FUN_00101480(ulong param_1,ulong param_2,ulong param_3)

{
  return param_2 <= param_1 && param_1 - param_2 <= param_3;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001480 <lab05_expiry>:
    1480:	31 c0                	xor    eax,eax
    1482:	48 39 f7             	cmp    rdi,rsi
    1485:	72 0b                	jb     1492 <lab05_expiry+0x12>
    1487:	48 29 f7             	sub    rdi,rsi
    148a:	31 c0                	xor    eax,eax
    148c:	48 39 fa             	cmp    rdx,rdi
    148f:	0f 93 c0             	setae  al
    1492:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  1
 RDX  0xc8
 RDI  0x3e8
 RSI  0x384
 R8   0xf61fc04c
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x555555555167 (main+263) ◂— mov esi, 5
 RIP  0x555555555480 (lab05_expiry) ◂— xor eax, eax
   0x555555555482 <lab05_expiry+2>     cmp    rdi, rsi     0x3e8 - 0x384     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555485 <lab05_expiry+5>   ✘ jb     lab05_expiry+18             <lab05_expiry+18>
   0x555555555487 <lab05_expiry+7>     sub    rdi, rsi     RDI => 0x64 (0x3e8 - 0x384)
   0x55555555548a <lab05_expiry+10>    xor    eax, eax     EAX => 0
   0x55555555548c <lab05_expiry+12>    cmp    rdx, rdi     0xc8 - 0x64     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x55555555548f <lab05_expiry+15>    setae  al
   0x555555555492 <lab05_expiry+18>    ret                                <main+263>
   0x555555555167 <main+263>           mov    esi, 5       ESI => 5
   0x55555555516c <main+268>           mov    edi, 7       EDI => 7
   0x555555555171 <main+273>           add    rcx, r8      RCX => 0xf61fc04d (0x1 + 0xf61fc04c)
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab05_expiry`, RVA `0x1480`.

# Walkthrough 06 — Feature mask

## Protection question

Recover requested∩licensed and distinguish calculation from authorization decision.

## Ghidra decompilation

```c
FUNCTION FUN_001014a0
ENTRY 001014a0
SIGNATURE undefined FUN_001014a0(void)
CALLERS 00102094, 001021d8, 00101176, 001015fb

uint FUN_001014a0(uint param_1,uint param_2)

{
  return param_2 & param_1;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014a0 <lab06_features>:
    14a0:	89 f0                	mov    eax,esi
    14a2:	21 f8                	and    eax,edi
    14a4:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  0xf61fc04d
 RDX  1
 RDI  7
 RSI  5
 R8   0xf61fc04c
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x55555555517b (main+283) ◂— add rdx, rcx
 RIP  0x5555555554a0 (lab06_features) ◂— mov eax, esi
   0x5555555554a2 <lab06_features+2>    and    eax, edi     EAX => 5 (5 & 7)
   0x5555555554a4 <lab06_features+4>    ret                                <main+283>
   0x55555555517b <main+283>            add    rdx, rcx              RDX => 0xf61fc04e (0x1 + 0xf61fc04d)
   0x55555555517e <main+286>            lea    rsi, [rbp - 0x60]     RSI => 0x7fffffffe100 ◂— 1
   0x555555555182 <main+290>            mov    edi, 4                EDI => 4
   0x555555555187 <main+295>            mov    ecx, eax              ECX => 5
   0x555555555189 <main+297>            add    rcx, rdx              RCX => 0xf61fc053 (0x5 + 0xf61fc04e)
   0x55555555518c <main+300>            mov    edx, 3                EDX => 3
   0x555555555191 <main+305>            call   lab07_nonce_replay          <lab07_nonce_replay>
   0x555555555196 <main+310>            mov    edx, 0x38             EDX => 0x38
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab06_features`, RVA `0x14a0`.

# Walkthrough 07 — Replay-set lookup

## Protection question

Recover linear seen-nonce search and unseen Boolean.

## Ghidra decompilation

```c
FUNCTION FUN_001014b0
ENTRY 001014b0
SIGNATURE undefined FUN_001014b0(void)
CALLERS 0010209c, 001021ec, 00101191

undefined8 FUN_001014b0(long param_1,long param_2,long param_3)

{
  long lVar1;

  lVar1 = 0;
  if (param_3 != 0) {
    do {
      if (*(long *)(param_2 + lVar1 * 8) == param_1) {
        return 0;
      }
      lVar1 = lVar1 + 1;
    } while (param_3 != lVar1);
  }
  return 1;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014b0 <lab07_nonce_replay>:
    14b0:	31 c0                	xor    eax,eax
    14b2:	48 85 d2             	test   rdx,rdx
    14b5:	75 12                	jne    14c9 <lab07_nonce_replay+0x19>
    14b7:	eb 1f                	jmp    14d8 <lab07_nonce_replay+0x28>
    14b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    14c0:	48 83 c0 01          	add    rax,0x1
    14c4:	48 39 c2             	cmp    rdx,rax
    14c7:	74 0f                	je     14d8 <lab07_nonce_replay+0x28>
    14c9:	48 39 3c c6          	cmp    QWORD PTR [rsi+rax*8],rdi
    14cd:	75 f1                	jne    14c0 <lab07_nonce_replay+0x10>
    14cf:	31 c0                	xor    eax,eax
    14d1:	c3                   	ret
    14d2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    14d8:	b8 01 00 00 00       	mov    eax,0x1
    14dd:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  5
 RBX  0x24effc4f
 RCX  0xf61fc053
 RDX  3
 RDI  4
 RSI  0x7fffffffe100 ◂— 1
 R8   0xf61fc04c
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0f8 —▸ 0x555555555196 (main+310) ◂— mov edx, 0x38
 RIP  0x5555555554b0 (lab07_nonce_replay) ◂— xor eax, eax
   0x5555555554b2 <lab07_nonce_replay+2>     test   rdx, rdx     3 & 3     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555554b5 <lab07_nonce_replay+5>   ✔ jne    lab07_nonce_replay+25       <lab07_nonce_replay+25>
   0x5555555554c9 <lab07_nonce_replay+25>    cmp    qword ptr [rsi + rax*8], rdi     1 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x5555555554cd <lab07_nonce_replay+29>  ✔ jne    lab07_nonce_replay+16       <lab07_nonce_replay+16>
   0x5555555554c0 <lab07_nonce_replay+16>    add    rax, 1       RAX => 1 (0 + 1)
   0x5555555554c4 <lab07_nonce_replay+20>    cmp    rdx, rax     3 - 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x5555555554c7 <lab07_nonce_replay+23>  ✘ je     lab07_nonce_replay+40       <lab07_nonce_replay+40>
   0x5555555554c9 <lab07_nonce_replay+25>    cmp    qword ptr [rsi + rax*8], rdi     2 - 4     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x5555555554cd <lab07_nonce_replay+29>  ✔ jne    lab07_nonce_replay+16       <lab07_nonce_replay+16>
   0x5555555554c0 <lab07_nonce_replay+16>    add    rax, 1                           RAX => 2 (1 + 1)
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab07_nonce_replay`, RVA `0x14b0`.

# Walkthrough 08 — Per-copy watermark ID

## Protection question

Recover user/build/copy mixing and final avalanche-like XOR shift.

## Ghidra decompilation

```c
FUNCTION FUN_001014e0
ENTRY 001014e0
SIGNATURE undefined FUN_001014e0(void)
CALLERS 001020a4, 00102200, 001011ab

uint FUN_001014e0(int param_1,int param_2,uint param_3)

{
  uint uVar1;

  uVar1 = param_2 * 0x21 ^ param_3 ^ param_1 * 0x45d9f3b;
  return uVar1 >> 0x10 ^ uVar1;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000014e0 <lab08_watermark>:
    14e0:	89 f1                	mov    ecx,esi
    14e2:	69 c7 3b 9f 5d 04    	imul   eax,edi,0x45d9f3b
    14e8:	c1 e1 05             	shl    ecx,0x5
    14eb:	8d 3c 31             	lea    edi,[rcx+rsi*1]
    14ee:	31 d7                	xor    edi,edx
    14f0:	31 c7                	xor    edi,eax
    14f2:	89 f8                	mov    eax,edi
    14f4:	c1 e8 10             	shr    eax,0x10
    14f7:	31 f8                	xor    eax,edi
    14f9:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  0xf61fc053
 RDX  0x38
 RDI  0xc
 RSI  0x22
 R8   0xf61fc04c
 R9   0xf61fc054
 RSP  0x7fffffffe0f8 —▸ 0x5555555551b0 (main+336) ◂— mov edx, 0xa
 RIP  0x5555555554e0 (lab08_watermark) ◂— mov ecx, esi
   0x5555555554e2 <lab08_watermark+2>     imul   eax, edi, 0x45d9f3b
   0x5555555554e8 <lab08_watermark+8>     shl    ecx, 5
   0x5555555554eb <lab08_watermark+11>    lea    edi, [rcx + rsi]        EDI => 0x462
   0x5555555554ee <lab08_watermark+14>    xor    edi, edx                EDI => 0x45a (0x462 ^ 0x38)
   0x5555555554f0 <lab08_watermark+16>    xor    edi, eax                EDI => 0x3463729e (0x45a ^ 0x346376c4)
   0x5555555554f2 <lab08_watermark+18>    mov    eax, edi                EAX => 0x3463729e
   0x5555555554f4 <lab08_watermark+20>    shr    eax, 0x10
   0x5555555554f7 <lab08_watermark+23>    xor    eax, edi                EAX => 0x346346fd (0x3463 ^ 0x3463729e)
   0x5555555554f9 <lab08_watermark+25>    ret                                <main+336>
   0x5555555551b0 <main+336>              mov    edx, 0xa                EDX => 0xa
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab08_watermark`, RVA `0x14e0`.

# Walkthrough 09 — Clock rollback tolerance

## Protection question

Recover now+tolerance>=last and discuss addition overflow edge.

## Ghidra decompilation

```c
FUNCTION FUN_00101500
ENTRY 00101500
SIGNATURE undefined FUN_00101500(void)
CALLERS 001020ac, 00102214, 001011c2

bool FUN_00101500(long param_1,ulong param_2,long param_3)

{
  return param_2 <= (ulong)(param_1 + param_3);
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001500 <lab09_clock_rollback>:
    1500:	48 01 d7             	add    rdi,rdx
    1503:	31 c0                	xor    eax,eax
    1505:	48 39 f7             	cmp    rdi,rsi
    1508:	0f 93 c0             	setae  al
    150b:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x346346fd
 RBX  0x24effc4f
 RCX  0x440
 RDX  0xa
 RDI  0x64
 RSI  0x69
 R8   0x346346fd
 R9   0xf61fc054
 RSP  0x7fffffffe0f8 —▸ 0x5555555551c7 (main+359) ◂— mov esi, 2
 RIP  0x555555555500 (lab09_clock_rollback) ◂— add rdi, rdx
   0x555555555503 <lab09_clock_rollback+3>     xor    eax, eax     EAX => 0
   0x555555555505 <lab09_clock_rollback+5>     cmp    rdi, rsi     0x6e - 0x69     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555508 <lab09_clock_rollback+8>     setae  al
   0x55555555550b <lab09_clock_rollback+11>    ret                                <main+359>
   0x5555555551c7 <main+359>                   mov    esi, 2       ESI => 2
   0x5555555551cc <main+364>                   mov    edi, 7       EDI => 7
   0x5555555551d1 <main+369>                   add    r8, r9       R8 => 0x12a830751 (0x346346fd + 0xf61fc054)
   0x5555555551d4 <main+372>                   mov    ecx, eax     ECX => 1
   0x5555555551d6 <main+374>                   call   lab10_usage_limit           <lab10_usage_limit>
   0x5555555551db <main+379>                   add    rcx, r8
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab09_clock_rollback`, RVA `0x1500`.

# Walkthrough 10 — Quota check

## Protection question

Recover used<=limit and requested<=limit-used with subtraction safety.

## Ghidra decompilation

```c
FUNCTION FUN_00101510
ENTRY 00101510
SIGNATURE undefined FUN_00101510(void)
CALLERS 001020b4, 00102228, 001011d6

bool FUN_00101510(uint param_1,uint param_2,uint param_3)

{
  return param_1 <= param_3 && param_2 <= param_3 - param_1;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001510 <lab10_usage_limit>:
    1510:	31 c0                	xor    eax,eax
    1512:	39 fa                	cmp    edx,edi
    1514:	72 09                	jb     151f <lab10_usage_limit+0xf>
    1516:	29 fa                	sub    edx,edi
    1518:	31 c0                	xor    eax,eax
    151a:	39 f2                	cmp    edx,esi
    151c:	0f 93 c0             	setae  al
    151f:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  1
 RDX  0xa
 RDI  7
 RSI  2
 R8   0x12a830751
 R9   0xf61fc054
 RSP  0x7fffffffe0f8 —▸ 0x5555555551db (main+379) ◂— add rcx, r8
 RIP  0x555555555510 (lab10_usage_limit) ◂— xor eax, eax
   0x555555555512 <lab10_usage_limit+2>     cmp    edx, edi     0xa - 0x7     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555514 <lab10_usage_limit+4>   ✘ jb     lab10_usage_limit+15        <lab10_usage_limit+15>
   0x555555555516 <lab10_usage_limit+6>     sub    edx, edi     EDX => 3 (0xa - 0x7)
   0x555555555518 <lab10_usage_limit+8>     xor    eax, eax     EAX => 0
   0x55555555551a <lab10_usage_limit+10>    cmp    edx, esi     3 - 2     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x55555555551c <lab10_usage_limit+12>    setae  al
   0x55555555551f <lab10_usage_limit+15>    ret                                <main+379>
   0x5555555551db <main+379>                add    rcx, r8       RCX => 0x12a830752 (0x1 + 0x12a830751)
   0x5555555551de <main+382>                mov    edx, r13d     EDX => 0x2804678d
   0x5555555551e1 <main+385>                mov    esi, 0xc      ESI => 0xc
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab10_usage_limit`, RVA `0x1510`.

# Walkthrough 11 — Receipt/body binding

## Protection question

Recover minimum length, hash excluding product trailer, MAC comparison, and trailing product ID.

## Ghidra decompilation

```c
FUNCTION FUN_00101520
ENTRY 00101520
SIGNATURE undefined FUN_00101520(void)
CALLERS 001020bc, 0010223c, 001011f5

bool FUN_00101520(long param_1,ulong param_2,int param_3,int param_4)

{
  int iVar1;

  if (param_2 < 4) {
    return false;
  }
  iVar1 = FUN_001013a0(param_1,param_2 - 4);
  if (iVar1 != param_3) {
    return false;
  }
  return *(int *)(param_1 + -4 + param_2) == param_4;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001520 <lab11_receipt>:
    1520:	48 83 fe 03          	cmp    rsi,0x3
    1524:	76 22                	jbe    1548 <lab11_receipt+0x28>
    1526:	55                   	push   rbp
    1527:	49 89 f0             	mov    r8,rsi
    152a:	48 8d 76 fc          	lea    rsi,[rsi-0x4]
    152e:	41 89 d2             	mov    r10d,edx
    1531:	49 89 f9             	mov    r9,rdi
    1534:	48 89 e5             	mov    rbp,rsp
    1537:	e8 64 fe ff ff       	call   13a0 <h32>
    153c:	44 39 d0             	cmp    eax,r10d
    153f:	74 0f                	je     1550 <lab11_receipt+0x30>
    1541:	31 c0                	xor    eax,eax
    1543:	5d                   	pop    rbp
    1544:	c3                   	ret
    1545:	0f 1f 00             	nop    DWORD PTR [rax]
    1548:	31 c0                	xor    eax,eax
    154a:	c3                   	ret
    154b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1550:	31 c0                	xor    eax,eax
    1552:	43 39 4c 01 fc       	cmp    DWORD PTR [r9+r8*1-0x4],ecx
    1557:	5d                   	pop    rbp
    1558:	0f 94 c0             	sete   al
    155b:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  0x1234
 RDX  0x2804678d
 RDI  0x7fffffffe12c ◂— 0x807060504030201
 RSI  0xc
 R8   0x12a830751
 R9   0xf61fc054
 RSP  0x7fffffffe0f8 —▸ 0x5555555551fa (main+410) ◂— mov esi, 0x12345
 RIP  0x555555555520 (lab11_receipt) ◂— cmp rsi, 3
   0x555555555524 <lab11_receipt+4>   ✘ jbe    lab11_receipt+40            <lab11_receipt+40>
   0x555555555526 <lab11_receipt+6>     push   rbp
   0x555555555527 <lab11_receipt+7>     mov    r8, rsi            R8 => 0xc
   0x55555555552a <lab11_receipt+10>    lea    rsi, [rsi - 4]     RSI => 8
   0x55555555552e <lab11_receipt+14>    mov    r10d, edx          R10D => 0x2804678d
   0x555555555531 <lab11_receipt+17>    mov    r9, rdi            R9 => 0x7fffffffe12c ◂— 0x807060504030201
   0x555555555534 <lab11_receipt+20>    mov    rbp, rsp           RBP => 0x7fffffffe0f0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555537 <lab11_receipt+23>    call   h32                         <h32>
   0x55555555553c <lab11_receipt+28>    cmp    eax, r10d
   0x55555555553f <lab11_receipt+31>    je     lab11_receipt+48            <lab11_receipt+48>
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab11_receipt`, RVA `0x1520`.

# Walkthrough 12 — Hardware-token surrogate

## Protection question

Recover secret-dependent arithmetic and explain why exposed host implementation is a class-break risk.

## Ghidra decompilation

```c
FUNCTION FUN_00101560
ENTRY 00101560
SIGNATURE undefined FUN_00101560(void)
CALLERS 001020c4, 00102268, 0010120c

uint FUN_00101560(uint param_1,int param_2)

{
  return param_2 * param_1 ^ (param_1 << 0xb | param_1 >> 0x15);
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001560 <lab12_token_oracle>:
    1560:	89 f0                	mov    eax,esi
    1562:	0f af c7             	imul   eax,edi
    1565:	c1 c7 0b             	rol    edi,0xb
    1568:	31 f8                	xor    eax,edi
    156a:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  0x24effc4f
 RCX  0x1234
 RDX  1
 RDI  3
 RSI  0x12345
 R8   0xc
 R9   5
 RSP  0x7fffffffe0f8 —▸ 0x555555555211 (main+433) ◂— add rdx, r11
 RIP  0x555555555560 (lab12_token_oracle) ◂— mov eax, esi
   0x555555555562 <lab12_token_oracle+2>     imul   eax, edi
   0x555555555565 <lab12_token_oracle+5>     rol    edi, 0xb
   0x555555555568 <lab12_token_oracle+8>     xor    eax, edi     EAX => 0x371cf (0x369cf ^ 0x1800)
   0x55555555556a <lab12_token_oracle+10>    ret                                <main+433>
   0x555555555211 <main+433>                 add    rdx, r11              RDX => 0x12a830754 (0x1 + 0x12a830753)
   0x555555555214 <main+436>                 mov    esi, 5                ESI => 5
   0x555555555219 <main+441>                 lea    rdi, [rbp - 0x41]     RDI => 0x7fffffffe11f ◂— 0x4f43004d49414c43 /* 'CLAIM' */
   0x55555555521d <main+445>                 mov    r8d, eax              R8D => 0x371cf
   0x555555555220 <main+448>                 add    r8, rdx               R8 => 0x12a867923 (0x371cf + 0x12a830754)
   0x555555555223 <main+451>                 mov    edx, ebx              EDX => 0x24effc4f
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab12_token_oracle`, RVA `0x1560`.

# Walkthrough 13 — Integrity gate

## Protection question

Recover exact code/data range hash and expected comparison.

## Ghidra decompilation

```c
FUNCTION FUN_00101570
ENTRY 00101570
SIGNATURE undefined FUN_00101570(void)
CALLERS 001020cc, 0010227c, 00101225

bool FUN_00101570(undefined8 param_1,undefined8 param_2,int param_3)

{
  int iVar1;

  iVar1 = FUN_001013a0();
  return iVar1 == param_3;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001570 <lab13_code_integrity>:
    1570:	55                   	push   rbp
    1571:	89 d1                	mov    ecx,edx
    1573:	48 89 e5             	mov    rbp,rsp
    1576:	e8 25 fe ff ff       	call   13a0 <h32>
    157b:	5d                   	pop    rbp
    157c:	39 c8                	cmp    eax,ecx
    157e:	0f 94 c0             	sete   al
    1581:	0f b6 c0             	movzx  eax,al
    1584:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0x371cf
 RBX  0x24effc4f
 RCX  0x1234
 RDX  0x24effc4f
 RDI  0x7fffffffe11f ◂— 0x4f43004d49414c43 /* 'CLAIM' */
 RSI  5
 R8   0x12a867923
 R9   5
 RSP  0x7fffffffe0f8 —▸ 0x55555555522a (main+458) ◂— lea rdi, [rbp - 0x3b]
 RIP  0x555555555570 (lab13_code_integrity) ◂— push rbp
   0x555555555571 <lab13_code_integrity+1>     mov    ecx, edx     ECX => 0x24effc4f
   0x555555555573 <lab13_code_integrity+3>     mov    rbp, rsp     RBP => 0x7fffffffe0f0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555576 <lab13_code_integrity+6>     call   h32                         <h32>
   0x55555555557b <lab13_code_integrity+11>    pop    rbp
   0x55555555557c <lab13_code_integrity+12>    cmp    eax, ecx
   0x55555555557e <lab13_code_integrity+14>    sete   al
   0x555555555581 <lab13_code_integrity+17>    movzx  eax, al
   0x555555555584 <lab13_code_integrity+20>    ret
   0x555555555585                              nop    word ptr [rax + rax]
=> 0x555555555570 <lab13_code_integrity>:	push   rbp
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab13_code_integrity`, RVA `0x1570`.

# Walkthrough 14 — Encrypted configuration

## Protection question

Recover LCG keystream and in-place XOR; locate runtime plaintext window.

## Ghidra decompilation

```c
FUNCTION FUN_00101590
ENTRY 00101590
SIGNATURE undefined FUN_00101590(void)
CALLERS 001020d4, 0010229c, 0010123f

void FUN_00101590(byte *param_1,long param_2,int param_3)

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

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001590 <lab14_config_crypt>:
    1590:	48 85 f6             	test   rsi,rsi
    1593:	74 27                	je     15bc <lab14_config_crypt+0x2c>
    1595:	48 01 fe             	add    rsi,rdi
    1598:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    159f:	00
    15a0:	69 d2 0d 66 19 00    	imul   edx,edx,0x19660d
    15a6:	81 c2 5f f3 6e 3c    	add    edx,0x3c6ef35f
    15ac:	89 d0                	mov    eax,edx
    15ae:	c1 e8 18             	shr    eax,0x18
    15b1:	30 07                	xor    BYTE PTR [rdi],al
    15b3:	48 83 c7 01          	add    rdi,0x1
    15b7:	48 39 fe             	cmp    rsi,rdi
    15ba:	75 e4                	jne    15a0 <lab14_config_crypt+0x10>
    15bc:	c3                   	ret

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  1
 RBX  1
 RCX  0x384
 RDX  7
 RDI  0x7fffffffe125 ◂— 0x1004749464e4f43 /* 'CONFIG' */
 RSI  6
 R8   0x12a867923
 R9   5
 RSP  0x7fffffffe0f8 —▸ 0x555555555244 (main+484) ◂— add rbx, r8
 RIP  0x555555555590 (lab14_config_crypt) ◂— test rsi, rsi
   0x55555555557c <lab13_code_integrity+12>    cmp    eax, ecx
   0x55555555557e <lab13_code_integrity+14>    sete   al
   0x555555555581 <lab13_code_integrity+17>    movzx  eax, al
   0x555555555584 <lab13_code_integrity+20>    ret
   0x555555555585                              nop    word ptr [rax + rax]
   0x555555555593 <lab14_config_crypt+3>     ✘ je     lab14_config_crypt+44       <lab14_config_crypt+44>
   0x555555555595 <lab14_config_crypt+5>       add    rsi, rdi                  RSI => 0x7fffffffe12b (0x6 + 0x7fffffffe125)
   0x555555555598 <lab14_config_crypt+8>       nop    dword ptr [rax + rax]
   0x5555555555a0 <lab14_config_crypt+16>      imul   edx, edx, 0x19660d
   0x5555555555a6 <lab14_config_crypt+22>      add    edx, 0x3c6ef35f           EDX => 0x3d20bdba (0xb1ca5b + 0x3c6ef35f)
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab14_config_crypt`, RVA `0x1590`.

# Walkthrough 15 — Composite license state machine

## Protection question

Recover serial, expiry, feature gates, ordered error codes, and why one branch patch may leave state invalid.

## Ghidra decompilation

```c
FUNCTION FUN_001015c0
ENTRY 001015c0
SIGNATURE undefined FUN_001015c0(void)
CALLERS 001020dc, 001022b0, 0010125c

undefined4
FUN_001015c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined4 param_5,int param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 extraout_EDX;

  iVar1 = FUN_001013e0();
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = FUN_00101480(param_3,param_4,0x15180);
    if (iVar1 == 0) {
      uVar2 = 0xfffffffe;
    }
    else {
      iVar1 = FUN_001014a0(param_5,param_6,iVar1);
      uVar2 = 0xfffffffd;
      if (iVar1 == param_6) {
        uVar2 = extraout_EDX;
      }
    }
  }
  return uVar2;
}
```

## Complete assembly

```asm
reversing-walkthrough-lab/build/ch09/ch09_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000015c0 <lab15_composite>:
    15c0:	55                   	push   rbp
    15c1:	48 89 e5             	mov    rbp,rsp
    15c4:	41 56                	push   r14
    15c6:	49 89 ce             	mov    r14,rcx
    15c9:	41 55                	push   r13
    15cb:	45 89 c5             	mov    r13d,r8d
    15ce:	41 54                	push   r12
    15d0:	49 89 d4             	mov    r12,rdx
    15d3:	53                   	push   rbx
    15d4:	44 89 cb             	mov    ebx,r9d
    15d7:	e8 04 fe ff ff       	call   13e0 <lab01_serial_checksum>
    15dc:	85 c0                	test   eax,eax
    15de:	74 38                	je     1618 <lab15_composite+0x58>
    15e0:	ba 80 51 01 00       	mov    edx,0x15180
    15e5:	4c 89 f6             	mov    rsi,r14
    15e8:	4c 89 e7             	mov    rdi,r12
    15eb:	e8 90 fe ff ff       	call   1480 <lab05_expiry>
    15f0:	89 c2                	mov    edx,eax
    15f2:	85 c0                	test   eax,eax
    15f4:	74 2a                	je     1620 <lab15_composite+0x60>
    15f6:	89 de                	mov    esi,ebx
    15f8:	44 89 ef             	mov    edi,r13d
    15fb:	e8 a0 fe ff ff       	call   14a0 <lab06_features>
    1600:	39 d8                	cmp    eax,ebx
    1602:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    1607:	0f 44 c2             	cmove  eax,edx
    160a:	5b                   	pop    rbx
    160b:	41 5c                	pop    r12
    160d:	41 5d                	pop    r13
    160f:	41 5e                	pop    r14
    1611:	5d                   	pop    rbp
    1612:	c3                   	ret
    1613:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1618:	b8 ff ff ff ff       	mov    eax,0xffffffff
    161d:	eb eb                	jmp    160a <lab15_composite+0x4a>
    161f:	90                   	nop
    1620:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1625:	eb e3                	jmp    160a <lab15_composite+0x4a>

Disassembly of section .fini:
```

## pwndbg state

```text
RAX  0xdb
 RBX  0x12a867924
 RCX  0x384
 RDX  0x3e8
 RDI  0x555555556004 ◂— 0x6300524f544e454d /* 'MENTOR' */
 RSI  0x1587a9bf
 R8   7
 R9   5
 RSP  0x7fffffffe0f8 —▸ 0x555555555261 (main+513) ◂— lea rdi, [rip + 0xda3]
 RIP  0x5555555555c0 (lab15_composite) ◂— push rbp
   0x5555555555c1 <lab15_composite+1>     mov    rbp, rsp      RBP => 0x7fffffffe0f0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555555c4 <lab15_composite+4>     push   r14
   0x5555555555c6 <lab15_composite+6>     mov    r14, rcx      R14 => 0x384
   0x5555555555c9 <lab15_composite+9>     push   r13
   0x5555555555cb <lab15_composite+11>    mov    r13d, r8d     R13D => 7
   0x5555555555ce <lab15_composite+14>    push   r12
   0x5555555555d0 <lab15_composite+16>    mov    r12, rdx      R12 => 0x3e8
   0x5555555555d3 <lab15_composite+19>    push   rbx
   0x5555555555d4 <lab15_composite+20>    mov    ebx, r9d      EBX => 5
   0x5555555555d7 <lab15_composite+23>    call   lab01_serial_checksum       <lab01_serial_checksum>
```

## Architecture analysis

1. Identify the protected asset and enforcement decision.
2. Recover all client-side inputs, transforms, secrets, and error states.
3. Determine whether compromise is per-user or a class break.
4. Evaluate offline, availability, privacy, support, and false-reject tradeoffs.
5. Replace toy primitives with appropriate signatures/server/hardware boundaries in a real design.

**Recovered model:** `lab15_composite`, RVA `0x15c0`.

# Twenty Practice Questions

1. What is class break?
2. Why public-key license verification?
3. What makes time check safe?
4. How prevent replay?
5. What does device binding cost?
6. Feature-mask invariant?
7. Why is watermark not access control?
8. What is receipt canonicalization risk?
9. Why not embed symmetric master secret?
10. What does SaaS change?
11. What is an activation threat model?
12. How test quota safely?
13. Why inspect runtime config plaintext?
14. What does integrity hash not guarantee?
15. How identify composite gates?
16. What is a false reject?
17. Why use individualization?
18. What is trusted hardware boundary?
19. Why separate policy from mechanism?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** One recovered secret/algorithm defeats many instances.
4. Explain scale, usability, and recovery tradeoffs.

## 2. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Clients hold public verification key, not private issuance key.
4. Explain scale, usability, and recovery tradeoffs.

## 3. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** now>=issued then subtraction against duration avoids issued+duration overflow.
4. Explain scale, usability, and recovery tradeoffs.

## 4. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Fresh unpredictable nonce plus server/device state and one-time acceptance.
4. Explain scale, usability, and recovery tradeoffs.

## 5. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Hardware changes, privacy, collisions, spoofing, and support burden.
4. Explain scale, usability, and recovery tradeoffs.

## 6. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Every requested bit must be present in licensed mask.
4. Explain scale, usability, and recovery tradeoffs.

## 7. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** It supports attribution/deterrence after distribution.
4. Explain scale, usability, and recovery tradeoffs.

## 8. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Signer/verifier must hash exactly the same unambiguous bytes.
4. Explain scale, usability, and recovery tradeoffs.

## 9. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Client compromise extracts it and creates a class break.
4. Explain scale, usability, and recovery tradeoffs.

## 10. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Moves valuable operation server-side but introduces account/API/server risks.
4. Explain scale, usability, and recovery tradeoffs.

## 11. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Asset, adversary, access, scale, offline need, privacy, availability, accepted cost.
4. Explain scale, usability, and recovery tradeoffs.

## 12. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** used at/below/above limit and requested 0, remaining, remaining+1.
4. Explain scale, usability, and recovery tradeoffs.

## 13. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Encrypted bytes must be decoded before consumption, creating an observation window.
4. Explain scale, usability, and recovery tradeoffs.

## 14. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Authenticity without a protected key/signature and safety of the code.
4. Explain scale, usability, and recovery tradeoffs.

## 15. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Ordered calls/branches and distinct return codes tied to each condition.
4. Explain scale, usability, and recovery tradeoffs.

## 16. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Valid user denied due to clock/device/service/protection failure.
4. Explain scale, usability, and recovery tradeoffs.

## 17. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Reduces value and scale of one bypass.
4. Explain scale, usability, and recovery tradeoffs.

## 18. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Nonexportable key/operation, but host protocol/result checking still exposed.
4. Explain scale, usability, and recovery tradeoffs.

## 19. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Legal/business rule and technical enforcement have different guarantees/costs.
4. Explain scale, usability, and recovery tradeoffs.

## 20. Solution

1. State asset/adversary/trust boundary.
2. Trace decision and secret placement.
3. **Answer:** Threat-model and reverse all fifteen gates, then design a more robust lawful architecture.
4. Explain scale, usability, and recovery tradeoffs.


Return to [[Chapter 09 - Piracy and Copy Protection]].
