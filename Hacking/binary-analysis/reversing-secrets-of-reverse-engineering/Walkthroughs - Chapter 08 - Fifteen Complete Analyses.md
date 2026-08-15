# Chapter 8 — Fifteen Complete Inert Malware-Reversing Walkthroughs

> [!safety and evidence]
> These are fifteen separate executable specimens, each independently compiled, stripped, analyzed by Ghidra, and traced under pwndbg. They emulate one malware-relevant behavior with inert data. There is no live C2, propagation, persistence modification, credential access, file encryption, or deletion.


# Walkthrough 01 — Persistence-plan construction

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab01_persistence_plan(const char*user,char*out,size_t cap){return snprintf(out,cap,"SIMULATED startup:%s/.config/mentor-agent",user);}
int main(void){char out[128];int r=lab01_persistence_plan("/lab",out,sizeof out);printf("%d %s\n",r,out);return 0;}
```

## Actual baseline output

```text
43 SIMULATED startup:/lab/.config/mentor-agent
```

## Ghidra stripped analysis

Recover path formatting, bounded snprintf contract, and the fact that the specimen reports a plan without creating artifacts.

```c
FUNCTION FUN_001011c0
ENTRY 001011c0
SIGNATURE undefined FUN_001011c0(void)
CALLERS 00102064, 001020d0, 0010108b

void FUN_001011c0(undefined8 param_1,char *param_2,size_t param_3)

{
  snprintf(param_2,param_3,"SIMULATED startup:%s/.config/mentor-agent",param_1);
  return;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/01_persistence_plan_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011c0 <lab01_persistence_plan>:
    11c0:	48 89 f9             	mov    rcx,rdi
    11c3:	31 c0                	xor    eax,eax
    11c5:	48 89 f7             	mov    rdi,rsi
    11c8:	48 89 d6             	mov    rsi,rdx
    11cb:	48 8d 15 36 0e 00 00 	lea    rdx,[rip+0xe36]        # 2008 <_IO_stdin_used+0x8>
    11d2:	e9 79 fe ff ff       	jmp    1050 <snprintf@plt>

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab01_persistence_plan
=== PWNDBG_EVIDENCE lab01_persistence_plan ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe278 —▸ 0x7fffffffe65f ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555160 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x80
 RDI  0x555555556032 ◂— 0x2064250062616c2f /* '/lab' */
 RSI  0x7fffffffe0a0 ◂— 0x40 /* '@' */
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe098 —▸ 0x555555555090 (main+48) ◂— lea rdx, [rbp - 0x90]
 RIP  0x5555555551c0 (lab01_persistence_plan) ◂— mov rcx, rdi
   0x5555555551c3 <lab01_persistence_plan+3>     xor    eax, eax               EAX => 0
   0x5555555551c5 <lab01_persistence_plan+5>     mov    rdi, rsi               RDI => 0x7fffffffe0a0 ◂— 0x40 /* '@' */
   0x5555555551c8 <lab01_persistence_plan+8>     mov    rsi, rdx               RSI => 0x80
   0x5555555551cb <lab01_persistence_plan+11>    lea    rdx, [rip + 0xe36]     RDX => 0x555555556008 ◂— 0x4554414c554d4953 ('SIMULATE')
   0x5555555551d2 <lab01_persistence_plan+18>    jmp    snprintf@plt                <snprintf@plt>
   0x555555555050 <snprintf@plt>                 jmp    qword ptr [rip + 0x2fba]    <snprintf@plt+6>
   0x555555555056 <snprintf@plt+6>               push   2
   0x55555555505b <snprintf@plt+11>              jmp    0x555555555020              <0x555555555020>
   0x555555555020                                push   qword ptr [rip + 0x2fca]
   0x555555555026                                jmp    qword ptr [rip + 0x2fcc]    <0x7ffff7fd5620>
=> 0x5555555551c0 <lab01_persistence_plan>:	mov    rcx,rdi
   0x5555555551c3 <lab01_persistence_plan+3>:	xor    eax,eax
   0x5555555551c5 <lab01_persistence_plan+5>:	mov    rdi,rsi
   0x5555555551c8 <lab01_persistence_plan+8>:	mov    rsi,rdx
   0x5555555551cb <lab01_persistence_plan+11>:	lea    rdx,[rip+0xe36]        # 0x555555556008
   0x5555555551d2 <lab01_persistence_plan+18>:	jmp    0x555555555050 <snprintf@plt>
   0x5555555551d7:	add    bl,dh
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab01_persistence_plan` at RVA `0x11c0` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 02 — Configuration decoder

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab02_config_decoder(uint8_t*p,size_t n,uint32_t k){uint32_t h=0;for(size_t i=0;i<n;i++){k=k*1103515245u+12345u;p[i]^=(uint8_t)(k>>16);h=h*33u+p[i];}return h;}
int main(void){uint8_t p[]={0x6d,0x65,0x6e,0x74,0x6f,0x72};printf("%u\n",lab02_config_decoder(p,sizeof p,7));return 0;}
```

## Actual baseline output

```text
91319007
```

## Ghidra stripped analysis

Recover LCG state, XOR transform, in-place buffer update, and rolling plaintext hash.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 0010202c, 00102098, 001010b5

int FUN_00101200(byte *param_1,long param_2,int param_3)

{
  int iVar1;
  byte bVar2;
  byte *pbVar3;
  byte *pbVar4;

  if (param_2 != 0) {
    iVar1 = 0;
    pbVar3 = param_1;
    do {
      pbVar4 = pbVar3 + 1;
      param_3 = param_3 * 0x41c64e6d + 0x3039;
      bVar2 = (byte)((uint)param_3 >> 0x10) ^ *pbVar3;
      *pbVar3 = bVar2;
      iVar1 = iVar1 * 0x21 + (uint)bVar2;
      pbVar3 = pbVar4;
    } while (param_1 + param_2 != pbVar4);
    return iVar1;
  }
  return 0;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/02_config_decoder_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab02_config_decoder>:
    1200:	48 85 f6             	test   rsi,rsi
    1203:	74 6b                	je     1270 <lab02_config_decoder+0x70>
    1205:	48 01 fe             	add    rsi,rdi
    1208:	31 c0                	xor    eax,eax
    120a:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1211:	00 00 00
    1214:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    121b:	00 00 00 00
    121f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1226:	00 00 00 00
    122a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1231:	00 00 00 00
    1235:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    123c:	00 00 00 00
    1240:	69 d2 6d 4e c6 41    	imul   edx,edx,0x41c64e6d
    1246:	41 89 c0             	mov    r8d,eax
    1249:	48 83 c7 01          	add    rdi,0x1
    124d:	41 c1 e0 05          	shl    r8d,0x5
    1251:	44 01 c0             	add    eax,r8d
    1254:	81 c2 39 30 00 00    	add    edx,0x3039
    125a:	89 d1                	mov    ecx,edx
    125c:	c1 e9 10             	shr    ecx,0x10
    125f:	32 4f ff             	xor    cl,BYTE PTR [rdi-0x1]
    1262:	88 4f ff             	mov    BYTE PTR [rdi-0x1],cl
    1265:	0f b6 c9             	movzx  ecx,cl
    1268:	01 c8                	add    eax,ecx
    126a:	48 39 fe             	cmp    rsi,rdi
    126d:	75 d1                	jne    1240 <lab02_config_decoder+0x40>
    126f:	c3                   	ret
    1270:	31 c0                	xor    eax,eax
    1272:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab02_config_decoder
=== PWNDBG_EVIDENCE lab02_config_decoder ===
 RAX  0x726f
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555190 (__do_global_dtors_aux) ◂— endbr64
 RDX  7
 RDI  0x7fffffffe132 ◂— 0x8200726f746e656d /* 'mentor' */
 RSI  6
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe128 —▸ 0x5555555550ba (main+58) ◂— lea rdi, [rip + 0xf43]
 RIP  0x555555555200 (lab02_config_decoder) ◂— test rsi, rsi
   0x555555555203 <lab02_config_decoder+3>   ✘ je     lab02_config_decoder+112    <lab02_config_decoder+112>
   0x555555555205 <lab02_config_decoder+5>     add    rsi, rdi                 RSI => 0x7fffffffe138 (0x6 + 0x7fffffffe132)
   0x555555555208 <lab02_config_decoder+8>     xor    eax, eax                 EAX => 0
   0x55555555520a <lab02_config_decoder+10>    nop    word ptr [rax + rax]
   0x555555555214 <lab02_config_decoder+20>    nop    word ptr [rax + rax]
   0x55555555521f <lab02_config_decoder+31>    nop    word ptr [rax + rax]
   0x55555555522a <lab02_config_decoder+42>    nop    word ptr [rax + rax]
   0x555555555235 <lab02_config_decoder+53>    nop    word ptr [rax + rax]
   0x555555555240 <lab02_config_decoder+64>    imul   edx, edx, 0x41c64e6d
   0x555555555246 <lab02_config_decoder+70>    mov    r8d, eax                 R8D => 0
=> 0x555555555200 <lab02_config_decoder>:	test   rsi,rsi
   0x555555555203 <lab02_config_decoder+3>:	je     0x555555555270 <lab02_config_decoder+112>
   0x555555555205 <lab02_config_decoder+5>:	add    rsi,rdi
   0x555555555208 <lab02_config_decoder+8>:	xor    eax,eax
   0x55555555520a <lab02_config_decoder+10>:	cs nop WORD PTR [rax+rax*1+0x0]
   0x555555555214 <lab02_config_decoder+20>:	data16 cs nop WORD PTR [rax+rax*1+0x0]
   0x55555555521f <lab02_config_decoder+31>:	data16 cs nop WORD PTR [rax+rax*1+0x0]
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab02_config_decoder` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 03 — DGA-like .invalid generator

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab03_invalid_dga(uint32_t day,char*out,size_t cap){uint32_t x=day^0xa5c31u;char name[17];for(int i=0;i<16;i++){x^=x<<13;x^=x>>17;x^=x<<5;name[i]='a'+x%26;}name[16]=0;snprintf(out,cap,"%s.invalid",name);return x;}
int main(void){char out[64];printf("%u %s\n",lab03_invalid_dga(20260809,out,sizeof out),out);return 0;}
```

## Actual baseline output

```text
214048484 oljqehrlbnfgxdoa.invalid
```

## Ghidra stripped analysis

Recover seed/day mixing, xorshift recurrence, modulo-26 labels, fixed length, and reserved non-routable suffix.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 0010203c, 001020a8, 001010a3

uint FUN_00101200(uint param_1,char *param_2,size_t param_3)

{
  char *pcVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  char local_38 [16];
  char local_28 [8];
  long local_20;

  param_1 = param_1 ^ 0xa5c31;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  pcVar1 = local_38;
  do {
    pcVar2 = pcVar1 + 1;
    param_1 = param_1 << 0xd ^ param_1;
    param_1 = param_1 >> 0x11 ^ param_1;
    param_1 = param_1 << 5 ^ param_1;
    *pcVar1 = (char)param_1 + (char)(param_1 / 0x1a) * -0x1a + 'a';
    pcVar1 = pcVar2;
  } while (local_28 != pcVar2);
  local_28[0] = '\0';
  snprintf(param_2,param_3,"%s.invalid");
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return param_1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/03_invalid_dga_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab03_invalid_dga>:
    1200:	55                   	push   rbp
    1201:	48 89 e5             	mov    rbp,rsp
    1204:	53                   	push   rbx
    1205:	89 fb                	mov    ebx,edi
    1207:	48 89 f7             	mov    rdi,rsi
    120a:	48 8d 4d d0          	lea    rcx,[rbp-0x30]
    120e:	81 f3 31 5c 0a 00    	xor    ebx,0xa5c31
    1214:	4c 8d 4d e0          	lea    r9,[rbp-0x20]
    1218:	48 89 ce             	mov    rsi,rcx
    121b:	48 83 ec 28          	sub    rsp,0x28
    121f:	64 4c 8b 04 25 28 00 	mov    r8,QWORD PTR fs:0x28
    1226:	00 00
    1228:	4c 89 45 e8          	mov    QWORD PTR [rbp-0x18],r8
    122c:	49 89 d0             	mov    r8,rdx
    122f:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1235:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    123c:	00 00 00 00
    1240:	89 da                	mov    edx,ebx
    1242:	48 83 c6 01          	add    rsi,0x1
    1246:	c1 e2 0d             	shl    edx,0xd
    1249:	31 da                	xor    edx,ebx
    124b:	89 d0                	mov    eax,edx
    124d:	c1 e8 11             	shr    eax,0x11
    1250:	31 d0                	xor    eax,edx
    1252:	89 c3                	mov    ebx,eax
    1254:	c1 e3 05             	shl    ebx,0x5
    1257:	31 c3                	xor    ebx,eax
    1259:	89 d8                	mov    eax,ebx
    125b:	89 da                	mov    edx,ebx
    125d:	48 69 c0 4f ec c4 4e 	imul   rax,rax,0x4ec4ec4f
    1264:	48 c1 e8 23          	shr    rax,0x23
    1268:	6b c0 1a             	imul   eax,eax,0x1a
    126b:	29 c2                	sub    edx,eax
    126d:	8d 42 61             	lea    eax,[rdx+0x61]
    1270:	88 46 ff             	mov    BYTE PTR [rsi-0x1],al
    1273:	49 39 f1             	cmp    r9,rsi
    1276:	75 c8                	jne    1240 <lab03_invalid_dga+0x40>
    1278:	31 c0                	xor    eax,eax
    127a:	48 8d 15 83 0d 00 00 	lea    rdx,[rip+0xd83]        # 2004 <_IO_stdin_used+0x4>
    1281:	4c 89 c6             	mov    rsi,r8
    1284:	c6 45 e0 00          	mov    BYTE PTR [rbp-0x20],0x0
    1288:	e8 c3 fd ff ff       	call   1050 <snprintf@plt>
    128d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
    1291:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1298:	00 00
    129a:	75 08                	jne    12a4 <lab03_invalid_dga+0xa4>
    129c:	89 d8                	mov    eax,ebx
    129e:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    12a2:	c9                   	leave
    12a3:	c3                   	ret
    12a4:	e8 87 fd ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab03_invalid_dga
=== PWNDBG_EVIDENCE lab03_invalid_dga ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe288 —▸ 0x7fffffffe669 ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555180 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x40
 RDI  0x13527c9
 RSI  0x7fffffffe0f0 ◂— 0x2200000
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0e8 —▸ 0x5555555550a8 (main+40) ◂— lea rdx, [rbp - 0x50]
 RIP  0x555555555200 (lab03_invalid_dga) ◂— push rbp
   0x555555555201 <lab03_invalid_dga+1>     mov    rbp, rsp                    RBP => 0x7fffffffe0e0 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x555555555204 <lab03_invalid_dga+4>     push   rbx
   0x555555555205 <lab03_invalid_dga+5>     mov    ebx, edi                    EBX => 0x13527c9
   0x555555555207 <lab03_invalid_dga+7>     mov    rdi, rsi                    RDI => 0x7fffffffe0f0 ◂— 0x2200000
   0x55555555520a <lab03_invalid_dga+10>    lea    rcx, [rbp - 0x30]           RCX => 0x7fffffffe0b0 ◂— 0x40 /* '@' */
   0x55555555520e <lab03_invalid_dga+14>    xor    ebx, 0xa5c31                EBX => 0x13f7bf8 (0x13527c9 ^ 0xa5c31)
   0x555555555214 <lab03_invalid_dga+20>    lea    r9, [rbp - 0x20]            R9 => 0x7fffffffe0c0 ◂— 0x100
   0x555555555218 <lab03_invalid_dga+24>    mov    rsi, rcx                    RSI => 0x7fffffffe0b0 ◂— 0x40 /* '@' */
   0x55555555521b <lab03_invalid_dga+27>    sub    rsp, 0x28                   RSP => 0x7fffffffe0b0 {name} (0x7fffffffe0d8 - 0x28)
   0x55555555521f <lab03_invalid_dga+31>    mov    r8, qword ptr fs:[0x28]     R8, [0x7ffff7f7f768] => 0xc525d8228c64e400
=> 0x555555555200 <lab03_invalid_dga>:	push   rbp
   0x555555555201 <lab03_invalid_dga+1>:	mov    rbp,rsp
   0x555555555204 <lab03_invalid_dga+4>:	push   rbx
   0x555555555205 <lab03_invalid_dga+5>:	mov    ebx,edi
   0x555555555207 <lab03_invalid_dga+7>:	mov    rdi,rsi
   0x55555555520a <lab03_invalid_dga+10>:	lea    rcx,[rbp-0x30]
   0x55555555520e <lab03_invalid_dga+14>:	xor    ebx,0xa5c31
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab03_invalid_dga` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 04 — IRC command parser

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab04_irc_parser(const char*s,char*cmd,size_t cap){const char*p=strstr(s," PRIVMSG ");if(!p)return-1;p=strchr(p,':');if(!p)return-2;p++;size_t n=strcspn(p," \r\n");if(n+1>cap)return-3;memcpy(cmd,p,n);cmd[n]=0;return(int)n;}
int main(void){char c[32];printf("%d %s\n",lab04_irc_parser(":srv PRIVMSG #lab :status",c,sizeof c),c);return 0;}
```

## Actual baseline output

```text
6 status
```

## Ghidra stripped analysis

Recover PRIVMSG search, colon boundary, token length, capacity check, copy, and error codes.

```c
FUNCTION FUN_001011f0
ENTRY 001011f0
SIGNATURE undefined FUN_001011f0(void)
CALLERS 00102058, 001020c0, 001010b5

ulong FUN_001011f0(char *param_1,void *param_2,ulong param_3)

{
  char *pcVar1;
  size_t __n;
  ulong uVar2;

  pcVar1 = strstr(param_1," PRIVMSG ");
  if (pcVar1 == (char *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    pcVar1 = strchr(pcVar1,0x3a);
    if (pcVar1 == (char *)0x0) {
      uVar2 = 0xfffffffe;
    }
    else {
      __n = strcspn(pcVar1 + 1," \r\n");
      if (param_3 < __n + 1) {
        uVar2 = 0xfffffffd;
      }
      else {
        memcpy(param_2,pcVar1 + 1,__n);
        *(undefined1 *)((long)param_2 + __n) = 0;
        uVar2 = __n & 0xffffffff;
      }
    }
  }
  return uVar2;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/04_irc_parser_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011f0 <lab04_irc_parser>:
    11f0:	55                   	push   rbp
    11f1:	48 89 e5             	mov    rbp,rsp
    11f4:	48 83 ec 20          	sub    rsp,0x20
    11f8:	4c 89 6d f0          	mov    QWORD PTR [rbp-0x10],r13
    11fc:	49 89 f5             	mov    r13,rsi
    11ff:	48 8d 35 fe 0d 00 00 	lea    rsi,[rip+0xdfe]        # 2004 <_IO_stdin_used+0x4>
    1206:	4c 89 75 f8          	mov    QWORD PTR [rbp-0x8],r14
    120a:	49 89 d6             	mov    r14,rdx
    120d:	e8 6e fe ff ff       	call   1080 <strstr@plt>
    1212:	48 85 c0             	test   rax,rax
    1215:	74 7f                	je     1296 <lab04_irc_parser+0xa6>
    1217:	be 3a 00 00 00       	mov    esi,0x3a
    121c:	48 89 c7             	mov    rdi,rax
    121f:	e8 1c fe ff ff       	call   1040 <strchr@plt>
    1224:	48 85 c0             	test   rax,rax
    1227:	74 66                	je     128f <lab04_irc_parser+0x9f>
    1229:	4c 89 65 e8          	mov    QWORD PTR [rbp-0x18],r12
    122d:	4c 8d 60 01          	lea    r12,[rax+0x1]
    1231:	48 8d 35 d6 0d 00 00 	lea    rsi,[rip+0xdd6]        # 200e <_IO_stdin_used+0xe>
    1238:	4c 89 e7             	mov    rdi,r12
    123b:	48 89 5d e0          	mov    QWORD PTR [rbp-0x20],rbx
    123f:	e8 1c fe ff ff       	call   1060 <strcspn@plt>
    1244:	48 89 c3             	mov    rbx,rax
    1247:	48 8d 40 01          	lea    rax,[rax+0x1]
    124b:	49 39 c6             	cmp    r14,rax
    124e:	72 30                	jb     1280 <lab04_irc_parser+0x90>
    1250:	48 89 da             	mov    rdx,rbx
    1253:	4c 89 e6             	mov    rsi,r12
    1256:	4c 89 ef             	mov    rdi,r13
    1259:	e8 12 fe ff ff       	call   1070 <memcpy@plt>
    125e:	41 c6 44 1d 00 00    	mov    BYTE PTR [r13+rbx*1+0x0],0x0
    1264:	89 d8                	mov    eax,ebx
    1266:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    126a:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    126e:	4c 8b 6d f0          	mov    r13,QWORD PTR [rbp-0x10]
    1272:	4c 8b 75 f8          	mov    r14,QWORD PTR [rbp-0x8]
    1276:	c9                   	leave
    1277:	c3                   	ret
    1278:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    127f:	00
    1280:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
    1284:	4c 8b 65 e8          	mov    r12,QWORD PTR [rbp-0x18]
    1288:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    128d:	eb df                	jmp    126e <lab04_irc_parser+0x7e>
    128f:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    1294:	eb d8                	jmp    126e <lab04_irc_parser+0x7e>
    1296:	b8 ff ff ff ff       	mov    eax,0xffffffff
    129b:	eb d1                	jmp    126e <lab04_irc_parser+0x7e>

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab04_irc_parser
=== PWNDBG_EVIDENCE lab04_irc_parser ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe288 —▸ 0x7fffffffe66b ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555190 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x20
 RDI  0x555555556012 ◂— 0x495250207672733a (':srv PRI')
 RSI  0x7fffffffe110 ◂— 0
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe108 —▸ 0x5555555550ba (main+42) ◂— lea rdx, [rbp - 0x30]
 RIP  0x5555555551f0 (lab04_irc_parser) ◂— push rbp
   0x5555555551f1 <lab04_irc_parser+1>     mov    rbp, rsp                        RBP => 0x7fffffffe100 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x5555555551f4 <lab04_irc_parser+4>     sub    rsp, 0x20                       RSP => 0x7fffffffe0e0 (0x7fffffffe100 - 0x20)
   0x5555555551f8 <lab04_irc_parser+8>     mov    qword ptr [rbp - 0x10], r13     [0x7fffffffe0f0] <= 1
   0x5555555551fc <lab04_irc_parser+12>    mov    r13, rsi                        R13 => 0x7fffffffe110 ◂— 0
   0x5555555551ff <lab04_irc_parser+15>    lea    rsi, [rip + 0xdfe]              RSI => 0x555555556004 ◂— ' PRIVMSG '
   0x555555555206 <lab04_irc_parser+22>    mov    qword ptr [rbp - 8], r14        [0x7fffffffe0f8] <= 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— ...
   0x55555555520a <lab04_irc_parser+26>    mov    r14, rdx                        R14 => 0x20
   0x55555555520d <lab04_irc_parser+29>    call   strstr@plt                  <strstr@plt>
   0x555555555212 <lab04_irc_parser+34>    test   rax, rax
   0x555555555215 <lab04_irc_parser+37>    je     lab04_irc_parser+166        <lab04_irc_parser+166>
=> 0x5555555551f0 <lab04_irc_parser>:	push   rbp
   0x5555555551f1 <lab04_irc_parser+1>:	mov    rbp,rsp
   0x5555555551f4 <lab04_irc_parser+4>:	sub    rsp,0x20
   0x5555555551f8 <lab04_irc_parser+8>:	mov    QWORD PTR [rbp-0x10],r13
   0x5555555551fc <lab04_irc_parser+12>:	mov    r13,rsi
   0x5555555551ff <lab04_irc_parser+15>:	lea    rsi,[rip+0xdfe]        # 0x555555556004
   0x555555555206 <lab04_irc_parser+22>:	mov    QWORD PTR [rbp-0x8],r14
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab04_irc_parser` at RVA `0x11f0` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 05 — SOCKS-like state machine

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab05_proxy_state(const uint8_t*p,size_t n){enum{V,METHOD,ADDR,PORT,DONE}st=V;uint32_t addr=0;uint16_t port=0;for(size_t i=0;i<n;i++){switch(st){case V:if(p[i]!=4)return-1;st=METHOD;break;case METHOD:if(p[i]!=1)return-2;st=PORT;break;case PORT:port=(port<<8)|p[i];if(i==3)st=ADDR;break;case ADDR:addr=(addr<<8)|p[i];if(i==7)st=DONE;break;default:break;}}return st==DONE?(int)((addr^port)&0x7fffffff):-3;}
int main(void){uint8_t p[]={4,1,0x1f,0x90,127,0,0,1};printf("%d\n",lab05_proxy_state(p,sizeof p));return 0;}
```

## Actual baseline output

```text
2130714513
```

## Ghidra stripped analysis

Recover version/method, network-order port/address accumulation, terminal state, and no actual sockets.

```c
FUNCTION FUN_001011b0
ENTRY 001011b0
SIGNATURE undefined FUN_001011b0(void)
CALLERS 0010202c, 00102098, 0010107c

uint FUN_001011b0(char *param_1,long param_2)

{
  byte *pbVar1;
  uint uVar2;
  uint uVar3;
  long lVar4;

  if (param_2 != 0) {
    if (*param_1 != '\x04') {
      return 0xffffffff;
    }
    if (param_2 != 1) {
      if (param_1[1] != '\x01') {
        return 0xfffffffe;
      }
      if (param_2 != 2) {
        lVar4 = 2;
        uVar2 = 0;
        do {
          pbVar1 = (byte *)(param_1 + lVar4);
          if (lVar4 == 3) {
            lVar4 = 4;
            uVar3 = 0;
            if (param_2 == 4) {
              return 0xfffffffd;
            }
            do {
              uVar3 = uVar3 << 8 | (uint)(byte)param_1[lVar4];
              if (lVar4 == 7) {
                return (((uint)*pbVar1 | uVar2 << 8) ^ uVar3) & 0x7fffffff;
              }
              lVar4 = lVar4 + 1;
            } while (param_2 != lVar4);
            return 0xfffffffd;
          }
          lVar4 = 3;
          uVar2 = (uint)*pbVar1;
        } while (param_2 != 3);
      }
    }
  }
  return 0xfffffffd;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/05_proxy_state_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011b0 <lab05_proxy_state>:
    11b0:	48 85 f6             	test   rsi,rsi
    11b3:	74 3a                	je     11ef <lab05_proxy_state+0x3f>
    11b5:	80 3f 04             	cmp    BYTE PTR [rdi],0x4
    11b8:	75 79                	jne    1233 <lab05_proxy_state+0x83>
    11ba:	48 83 fe 01          	cmp    rsi,0x1
    11be:	74 2f                	je     11ef <lab05_proxy_state+0x3f>
    11c0:	80 7f 01 01          	cmp    BYTE PTR [rdi+0x1],0x1
    11c4:	75 73                	jne    1239 <lab05_proxy_state+0x89>
    11c6:	48 83 fe 02          	cmp    rsi,0x2
    11ca:	74 23                	je     11ef <lab05_proxy_state+0x3f>
    11cc:	b9 02 00 00 00       	mov    ecx,0x2
    11d1:	31 c0                	xor    eax,eax
    11d3:	0f b6 14 0f          	movzx  edx,BYTE PTR [rdi+rcx*1]
    11d7:	c1 e0 08             	shl    eax,0x8
    11da:	09 c2                	or     edx,eax
    11dc:	89 d0                	mov    eax,edx
    11de:	48 83 f9 03          	cmp    rcx,0x3
    11e2:	74 14                	je     11f8 <lab05_proxy_state+0x48>
    11e4:	b9 03 00 00 00       	mov    ecx,0x3
    11e9:	48 83 fe 03          	cmp    rsi,0x3
    11ed:	75 e4                	jne    11d3 <lab05_proxy_state+0x23>
    11ef:	b8 fd ff ff ff       	mov    eax,0xfffffffd
    11f4:	c3                   	ret
    11f5:	0f 1f 00             	nop    DWORD PTR [rax]
    11f8:	b8 04 00 00 00       	mov    eax,0x4
    11fd:	31 c9                	xor    ecx,ecx
    11ff:	48 83 fe 04          	cmp    rsi,0x4
    1203:	74 ea                	je     11ef <lab05_proxy_state+0x3f>
    1205:	44 0f b6 04 07       	movzx  r8d,BYTE PTR [rdi+rax*1]
    120a:	c1 e1 08             	shl    ecx,0x8
    120d:	44 09 c1             	or     ecx,r8d
    1210:	48 83 f8 07          	cmp    rax,0x7
    1214:	74 12                	je     1228 <lab05_proxy_state+0x78>
    1216:	48 83 c0 01          	add    rax,0x1
    121a:	48 39 c6             	cmp    rsi,rax
    121d:	75 e6                	jne    1205 <lab05_proxy_state+0x55>
    121f:	eb ce                	jmp    11ef <lab05_proxy_state+0x3f>
    1221:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1228:	0f b7 c2             	movzx  eax,dx
    122b:	31 c8                	xor    eax,ecx
    122d:	25 ff ff ff 7f       	and    eax,0x7fffffff
    1232:	c3                   	ret
    1233:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1238:	c3                   	ret
    1239:	b8 fe ff ff ff       	mov    eax,0xfffffffe
    123e:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab05_proxy_state
=== PWNDBG_EVIDENCE lab05_proxy_state ===
 RAX  0x100007f901f0104
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555150 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe288 —▸ 0x7fffffffe669 ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x7fffffffe130 ◂— 0x100007f901f0104
 RSI  8
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe128 —▸ 0x555555555081 (main+49) ◂— lea rdi, [rip + 0xf7c]
 RIP  0x5555555551b0 (lab05_proxy_state) ◂— test rsi, rsi
   0x5555555551b3 <lab05_proxy_state+3>   ✘ je     lab05_proxy_state+63        <lab05_proxy_state+63>
   0x5555555551b5 <lab05_proxy_state+5>     cmp    byte ptr [rdi], 4     4 - 4     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555551b8 <lab05_proxy_state+8>   ✘ jne    lab05_proxy_state+131       <lab05_proxy_state+131>
   0x5555555551ba <lab05_proxy_state+10>    cmp    rsi, 1                8 - 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x5555555551be <lab05_proxy_state+14>  ✘ je     lab05_proxy_state+63        <lab05_proxy_state+63>
   0x5555555551c0 <lab05_proxy_state+16>    cmp    byte ptr [rdi + 1], 1     1 - 1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555551c4 <lab05_proxy_state+20>  ✘ jne    lab05_proxy_state+137       <lab05_proxy_state+137>
   0x5555555551c6 <lab05_proxy_state+22>    cmp    rsi, 2                    8 - 2     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555551ca <lab05_proxy_state+26>  ✘ je     lab05_proxy_state+63        <lab05_proxy_state+63>
   0x5555555551cc <lab05_proxy_state+28>    mov    ecx, 2                    ECX => 2
=> 0x5555555551b0 <lab05_proxy_state>:	test   rsi,rsi
   0x5555555551b3 <lab05_proxy_state+3>:	je     0x5555555551ef <lab05_proxy_state+63>
   0x5555555551b5 <lab05_proxy_state+5>:	cmp    BYTE PTR [rdi],0x4
   0x5555555551b8 <lab05_proxy_state+8>:	jne    0x555555555233 <lab05_proxy_state+131>
   0x5555555551ba <lab05_proxy_state+10>:	cmp    rsi,0x1
   0x5555555551be <lab05_proxy_state+14>:	je     0x5555555551ef <lab05_proxy_state+63>
   0x5555555551c0 <lab05_proxy_state+16>:	cmp    BYTE PTR [rdi+0x1],0x1
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab05_proxy_state` at RVA `0x11b0` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 06 — Target-extension classifier

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab06_file_classifier(const char*name){const char*e=strrchr(name,'.');if(!e)return 0;if(!strcmp(e,".doc")||!strcmp(e,".pdf"))return 1;if(!strcmp(e,".key"))return 2;if(!strcmp(e,".log"))return 4;return 8;}
int main(void){printf("%u\n",lab06_file_classifier("report.pdf"));return 0;}
```

## Actual baseline output

```text
1
```

## Ghidra stripped analysis

Recover last-dot search, extension comparison chain, and class bit values.

```c
FUNCTION FUN_00101190
ENTRY 00101190
SIGNATURE undefined FUN_00101190(void)
CALLERS 00102048, 001020b0, 0010106b

int FUN_00101190(char *param_1)

{
  int iVar1;
  char *__s1;

  __s1 = strrchr(param_1,0x2e);
  if (__s1 == (char *)0x0) {
    return 0;
  }
  iVar1 = strcmp(__s1,".doc");
  if (iVar1 != 0) {
    iVar1 = strcmp(__s1,".pdf");
    if (iVar1 != 0) {
      iVar1 = strcmp(__s1,".key");
      if (iVar1 != 0) {
        iVar1 = strcmp(__s1,".log");
        return (-(uint)(iVar1 == 0) & 0xfffffffc) + 8;
      }
      return 2;
    }
  }
  return 1;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/06_file_classifier_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001190 <lab06_file_classifier>:
    1190:	55                   	push   rbp
    1191:	be 2e 00 00 00       	mov    esi,0x2e
    1196:	48 89 e5             	mov    rbp,rsp
    1199:	48 83 ec 10          	sub    rsp,0x10
    119d:	e8 9e fe ff ff       	call   1040 <strrchr@plt>
    11a2:	48 85 c0             	test   rax,rax
    11a5:	74 79                	je     1220 <lab06_file_classifier+0x90>
    11a7:	48 8d 35 56 0e 00 00 	lea    rsi,[rip+0xe56]        # 2004 <_IO_stdin_used+0x4>
    11ae:	48 89 c7             	mov    rdi,rax
    11b1:	48 89 5d f8          	mov    QWORD PTR [rbp-0x8],rbx
    11b5:	48 89 c3             	mov    rbx,rax
    11b8:	e8 93 fe ff ff       	call   1050 <strcmp@plt>
    11bd:	85 c0                	test   eax,eax
    11bf:	74 4f                	je     1210 <lab06_file_classifier+0x80>
    11c1:	48 8d 35 51 0e 00 00 	lea    rsi,[rip+0xe51]        # 2019 <_IO_stdin_used+0x19>
    11c8:	48 89 df             	mov    rdi,rbx
    11cb:	e8 80 fe ff ff       	call   1050 <strcmp@plt>
    11d0:	85 c0                	test   eax,eax
    11d2:	74 3c                	je     1210 <lab06_file_classifier+0x80>
    11d4:	48 8d 35 2e 0e 00 00 	lea    rsi,[rip+0xe2e]        # 2009 <_IO_stdin_used+0x9>
    11db:	48 89 df             	mov    rdi,rbx
    11de:	e8 6d fe ff ff       	call   1050 <strcmp@plt>
    11e3:	85 c0                	test   eax,eax
    11e5:	b8 02 00 00 00       	mov    eax,0x2
    11ea:	74 3c                	je     1228 <lab06_file_classifier+0x98>
    11ec:	48 89 df             	mov    rdi,rbx
    11ef:	48 8d 35 18 0e 00 00 	lea    rsi,[rip+0xe18]        # 200e <_IO_stdin_used+0xe>
    11f6:	e8 55 fe ff ff       	call   1050 <strcmp@plt>
    11fb:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    11ff:	c9                   	leave
    1200:	83 f8 01             	cmp    eax,0x1
    1203:	19 c0                	sbb    eax,eax
    1205:	83 e0 fc             	and    eax,0xfffffffc
    1208:	83 c0 08             	add    eax,0x8
    120b:	c3                   	ret
    120c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1210:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    1214:	b8 01 00 00 00       	mov    eax,0x1
    1219:	c9                   	leave
    121a:	c3                   	ret
    121b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1220:	c9                   	leave
    1221:	31 c0                	xor    eax,eax
    1223:	c3                   	ret
    1224:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1228:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    122c:	c9                   	leave
    122d:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab06_file_classifier
=== PWNDBG_EVIDENCE lab06_file_classifier ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe288 —▸ 0x7fffffffe661 ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555130 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe288 —▸ 0x7fffffffe661 ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x555555556013 ◂— 'report.pdf'
 RSI  0x7fffffffe278 —▸ 0x7fffffffe610 ◂— 0x74782f656d6f682f ('/home/xt')
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe138 —▸ 0x555555555070 (main+16) ◂— lea rdi, [rip + 0xfa7]
 RIP  0x555555555190 (lab06_file_classifier) ◂— push rbp
   0x555555555191 <lab06_file_classifier+1>     mov    esi, 0x2e     ESI => 0x2e
   0x555555555196 <lab06_file_classifier+6>     mov    rbp, rsp      RBP => 0x7fffffffe130 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x555555555199 <lab06_file_classifier+9>     sub    rsp, 0x10     RSP => 0x7fffffffe120 (0x7fffffffe130 - 0x10)
   0x55555555519d <lab06_file_classifier+13>    call   strrchr@plt                 <strrchr@plt>
   0x5555555551a2 <lab06_file_classifier+18>    test   rax, rax
   0x5555555551a5 <lab06_file_classifier+21>    je     lab06_file_classifier+144   <lab06_file_classifier+144>
   0x5555555551a7 <lab06_file_classifier+23>    lea    rsi, [rip + 0xe56]           RSI => 0x555555556004 ◂— 0x656b2e00636f642e /* '.doc' */
   0x5555555551ae <lab06_file_classifier+30>    mov    rdi, rax
   0x5555555551b1 <lab06_file_classifier+33>    mov    qword ptr [rbp - 8], rbx
   0x5555555551b5 <lab06_file_classifier+37>    mov    rbx, rax
=> 0x555555555190 <lab06_file_classifier>:	push   rbp
   0x555555555191 <lab06_file_classifier+1>:	mov    esi,0x2e
   0x555555555196 <lab06_file_classifier+6>:	mov    rbp,rsp
   0x555555555199 <lab06_file_classifier+9>:	sub    rsp,0x10
   0x55555555519d <lab06_file_classifier+13>:	call   0x555555555040 <strrchr@plt>
   0x5555555551a2 <lab06_file_classifier+18>:	test   rax,rax
   0x5555555551a5 <lab06_file_classifier+21>:	je     0x555555555220 <lab06_file_classifier+144>
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab06_file_classifier` at RVA `0x1190` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 07 — Process-name matching

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab07_process_matcher(const char*const*p,size_t n,const char*const*deny,size_t d){int hits=0;for(size_t i=0;i<n;i++)for(size_t j=0;j<d;j++)if(strstr(p[i],deny[j]))hits++;return hits;}
int main(void){const char*p[]={"shell","analysis-tool","editor"};const char*d[]={"analysis","debug"};printf("%d\n",lab07_process_matcher(p,3,d,2));return 0;}
```

## Actual baseline output

```text
1
```

## Ghidra stripped analysis

Recover nested list traversal, substring comparisons, hit accumulation, and synthetic inputs.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 00102058, 001020c0, 001010ca

int FUN_00101200(long param_1,long param_2,undefined8 *param_3,long param_4)

{
  char *__haystack;
  char *pcVar1;
  int iVar2;
  long lVar3;
  undefined8 *puVar4;

  if ((param_2 != 0) && (param_4 != 0)) {
    iVar2 = 0;
    lVar3 = 0;
    do {
      __haystack = *(char **)(param_1 + lVar3 * 8);
      puVar4 = param_3;
      do {
        pcVar1 = strstr(__haystack,(char *)*puVar4);
        iVar2 = (iVar2 + 1) - (uint)(pcVar1 == (char *)0x0);
        puVar4 = puVar4 + 1;
      } while (puVar4 != param_3 + param_4);
      lVar3 = lVar3 + 1;
    } while (lVar3 != param_2);
    return iVar2;
  }
  return 0;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/07_process_matcher_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab07_process_matcher>:
    1200:	55                   	push   rbp
    1201:	48 89 e5             	mov    rbp,rsp
    1204:	48 83 ec 50          	sub    rsp,0x50
    1208:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    120c:	48 85 f6             	test   rsi,rsi
    120f:	74 7c                	je     128d <lab07_process_matcher+0x8d>
    1211:	48 85 c9             	test   rcx,rcx
    1214:	74 77                	je     128d <lab07_process_matcher+0x8d>
    1216:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    121a:	31 db                	xor    ebx,ebx
    121c:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1220:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
    1224:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
    1228:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    122c:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1230:	4c 8d 2c ca          	lea    r13,[rdx+rcx*8]
    1234:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1238:	45 31 f6             	xor    r14d,r14d
    123b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1240:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    1244:	4c 8b 7d b8          	mov    r15,QWORD PTR [rbp-0x48]
    1248:	4e 8b 24 f0          	mov    r12,QWORD PTR [rax+r14*8]
    124c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1250:	49 8b 37             	mov    rsi,QWORD PTR [r15]
    1253:	4c 89 e7             	mov    rdi,r12
    1256:	e8 f5 fd ff ff       	call   1050 <strstr@plt>
    125b:	48 83 f8 01          	cmp    rax,0x1
    125f:	83 db ff             	sbb    ebx,0xffffffff
    1262:	49 83 c7 08          	add    r15,0x8
    1266:	4d 39 ef             	cmp    r15,r13
    1269:	75 e5                	jne    1250 <lab07_process_matcher+0x50>
    126b:	49 83 c6 01          	add    r14,0x1
    126f:	4c 3b 75 c0          	cmp    r14,QWORD PTR [rbp-0x40]
    1273:	75 cb                	jne    1240 <lab07_process_matcher+0x40>
    1275:	89 d8                	mov    eax,ebx
    1277:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    127b:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    127f:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    1283:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    1287:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    128b:	c9                   	leave
    128c:	c3                   	ret
    128d:	31 db                	xor    ebx,ebx
    128f:	89 d8                	mov    eax,ebx
    1291:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    1295:	c9                   	leave
    1296:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab07_process_matcher
=== PWNDBG_EVIDENCE lab07_process_matcher ===
 RAX  0x555555556028 ◂— 0x6425006775626564 /* 'debug' */
 RCX  2
 RDX  0x7fffffffe110 —▸ 0x55555555601f ◂— 'analysis'
 RDI  0x7fffffffe120 —▸ 0x555555556004 ◂— 0x6e61006c6c656873 /* 'shell' */
 RSI  3
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe108 —▸ 0x5555555550cf (main+111) ◂— lea rdi, [rip + 0xf58]
 RIP  0x555555555200 (lab07_process_matcher) ◂— push rbp
   0x555555555201 <lab07_process_matcher+1>     mov    rbp, rsp                        RBP => 0x7fffffffe100 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x555555555204 <lab07_process_matcher+4>     sub    rsp, 0x50                       RSP => 0x7fffffffe0b0 (0x7fffffffe100 - 0x50)
   0x555555555208 <lab07_process_matcher+8>     mov    qword ptr [rbp - 0x28], rbx     [0x7fffffffe0d8] <= 0
   0x55555555520c <lab07_process_matcher+12>    test   rsi, rsi                        3 & 3     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x55555555520f <lab07_process_matcher+15>  ✘ je     lab07_process_matcher+141   <lab07_process_matcher+141>
   0x555555555211 <lab07_process_matcher+17>    test   rcx, rcx                        2 & 2     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555214 <lab07_process_matcher+20>  ✘ je     lab07_process_matcher+141   <lab07_process_matcher+141>
   0x555555555216 <lab07_process_matcher+22>    mov    qword ptr [rbp - 0x20], r12     [0x7fffffffe0e0] <= 0x7fffffffe278 —▸ 0x7fffffffe610 ◂— 0x74782f656d6f682f ('/home/xt')
   0x55555555521a <lab07_process_matcher+26>    xor    ebx, ebx                        EBX => 0
   0x55555555521c <lab07_process_matcher+28>    mov    qword ptr [rbp - 8], r15        [0x7fffffffe0f8] <= 0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
=> 0x555555555200 <lab07_process_matcher>:	push   rbp
   0x555555555201 <lab07_process_matcher+1>:	mov    rbp,rsp
   0x555555555204 <lab07_process_matcher+4>:	sub    rsp,0x50
   0x555555555208 <lab07_process_matcher+8>:	mov    QWORD PTR [rbp-0x28],rbx
   0x55555555520c <lab07_process_matcher+12>:	test   rsi,rsi
   0x55555555520f <lab07_process_matcher+15>:	je     0x55555555528d <lab07_process_matcher+141>
   0x555555555211 <lab07_process_matcher+17>:	test   rcx,rcx
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab07_process_matcher` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 08 — Sandbox heuristic scoring

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab08_sandbox_score(uint32_t cpus,uint64_t ram_mb,uint64_t uptime_s,int debugger){int s=0;if(cpus<2)s+=3;if(ram_mb<2048)s+=3;if(uptime_s<300)s+=2;if(debugger)s+=5;return s;}
int main(void){printf("%d\n",lab08_sandbox_score(1,1024,60,1));return 0;}
```

## Actual baseline output

```text
13
```

## Ghidra stripped analysis

Recover threshold comparisons, weighted score, and debugger input without evasive action.

```c
FUNCTION FUN_00101180
ENTRY 00101180
SIGNATURE undefined FUN_00101180(void)
CALLERS 0010202c, 00102098, 00101058

byte FUN_00101180(uint param_1,ulong param_2,ulong param_3,int param_4)

{
  byte bVar1;

  bVar1 = -(param_1 < 2) & 3;
  if (param_2 < 0x800) {
    bVar1 = bVar1 + 3;
  }
  if (param_3 < 300) {
    bVar1 = bVar1 + 2;
  }
  if (param_4 != 0) {
    bVar1 = bVar1 + 5;
  }
  return bVar1;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/08_sandbox_score_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001180 <lab08_sandbox_score>:
    1180:	83 ff 02             	cmp    edi,0x2
    1183:	48 89 f7             	mov    rdi,rsi
    1186:	48 89 d6             	mov    rsi,rdx
    1189:	19 c0                	sbb    eax,eax
    118b:	83 e0 03             	and    eax,0x3
    118e:	48 81 ff ff 07 00 00 	cmp    rdi,0x7ff
    1195:	8d 50 03             	lea    edx,[rax+0x3]
    1198:	0f 46 c2             	cmovbe eax,edx
    119b:	48 81 fe 2b 01 00 00 	cmp    rsi,0x12b
    11a2:	8d 50 02             	lea    edx,[rax+0x2]
    11a5:	0f 46 c2             	cmovbe eax,edx
    11a8:	85 c9                	test   ecx,ecx
    11aa:	8d 50 05             	lea    edx,[rax+0x5]
    11ad:	0f 45 c2             	cmovne eax,edx
    11b0:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab08_sandbox_score
=== PWNDBG_EVIDENCE lab08_sandbox_score ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe288 —▸ 0x7fffffffe665 ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  1
 RDX  0x3c
 RDI  1
 RSI  0x400
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe138 —▸ 0x55555555505d (main+29) ◂— lea rdi, [rip + 0xfa0]
 RIP  0x555555555180 (lab08_sandbox_score) ◂— cmp edi, 2
   0x555555555183 <lab08_sandbox_score+3>     mov    rdi, rsi           RDI => 0x400
   0x555555555186 <lab08_sandbox_score+6>     mov    rsi, rdx           RSI => 0x3c
   0x555555555189 <lab08_sandbox_score+9>     sbb    eax, eax
   0x55555555518b <lab08_sandbox_score+11>    and    eax, 3             EAX => 3 (0xffffffff & 0x3)
   0x55555555518e <lab08_sandbox_score+14>    cmp    rdi, 0x7ff         0x400 - 0x7ff     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
   0x555555555195 <lab08_sandbox_score+21>    lea    edx, [rax + 3]     EDX => 6
   0x555555555198 <lab08_sandbox_score+24>  ✔ cmovbe eax, edx
   0x55555555519b <lab08_sandbox_score+27>    cmp    rsi, 0x12b         0x3c - 0x12b     EFLAGS => 0x287 [ CF PF af zf SF IF df of ac ]
   0x5555555551a2 <lab08_sandbox_score+34>    lea    edx, [rax + 2]     EDX => 8
   0x5555555551a5 <lab08_sandbox_score+37>  ✔ cmovbe eax, edx
=> 0x555555555180 <lab08_sandbox_score>:	cmp    edi,0x2
   0x555555555183 <lab08_sandbox_score+3>:	mov    rdi,rsi
   0x555555555186 <lab08_sandbox_score+6>:	mov    rsi,rdx
   0x555555555189 <lab08_sandbox_score+9>:	sbb    eax,eax
   0x55555555518b <lab08_sandbox_score+11>:	and    eax,0x3
   0x55555555518e <lab08_sandbox_score+14>:	cmp    rdi,0x7ff
   0x555555555195 <lab08_sandbox_score+21>:	lea    edx,[rax+0x3]
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab08_sandbox_score` at RVA `0x1180` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 09 — Unpacking transform

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab09_unpack_stub(uint8_t*out,const uint8_t*in,size_t n,uint8_t key){uint32_t c=0;for(size_t i=0;i<n;i++){out[i]=in[i]^key;key=(uint8_t)(key*17u+31u);c=(c<<5)|(c>>27);c^=out[i];}return c;}
int main(void){uint8_t in[]={1,2,3,4,5},out[5];printf("%u\n",lab09_unpack_stub(out,in,5,0x5a));return 0;}
```

## Actual baseline output

```text
96379027
```

## Ghidra stripped analysis

Recover evolving byte key, output buffer, rolling checksum, and crucial absence of execute/permission transfer.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 0010202c, 00102098, 001010b4

uint FUN_00101200(long param_1,long param_2,long param_3,byte param_4)

{
  uint uVar1;
  long lVar2;
  byte bVar3;

  if (param_3 != 0) {
    lVar2 = 0;
    uVar1 = 0;
    do {
      bVar3 = *(byte *)(param_2 + lVar2) ^ param_4;
      param_4 = param_4 * '\x11' + 0x1f;
      *(byte *)(param_1 + lVar2) = bVar3;
      lVar2 = lVar2 + 1;
      uVar1 = (uVar1 << 5 | uVar1 >> 0x1b) ^ (uint)bVar3;
    } while (param_3 != lVar2);
    return uVar1;
  }
  return 0;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/09_unpack_stub_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab09_unpack_stub>:
    1200:	49 89 f9             	mov    r9,rdi
    1203:	49 89 f2             	mov    r10,rsi
    1206:	49 89 d0             	mov    r8,rdx
    1209:	48 85 d2             	test   rdx,rdx
    120c:	74 62                	je     1270 <lab09_unpack_stub+0x70>
    120e:	31 d2                	xor    edx,edx
    1210:	31 c0                	xor    eax,eax
    1212:	66 90                	xchg   ax,ax
    1214:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    121b:	00 00 00 00
    121f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1226:	00 00 00 00
    122a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1231:	00 00 00 00
    1235:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    123c:	00 00 00 00
    1240:	41 0f b6 34 12       	movzx  esi,BYTE PTR [r10+rdx*1]
    1245:	89 cf                	mov    edi,ecx
    1247:	c1 c0 05             	rol    eax,0x5
    124a:	c1 e7 04             	shl    edi,0x4
    124d:	31 ce                	xor    esi,ecx
    124f:	8d 4c 39 1f          	lea    ecx,[rcx+rdi*1+0x1f]
    1253:	41 88 34 11          	mov    BYTE PTR [r9+rdx*1],sil
    1257:	40 0f b6 f6          	movzx  esi,sil
    125b:	48 83 c2 01          	add    rdx,0x1
    125f:	31 f0                	xor    eax,esi
    1261:	49 39 d0             	cmp    r8,rdx
    1264:	75 da                	jne    1240 <lab09_unpack_stub+0x40>
    1266:	c3                   	ret
    1267:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    126e:	00 00
    1270:	31 c0                	xor    eax,eax
    1272:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab09_unpack_stub
=== PWNDBG_EVIDENCE lab09_unpack_stub ===
 RAX  0
 RCX  0x5a
 RDX  5
 RDI  0x7fffffffe133 ◂— 0xa41d000000000000
 RSI  0x7fffffffe12e ◂— 0x504030201
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe118 —▸ 0x5555555550b9 (main+57) ◂— lea rdi, [rip + 0xf44]
 RIP  0x555555555200 (lab09_unpack_stub) ◂— mov r9, rdi
   0x555555555203 <lab09_unpack_stub+3>     mov    r10, rsi     R10 => 0x7fffffffe12e ◂— 0x504030201
   0x555555555206 <lab09_unpack_stub+6>     mov    r8, rdx      R8 => 5
   0x555555555209 <lab09_unpack_stub+9>     test   rdx, rdx     5 & 5     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x55555555520c <lab09_unpack_stub+12>  ✘ je     lab09_unpack_stub+112       <lab09_unpack_stub+112>
   0x55555555520e <lab09_unpack_stub+14>    xor    edx, edx                 EDX => 0
   0x555555555210 <lab09_unpack_stub+16>    xor    eax, eax                 EAX => 0
   0x555555555212 <lab09_unpack_stub+18>    nop
   0x555555555214 <lab09_unpack_stub+20>    nop    word ptr [rax + rax]
   0x55555555521f <lab09_unpack_stub+31>    nop    word ptr [rax + rax]
   0x55555555522a <lab09_unpack_stub+42>    nop    word ptr [rax + rax]
=> 0x555555555200 <lab09_unpack_stub>:	mov    r9,rdi
   0x555555555203 <lab09_unpack_stub+3>:	mov    r10,rsi
   0x555555555206 <lab09_unpack_stub+6>:	mov    r8,rdx
   0x555555555209 <lab09_unpack_stub+9>:	test   rdx,rdx
   0x55555555520c <lab09_unpack_stub+12>:	je     0x555555555270 <lab09_unpack_stub+112>
   0x55555555520e <lab09_unpack_stub+14>:	xor    edx,edx
   0x555555555210 <lab09_unpack_stub+16>:	xor    eax,eax
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab09_unpack_stub` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 10 — Command dispatcher

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
typedef int(*fn)(int);int inc(int x){return x+1;}int dec(int x){return x-1;}int lab10_command_table(unsigned op,int x){static fn t[]={inc,dec};if(op>=2)return-1;return t[op](x);}
int main(void){printf("%d\n",lab10_command_table(0,41));return 0;}
```

## Actual baseline output

```text
42
```

## Ghidra stripped analysis

Recover bounds, function-pointer table, indirect call, and two benign handlers.

```c
FUNCTION FUN_00101190
ENTRY 00101190
SIGNATURE undefined FUN_00101190(void)
CALLERS 0010203c, 001020d0, 0010104b

int FUN_00101190(undefined4 param_1,int param_2)

{
  switch(param_1) {
  case 0:
    return param_2 + 1;
  case 1:
    return param_2 + -1;
  default:
    return -1;
  }
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/10_command_table_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001190 <lab10_command_table>:
    1190:	83 ff 01             	cmp    edi,0x1
    1193:	77 1b                	ja     11b0 <lab10_command_table+0x20>
    1195:	89 ff                	mov    edi,edi
    1197:	48 8d 05 32 2c 00 00 	lea    rax,[rip+0x2c32]        # 3dd0 <t.0>
    119e:	48 8b 04 f8          	mov    rax,QWORD PTR [rax+rdi*8]
    11a2:	89 f7                	mov    edi,esi
    11a4:	ff e0                	jmp    rax
    11a6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    11ad:	00 00 00
    11b0:	b8 ff ff ff ff       	mov    eax,0xffffffff
    11b5:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab10_command_table
=== PWNDBG_EVIDENCE lab10_command_table ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe288 —▸ 0x7fffffffe665 ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555110 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe288 —▸ 0x7fffffffe665 ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0
 RSI  0x29
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe138 —▸ 0x555555555050 (main+16) ◂— lea rdi, [rip + 0xfad]
 RIP  0x555555555190 (lab10_command_table) ◂— cmp edi, 1
   0x555555555193 <lab10_command_table+3>   ✘ ja     lab10_command_table+32      <lab10_command_table+32>
   0x555555555195 <lab10_command_table+5>     mov    edi, edi                         EDI => 0
   0x555555555197 <lab10_command_table+7>     lea    rax, [rip + 0x2c32]              RAX => 0x555555557dd0 (t) —▸ 0x555555555170 (inc) ◂— lea eax, [rdi + 1]
   0x55555555519e <lab10_command_table+14>    mov    rax, qword ptr [rax + rdi*8]     RAX, [t] => 0x555555555170 (inc) ◂— lea eax, [rdi + 1]
   0x5555555551a2 <lab10_command_table+18>    mov    edi, esi                         EDI => 0x29
   0x5555555551a4 <lab10_command_table+20>    jmp    rax                         <inc>
   0x555555555170 <inc>                       lea    eax, [rdi + 1]                   EAX => 0x2a
   0x555555555173 <inc+3>                     ret                                <main+16>
   0x555555555050 <main+16>                   lea    rdi, [rip + 0xfad]               RDI => 0x555555556004 ◂— 0x3b031b01000a6425 /* '%d\n' */
   0x555555555057 <main+23>                   mov    esi, eax                         ESI => 0x2a
=> 0x555555555190 <lab10_command_table>:	cmp    edi,0x1
   0x555555555193 <lab10_command_table+3>:	ja     0x5555555551b0 <lab10_command_table+32>
   0x555555555195 <lab10_command_table+5>:	mov    edi,edi
   0x555555555197 <lab10_command_table+7>:	lea    rax,[rip+0x2c32]        # 0x555555557dd0 <t.0>
   0x55555555519e <lab10_command_table+14>:	mov    rax,QWORD PTR [rax+rdi*8]
   0x5555555551a2 <lab10_command_table+18>:	mov    edi,esi
   0x5555555551a4 <lab10_command_table+20>:	jmp    rax
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab10_command_table` at RVA `0x1190` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 11 — Synthetic collection/staging

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab11_synthetic_collector(const char*const*items,size_t n,char*out,size_t cap){size_t w=0;uint32_t h=0;for(size_t i=0;i<n;i++){size_t z=strlen(items[i]);if(z>cap-w-1)break;memcpy(out+w,items[i],z);w+=z;out[w++]='|';for(size_t j=0;j<z;j++)h=h*131u+(uint8_t)items[i][j];}if(w<cap)out[w]=0;return h;}
int main(void){const char*i[]={"DEMO_USER","DEMO_TOKEN"};char o[64];printf("%u %s\n",lab11_synthetic_collector(i,2,o,sizeof o),o);return 0;}
```

## Actual baseline output

```text
3267479988 DEMO_USER|DEMO_TOKEN|
```

## Ghidra stripped analysis

Recover capacity, item concatenation, delimiter, hash, and explicitly fake strings.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 00102044, 001020b0, 001010c3

int FUN_00101200(long param_1,long param_2,long param_3,ulong param_4)

{
  byte *pbVar1;
  byte bVar2;
  char *__s;
  size_t __n;
  byte *pbVar3;
  long lVar4;
  ulong uVar5;
  int iVar6;

  if (param_2 == 0) {
    uVar5 = 0;
    iVar6 = 0;
  }
  else {
    iVar6 = 0;
    uVar5 = 0;
    lVar4 = 0;
    do {
      __s = *(char **)(param_1 + lVar4 * 8);
      __n = strlen(__s);
      if ((param_4 - 1) - uVar5 < __n) break;
      memcpy((void *)(param_3 + uVar5),__s,__n);
      *(undefined1 *)(param_3 + __n + uVar5) = 0x7c;
      uVar5 = __n + uVar5 + 1;
      if (__n != 0) {
        pbVar3 = *(byte **)(param_1 + lVar4 * 8);
        pbVar1 = pbVar3 + __n;
        do {
          bVar2 = *pbVar3;
          pbVar3 = pbVar3 + 1;
          iVar6 = (uint)bVar2 + iVar6 * 0x83;
        } while (pbVar1 != pbVar3);
      }
      lVar4 = lVar4 + 1;
    } while (param_2 != lVar4);
  }
  if (uVar5 < param_4) {
    *(undefined1 *)(param_3 + uVar5) = 0;
  }
  return iVar6;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/11_synthetic_collector_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab11_synthetic_collector>:
    1200:	55                   	push   rbp
    1201:	48 89 e5             	mov    rbp,rsp
    1204:	48 83 ec 60          	sub    rsp,0x60
    1208:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    120c:	48 89 d3             	mov    rbx,rdx
    120f:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    1213:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    1217:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
    121b:	48 89 4d a8          	mov    QWORD PTR [rbp-0x58],rcx
    121f:	48 85 f6             	test   rsi,rsi
    1222:	0f 84 bd 00 00 00    	je     12e5 <lab11_synthetic_collector+0xe5>
    1228:	48 8d 41 ff          	lea    rax,[rcx-0x1]
    122c:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    1230:	45 31 ff             	xor    r15d,r15d
    1233:	49 89 fc             	mov    r12,rdi
    1236:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
    123a:	45 31 f6             	xor    r14d,r14d
    123d:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1241:	45 31 ed             	xor    r13d,r13d
    1244:	90                   	nop
    1245:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    124c:	00 00 00 00
    1250:	4b 8b 34 ec          	mov    rsi,QWORD PTR [r12+r13*8]
    1254:	48 89 f7             	mov    rdi,rsi
    1257:	48 89 75 c8          	mov    QWORD PTR [rbp-0x38],rsi
    125b:	e8 d0 fd ff ff       	call   1030 <strlen@plt>
    1260:	48 89 c2             	mov    rdx,rax
    1263:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
    1267:	4c 29 f0             	sub    rax,r14
    126a:	48 39 d0             	cmp    rax,rdx
    126d:	72 52                	jb     12c1 <lab11_synthetic_collector+0xc1>
    126f:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
    1273:	4a 8d 3c 33          	lea    rdi,[rbx+r14*1]
    1277:	48 89 55 c0          	mov    QWORD PTR [rbp-0x40],rdx
    127b:	e8 e0 fd ff ff       	call   1060 <memcpy@plt>
    1280:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    1284:	4a 8d 04 32          	lea    rax,[rdx+r14*1]
    1288:	c6 04 03 7c          	mov    BYTE PTR [rbx+rax*1],0x7c
    128c:	4c 8d 70 01          	lea    r14,[rax+0x1]
    1290:	48 85 d2             	test   rdx,rdx
    1293:	74 22                	je     12b7 <lab11_synthetic_collector+0xb7>
    1295:	4b 8b 04 ec          	mov    rax,QWORD PTR [r12+r13*8]
    1299:	48 8d 34 10          	lea    rsi,[rax+rdx*1]
    129d:	0f 1f 00             	nop    DWORD PTR [rax]
    12a0:	41 69 cf 83 00 00 00 	imul   ecx,r15d,0x83
    12a7:	0f b6 10             	movzx  edx,BYTE PTR [rax]
    12aa:	48 83 c0 01          	add    rax,0x1
    12ae:	44 8d 3c 0a          	lea    r15d,[rdx+rcx*1]
    12b2:	48 39 c6             	cmp    rsi,rax
    12b5:	75 e9                	jne    12a0 <lab11_synthetic_collector+0xa0>
    12b7:	49 83 c5 01          	add    r13,0x1
    12bb:	4c 39 6d b0          	cmp    QWORD PTR [rbp-0x50],r13
    12bf:	75 8f                	jne    1250 <lab11_synthetic_collector+0x50>
    12c1:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    12c5:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    12c9:	4c 3b 75 a8          	cmp    r14,QWORD PTR [rbp-0x58]
    12cd:	73 05                	jae    12d4 <lab11_synthetic_collector+0xd4>
    12cf:	42 c6 04 33 00       	mov    BYTE PTR [rbx+r14*1],0x0
    12d4:	44 89 f8             	mov    eax,r15d
    12d7:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    12db:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    12df:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    12e3:	c9                   	leave
    12e4:	c3                   	ret
    12e5:	45 31 f6             	xor    r14d,r14d
    12e8:	45 31 ff             	xor    r15d,r15d
    12eb:	eb dc                	jmp    12c9 <lab11_synthetic_collector+0xc9>

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab11_synthetic_collector
=== PWNDBG_EVIDENCE lab11_synthetic_collector ===
 RAX  0x55555555600e ◂— 'DEMO_TOKEN'
 RCX  0x40
 RDX  0x7fffffffe0e0 ◂— 0x2200000
 RDI  0x7fffffffe0d0 —▸ 0x555555556004 ◂— 'DEMO_USER'
 RSI  2
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0c8 —▸ 0x5555555550c8 (main+72) ◂— lea rdx, [rbp - 0x50]
 RIP  0x555555555200 (lab11_synthetic_collector) ◂— push rbp
   0x555555555201 <lab11_synthetic_collector+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0c0 —▸ 0x7fffffffe130 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe240 ◂— ...
   0x555555555204 <lab11_synthetic_collector+4>     sub    rsp, 0x60                       RSP => 0x7fffffffe060 (0x7fffffffe0c0 - 0x60)
   0x555555555208 <lab11_synthetic_collector+8>     mov    qword ptr [rbp - 0x28], rbx     [0x7fffffffe098] <= 0
   0x55555555520c <lab11_synthetic_collector+12>    mov    rbx, rdx                        RBX => 0x7fffffffe0e0 ◂— 0x2200000
   0x55555555520f <lab11_synthetic_collector+15>    mov    qword ptr [rbp - 0x10], r14     [0x7fffffffe0b0] <= 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— ...
   0x555555555213 <lab11_synthetic_collector+19>    mov    qword ptr [rbp - 8], r15        [0x7fffffffe0b8] <= 0x555555557dd0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
   0x555555555217 <lab11_synthetic_collector+23>    mov    qword ptr [rbp - 0x50], rsi     [0x7fffffffe070] <= 2
   0x55555555521b <lab11_synthetic_collector+27>    mov    qword ptr [rbp - 0x58], rcx     [0x7fffffffe068] <= 0x40
   0x55555555521f <lab11_synthetic_collector+31>    test   rsi, rsi                        2 & 2     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555222 <lab11_synthetic_collector+34>  ✘ je     lab11_synthetic_collector+229 <lab11_synthetic_collector+229>
=> 0x555555555200 <lab11_synthetic_collector>:	push   rbp
   0x555555555201 <lab11_synthetic_collector+1>:	mov    rbp,rsp
   0x555555555204 <lab11_synthetic_collector+4>:	sub    rsp,0x60
   0x555555555208 <lab11_synthetic_collector+8>:	mov    QWORD PTR [rbp-0x28],rbx
   0x55555555520c <lab11_synthetic_collector+12>:	mov    rbx,rdx
   0x55555555520f <lab11_synthetic_collector+15>:	mov    QWORD PTR [rbp-0x10],r14
   0x555555555213 <lab11_synthetic_collector+19>:	mov    QWORD PTR [rbp-0x8],r15
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab11_synthetic_collector` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 12 — Cleanup-plan computation

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab12_cleanup_plan(const char*const*p,size_t n,uint32_t allowed_mask){uint32_t plan=0;for(size_t i=0;i<n;i++){if(strstr(p[i],".tmp"))plan|=1;if(strstr(p[i],".log"))plan|=2;if(strstr(p[i],"cache"))plan|=4;}return plan&allowed_mask;}
int main(void){const char*p[]={"demo.tmp","audit.log","cache.bin"};printf("%u\n",lab12_cleanup_plan(p,3,0));return 0;}
```

## Actual baseline output

```text
0
```

## Ghidra stripped analysis

Recover substring-derived bitmask and allowed-mask suppression; no delete API exists.

```c
FUNCTION FUN_001011e0
ENTRY 001011e0
SIGNATURE undefined FUN_001011e0(void)
CALLERS 00102050, 001020b8, 001010a7

uint FUN_001011e0(undefined8 *param_1,long param_2,uint param_3)

{
  undefined8 *puVar1;
  char *pcVar2;
  char *pcVar3;
  uint uVar4;

  if (param_2 != 0) {
    puVar1 = param_1 + param_2;
    uVar4 = 0;
    do {
      pcVar3 = (char *)*param_1;
      pcVar2 = strstr(pcVar3,".tmp");
      if (pcVar2 != (char *)0x0) {
        uVar4 = uVar4 | 1;
      }
      pcVar2 = strstr(pcVar3,".log");
      if (pcVar2 != (char *)0x0) {
        uVar4 = uVar4 | 2;
      }
      pcVar3 = strstr(pcVar3,"cache");
      if (pcVar3 != (char *)0x0) {
        uVar4 = uVar4 | 4;
      }
      param_1 = param_1 + 1;
    } while (param_1 != puVar1);
    return uVar4 & param_3;
  }
  return 0;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/12_cleanup_plan_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000011e0 <lab12_cleanup_plan>:
    11e0:	48 85 f6             	test   rsi,rsi
    11e3:	0f 84 a7 00 00 00    	je     1290 <lab12_cleanup_plan+0xb0>
    11e9:	55                   	push   rbp
    11ea:	48 89 e5             	mov    rbp,rsp
    11ed:	41 57                	push   r15
    11ef:	41 89 d7             	mov    r15d,edx
    11f2:	41 56                	push   r14
    11f4:	4c 8d 34 f7          	lea    r14,[rdi+rsi*8]
    11f8:	41 55                	push   r13
    11fa:	41 54                	push   r12
    11fc:	49 89 fc             	mov    r12,rdi
    11ff:	53                   	push   rbx
    1200:	31 db                	xor    ebx,ebx
    1202:	48 83 ec 08          	sub    rsp,0x8
    1206:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    120d:	00 00 00
    1210:	4d 8b 2c 24          	mov    r13,QWORD PTR [r12]
    1214:	48 8d 35 f3 0d 00 00 	lea    rsi,[rip+0xdf3]        # 200e <_IO_stdin_used+0xe>
    121b:	4c 89 ef             	mov    rdi,r13
    121e:	e8 2d fe ff ff       	call   1050 <strstr@plt>
    1223:	48 8d 35 ee 0d 00 00 	lea    rsi,[rip+0xdee]        # 2018 <_IO_stdin_used+0x18>
    122a:	4c 89 ef             	mov    rdi,r13
    122d:	48 89 c2             	mov    rdx,rax
    1230:	89 d8                	mov    eax,ebx
    1232:	83 c8 01             	or     eax,0x1
    1235:	48 85 d2             	test   rdx,rdx
    1238:	0f 45 d8             	cmovne ebx,eax
    123b:	e8 10 fe ff ff       	call   1050 <strstr@plt>
    1240:	48 8d 35 bd 0d 00 00 	lea    rsi,[rip+0xdbd]        # 2004 <_IO_stdin_used+0x4>
    1247:	4c 89 ef             	mov    rdi,r13
    124a:	48 89 c2             	mov    rdx,rax
    124d:	89 d8                	mov    eax,ebx
    124f:	83 c8 02             	or     eax,0x2
    1252:	48 85 d2             	test   rdx,rdx
    1255:	0f 45 d8             	cmovne ebx,eax
    1258:	e8 f3 fd ff ff       	call   1050 <strstr@plt>
    125d:	48 89 c2             	mov    rdx,rax
    1260:	89 d8                	mov    eax,ebx
    1262:	83 c8 04             	or     eax,0x4
    1265:	48 85 d2             	test   rdx,rdx
    1268:	0f 45 d8             	cmovne ebx,eax
    126b:	49 83 c4 08          	add    r12,0x8
    126f:	4d 39 f4             	cmp    r12,r14
    1272:	75 9c                	jne    1210 <lab12_cleanup_plan+0x30>
    1274:	48 83 c4 08          	add    rsp,0x8
    1278:	89 d8                	mov    eax,ebx
    127a:	44 21 f8             	and    eax,r15d
    127d:	5b                   	pop    rbx
    127e:	41 5c                	pop    r12
    1280:	41 5d                	pop    r13
    1282:	41 5e                	pop    r14
    1284:	41 5f                	pop    r15
    1286:	5d                   	pop    rbp
    1287:	c3                   	ret
    1288:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    128f:	00
    1290:	31 c0                	xor    eax,eax
    1292:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab12_cleanup_plan
=== PWNDBG_EVIDENCE lab12_cleanup_plan ===
 RAX  0x55555555601d ◂— 'cache.bin'
 RCX  0x555555557dd0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555180 (__do_global_dtors_aux) ◂— endbr64
 RDX  0
 RDI  0x7fffffffe120 —▸ 0x55555555600a ◂— 'demo.tmp'
 RSI  3
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe118 —▸ 0x5555555550ac (main+76) ◂— lea rdi, [rip + 0xf74]
 RIP  0x5555555551e0 (lab12_cleanup_plan) ◂— test rsi, rsi
   0x5555555551e3 <lab12_cleanup_plan+3>   ✘ je     lab12_cleanup_plan+176      <lab12_cleanup_plan+176>
   0x5555555551e9 <lab12_cleanup_plan+9>     push   rbp
   0x5555555551ea <lab12_cleanup_plan+10>    mov    rbp, rsp               RBP => 0x7fffffffe110 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x5555555551ed <lab12_cleanup_plan+13>    push   r15
   0x5555555551ef <lab12_cleanup_plan+15>    mov    r15d, edx              R15D => 0
   0x5555555551f2 <lab12_cleanup_plan+18>    push   r14
   0x5555555551f4 <lab12_cleanup_plan+20>    lea    r14, [rdi + rsi*8]     R14 => 0x7fffffffe138 ◂— 0xf4576714161e4c00
   0x5555555551f8 <lab12_cleanup_plan+24>    push   r13
   0x5555555551fa <lab12_cleanup_plan+26>    push   r12
   0x5555555551fc <lab12_cleanup_plan+28>    mov    r12, rdi               R12 => 0x7fffffffe120 —▸ 0x55555555600a ◂— 'demo.tmp'
=> 0x5555555551e0 <lab12_cleanup_plan>:	test   rsi,rsi
   0x5555555551e3 <lab12_cleanup_plan+3>:	je     0x555555555290 <lab12_cleanup_plan+176>
   0x5555555551e9 <lab12_cleanup_plan+9>:	push   rbp
   0x5555555551ea <lab12_cleanup_plan+10>:	mov    rbp,rsp
   0x5555555551ed <lab12_cleanup_plan+13>:	push   r15
   0x5555555551ef <lab12_cleanup_plan+15>:	mov    r15d,edx
   0x5555555551f2 <lab12_cleanup_plan+18>:	push   r14
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab12_cleanup_plan` at RVA `0x11e0` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 13 — Network-neighbor scoring

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI uint32_t lab13_lateral_plan(const uint32_t*hosts,size_t n,uint32_t local){uint32_t score=0;for(size_t i=0;i<n;i++){uint32_t same=(hosts[i]^local)&0xffffff00u;if(!same)score+=10;if((hosts[i]&255)>200)score+=1;}return score;}
int main(void){uint32_t h[]={0x0a000001,0x0a0000fe,0xc0000201};printf("%u\n",lab13_lateral_plan(h,3,0x0a000005));return 0;}
```

## Actual baseline output

```text
21
```

## Ghidra stripped analysis

Recover subnet mask comparison and host-byte score using only in-memory addresses.

```c
FUNCTION FUN_00101200
ENTRY 00101200
SIGNATURE undefined FUN_00101200(void)
CALLERS 0010202c, 00102098, 001010b8

int FUN_00101200(uint *param_1,long param_2,uint param_3)

{
  uint *puVar1;
  int iVar2;

  if (param_2 != 0) {
    puVar1 = param_1 + param_2;
    iVar2 = 0;
    do {
      if ((param_3 ^ *param_1) < 0x100) {
        iVar2 = iVar2 + 10;
      }
      iVar2 = (iVar2 + 1) - (uint)((*param_1 & 0xff) < 0xc9);
      param_1 = param_1 + 1;
    } while (puVar1 != param_1);
    return iVar2;
  }
  return 0;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/13_lateral_plan_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001200 <lab13_lateral_plan>:
    1200:	41 89 d0             	mov    r8d,edx
    1203:	48 85 f6             	test   rsi,rsi
    1206:	74 68                	je     1270 <lab13_lateral_plan+0x70>
    1208:	4c 8d 0c b7          	lea    r9,[rdi+rsi*4]
    120c:	31 c0                	xor    eax,eax
    120e:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1214:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    121b:	00 00 00 00
    121f:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1226:	00 00 00 00
    122a:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1231:	00 00 00 00
    1235:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    123c:	00 00 00 00
    1240:	8b 17                	mov    edx,DWORD PTR [rdi]
    1242:	44 89 c6             	mov    esi,r8d
    1245:	8d 48 0a             	lea    ecx,[rax+0xa]
    1248:	31 d6                	xor    esi,edx
    124a:	0f b6 d2             	movzx  edx,dl
    124d:	81 fe 00 01 00 00    	cmp    esi,0x100
    1253:	0f 42 c1             	cmovb  eax,ecx
    1256:	81 fa c9 00 00 00    	cmp    edx,0xc9
    125c:	83 d8 ff             	sbb    eax,0xffffffff
    125f:	48 83 c7 04          	add    rdi,0x4
    1263:	49 39 f9             	cmp    r9,rdi
    1266:	75 d8                	jne    1240 <lab13_lateral_plan+0x40>
    1268:	c3                   	ret
    1269:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1270:	31 c0                	xor    eax,eax
    1272:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab13_lateral_plan
=== PWNDBG_EVIDENCE lab13_lateral_plan ===
 RAX  0xa0000fe0a000001
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555190 (__do_global_dtors_aux) ◂— endbr64
 RDX  0xa000005
 RDI  0x7fffffffe128 ◂— 0xa0000fe0a000001
 RSI  3
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe118 —▸ 0x5555555550bd (main+61) ◂— lea rdi, [rip + 0xf40]
 RIP  0x555555555200 (lab13_lateral_plan) ◂— mov r8d, edx
   0x555555555203 <lab13_lateral_plan+3>     test   rsi, rsi     3 & 3     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x555555555206 <lab13_lateral_plan+6>   ✘ je     lab13_lateral_plan+112      <lab13_lateral_plan+112>
   0x555555555208 <lab13_lateral_plan+8>     lea    r9, [rdi + rsi*4]        R9 => 0x7fffffffe134 ◂— 0xc56d5e0000000000
   0x55555555520c <lab13_lateral_plan+12>    xor    eax, eax                 EAX => 0
   0x55555555520e <lab13_lateral_plan+14>    nop    word ptr [rax + rax]
   0x555555555214 <lab13_lateral_plan+20>    nop    word ptr [rax + rax]
   0x55555555521f <lab13_lateral_plan+31>    nop    word ptr [rax + rax]
   0x55555555522a <lab13_lateral_plan+42>    nop    word ptr [rax + rax]
   0x555555555235 <lab13_lateral_plan+53>    nop    word ptr [rax + rax]
   0x555555555240 <lab13_lateral_plan+64>    mov    edx, dword ptr [rdi]     EDX, [0x7fffffffe128] => 0xa000001
=> 0x555555555200 <lab13_lateral_plan>:	mov    r8d,edx
   0x555555555203 <lab13_lateral_plan+3>:	test   rsi,rsi
   0x555555555206 <lab13_lateral_plan+6>:	je     0x555555555270 <lab13_lateral_plan+112>
   0x555555555208 <lab13_lateral_plan+8>:	lea    r9,[rdi+rsi*4]
   0x55555555520c <lab13_lateral_plan+12>:	xor    eax,eax
   0x55555555520e <lab13_lateral_plan+14>:	nop    WORD PTR [rax+rax*1+0x0]
   0x555555555214 <lab13_lateral_plan+20>:	data16 cs nop WORD PTR [rax+rax*1+0x0]
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab13_lateral_plan` at RVA `0x1200` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 14 — Ransomware-like file eligibility

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int lab14_ransomware_classifier(const char*name,uint64_t size){const char*e=strrchr(name,'.');if(!e||size==0||size>1048576)return 0;return !strcmp(e,".demo")||!strcmp(e,".lab");}
int main(void){printf("%d\n",lab14_ransomware_classifier("owned.demo",4096));return 0;}
```

## Actual baseline output

```text
1
```

## Ghidra stripped analysis

Recover size gates and inert .demo/.lab extension selection; no file encryption/write exists.

```c
FUNCTION FUN_00101190
ENTRY 00101190
SIGNATURE undefined FUN_00101190(void)
CALLERS 0010203c, 001020a8, 00101070

bool FUN_00101190(char *param_1,long param_2)

{
  bool bVar1;
  int iVar2;
  char *__s1;

  __s1 = strrchr(param_1,0x2e);
  if ((param_2 - 1U < 0x100000) && (__s1 != (char *)0x0)) {
    iVar2 = strcmp(__s1,".demo");
    bVar1 = true;
    if (iVar2 != 0) {
      iVar2 = strcmp(__s1,".lab");
      return iVar2 == 0;
    }
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/14_ransomware_classifier_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001190 <lab14_ransomware_classifier>:
    1190:	55                   	push   rbp
    1191:	48 89 e5             	mov    rbp,rsp
    1194:	53                   	push   rbx
    1195:	48 8d 5e ff          	lea    rbx,[rsi-0x1]
    1199:	be 2e 00 00 00       	mov    esi,0x2e
    119e:	48 83 ec 18          	sub    rsp,0x18
    11a2:	e8 99 fe ff ff       	call   1040 <strrchr@plt>
    11a7:	48 81 fb ff ff 0f 00 	cmp    rbx,0xfffff
    11ae:	77 40                	ja     11f0 <lab14_ransomware_classifier+0x60>
    11b0:	48 89 c7             	mov    rdi,rax
    11b3:	48 85 c0             	test   rax,rax
    11b6:	74 38                	je     11f0 <lab14_ransomware_classifier+0x60>
    11b8:	48 8d 35 4f 0e 00 00 	lea    rsi,[rip+0xe4f]        # 200e <_IO_stdin_used+0xe>
    11bf:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
    11c3:	e8 88 fe ff ff       	call   1050 <strcmp@plt>
    11c8:	85 c0                	test   eax,eax
    11ca:	b8 01 00 00 00       	mov    eax,0x1
    11cf:	74 21                	je     11f2 <lab14_ransomware_classifier+0x62>
    11d1:	48 8b 7d e8          	mov    rdi,QWORD PTR [rbp-0x18]
    11d5:	48 8d 35 28 0e 00 00 	lea    rsi,[rip+0xe28]        # 2004 <_IO_stdin_used+0x4>
    11dc:	e8 6f fe ff ff       	call   1050 <strcmp@plt>
    11e1:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    11e5:	c9                   	leave
    11e6:	85 c0                	test   eax,eax
    11e8:	0f 94 c0             	sete   al
    11eb:	0f b6 c0             	movzx  eax,al
    11ee:	c3                   	ret
    11ef:	90                   	nop
    11f0:	31 c0                	xor    eax,eax
    11f2:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    11f6:	c9                   	leave
    11f7:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab14_ransomware_classifier
=== PWNDBG_EVIDENCE lab14_ransomware_classifier ===
 RAX  0x7ffff7e1ade8 (environ) —▸ 0x7fffffffe268 —▸ 0x7fffffffe655 ◂— 0x5454495243414c41 ('ALACRITT')
 RCX  0x555555557dd8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555130 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffe268 —▸ 0x7fffffffe655 ◂— 0x5454495243414c41 ('ALACRITT')
 RDI  0x555555556009 ◂— 'owned.demo'
 RSI  0x1000
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe118 —▸ 0x555555555075 (main+21) ◂— lea rdi, [rip + 0xf98]
 RIP  0x555555555190 (lab14_ransomware_classifier) ◂— push rbp
   0x555555555191 <lab14_ransomware_classifier+1>     mov    rbp, rsp           RBP => 0x7fffffffe110 —▸ 0x7fffffffe120 —▸ 0x7fffffffe1d0 —▸ 0x7fffffffe230 ◂— ...
   0x555555555194 <lab14_ransomware_classifier+4>     push   rbx
   0x555555555195 <lab14_ransomware_classifier+5>     lea    rbx, [rsi - 1]     RBX => 0xfff
   0x555555555199 <lab14_ransomware_classifier+9>     mov    esi, 0x2e          ESI => 0x2e
   0x55555555519e <lab14_ransomware_classifier+14>    sub    rsp, 0x18          RSP => 0x7fffffffe0f0 (0x7fffffffe108 - 0x18)
   0x5555555551a2 <lab14_ransomware_classifier+18>    call   strrchr@plt                 <strrchr@plt>
   0x5555555551a7 <lab14_ransomware_classifier+23>    cmp    rbx, 0xfffff
   0x5555555551ae <lab14_ransomware_classifier+30>    ja     lab14_ransomware_classifier+96 <lab14_ransomware_classifier+96>
   0x5555555551b0 <lab14_ransomware_classifier+32>    mov    rdi, rax
   0x5555555551b3 <lab14_ransomware_classifier+35>    test   rax, rax
=> 0x555555555190 <lab14_ransomware_classifier>:	push   rbp
   0x555555555191 <lab14_ransomware_classifier+1>:	mov    rbp,rsp
   0x555555555194 <lab14_ransomware_classifier+4>:	push   rbx
   0x555555555195 <lab14_ransomware_classifier+5>:	lea    rbx,[rsi-0x1]
   0x555555555199 <lab14_ransomware_classifier+9>:	mov    esi,0x2e
   0x55555555519e <lab14_ransomware_classifier+14>:	sub    rsp,0x18
   0x5555555551a2 <lab14_ransomware_classifier+18>:	call   0x555555555040 <strrchr@plt>
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab14_ransomware_classifier` at RVA `0x1190` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Walkthrough 15 — Update integrity/version gate

## Complete specimen source

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NI __attribute__((noinline))
uint32_t hash15(const uint8_t*p,size_t n){uint32_t h=0x811c9dc5;for(size_t i=0;i<n;i++)h=(h^p[i])*16777619u;return h;}int lab15_update_verifier(const uint8_t*p,size_t n,uint32_t expected,uint32_t version,uint32_t current){return version>current&&hash15(p,n)==expected;}
int main(void){uint8_t p[]="SAFE-UPDATE";uint32_t h=hash15(p,sizeof p-1);printf("%d\n",lab15_update_verifier(p,sizeof p-1,h,2,1));return 0;}
```

## Actual baseline output

```text
1
```

## Ghidra stripped analysis

Recover FNV hash, version monotonicity, exact expected comparison, and Boolean acceptance.

```c
FUNCTION FUN_00101220
ENTRY 00101220
SIGNATURE undefined FUN_00101220(void)
CALLERS 00102034, 001020b4, 001010ae

bool FUN_00101220(undefined8 param_1,undefined8 param_2,int param_3,uint param_4,uint param_5)

{
  int iVar1;

  if (param_5 < param_4) {
    iVar1 = FUN_001011e0();
    return iVar1 == param_3;
  }
  return false;
}
```

## Full function assembly

```asm
reversing-walkthrough-lab/build/ch08/15_update_verifier_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001220 <lab15_update_verifier>:
    1220:	41 39 c8             	cmp    r8d,ecx
    1223:	73 1b                	jae    1240 <lab15_update_verifier+0x20>
    1225:	55                   	push   rbp
    1226:	89 d1                	mov    ecx,edx
    1228:	48 89 e5             	mov    rbp,rsp
    122b:	e8 b0 ff ff ff       	call   11e0 <hash15>
    1230:	5d                   	pop    rbp
    1231:	39 c8                	cmp    eax,ecx
    1233:	0f 94 c0             	sete   al
    1236:	0f b6 c0             	movzx  eax,al
    1239:	c3                   	ret
    123a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1240:	31 c0                	xor    eax,eax
    1242:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg evidence

```text
TRACE_BREAKPOINTS 1 lab15_update_verifier
=== PWNDBG_EVIDENCE lab15_update_verifier ===
 RAX  0x83a09b3e
 RCX  2
 RDX  0x83a09b3e
 RDI  0x7fffffffe12c ◂— 'SAFE-UPDATE'
 RSI  0xb
 R8   1
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe118 —▸ 0x5555555550b3 (main+83) ◂— lea rdi, [rip + 0xf4a]
 RIP  0x555555555220 (lab15_update_verifier) ◂— cmp r8d, ecx
   0x555555555223 <lab15_update_verifier+3>   ✘ jae    lab15_update_verifier+32    <lab15_update_verifier+32>
   0x555555555225 <lab15_update_verifier+5>     push   rbp
   0x555555555226 <lab15_update_verifier+6>     mov    ecx, edx     ECX => 0x83a09b3e
   0x555555555228 <lab15_update_verifier+8>     mov    rbp, rsp     RBP => 0x7fffffffe110 —▸ 0x7fffffffe140 —▸ 0x7fffffffe1f0 —▸ 0x7fffffffe250 ◂— ...
   0x55555555522b <lab15_update_verifier+11>    call   hash15                      <hash15>
   0x555555555230 <lab15_update_verifier+16>    pop    rbp
   0x555555555231 <lab15_update_verifier+17>    cmp    eax, ecx
   0x555555555233 <lab15_update_verifier+19>    sete   al
   0x555555555236 <lab15_update_verifier+22>    movzx  eax, al
   0x555555555239 <lab15_update_verifier+25>    ret
=> 0x555555555220 <lab15_update_verifier>:	cmp    r8d,ecx
   0x555555555223 <lab15_update_verifier+3>:	jae    0x555555555240 <lab15_update_verifier+32>
   0x555555555225 <lab15_update_verifier+5>:	push   rbp
   0x555555555226 <lab15_update_verifier+6>:	mov    ecx,edx
   0x555555555228 <lab15_update_verifier+8>:	mov    rbp,rsp
   0x55555555522b <lab15_update_verifier+11>:	call   0x5555555551e0 <hash15>
   0x555555555230 <lab15_update_verifier+16>:	pop    rbp
```

## Complete analysis

1. Hash and classify this executable independently.
2. Identify sources, transforms, state machine/table, and all OS/API sinks.
3. Prove the modeled behavior from assembly and runtime inputs.
4. Explicitly search for the dangerous real-world sink and record whether it is absent.
5. Produce a capability claim limited to evidence: this specimen models `lab15_update_verifier` at RVA `0x1220` but does not perform the harmful operation.
6. Add a behavioral detection based on the stable transform/parser shape rather than its file hash alone.

## Defensive conclusion

The recovered behavior matches the source and baseline. The absence of destructive/network/persistence sinks is supported by imports, call graph, and trace for this specimen; it is not generalized to unrelated malware.

# Twenty Practice Questions

1. Why separate fifteen executables?
2. Why use .invalid?
3. What proves persistence is inert?
4. What proves unpacked bytes are not executed?
5. How prove a command handler?
6. What is an IOC versus behavior?
7. How recognize DGA?
8. What makes parser evidence strong?
9. Why is sandbox score not proof of malware?
10. How assign proxy roles?
11. What is persistence graph?
12. How validate a decoded config?
13. Why classify strings cautiously?
14. What is a safe malware lab?
15. How analyze cleanup?
16. How distinguish staging from exfiltration?
17. Why record absence claims?
18. How handle packed malware?
19. What is a capability confidence table?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** It prevents one shared dispatcher from manufacturing false cross-sample relationships and gives each sample independent hashes/imports/CFG.
4. State confidence, unobserved paths, and safe validation method.

## 2. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** It is reserved for non-routable examples and prevents accidental real command infrastructure.
4. State confidence, unobserved paths, and safe validation method.

## 3. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Only snprintf/output calls exist; no filesystem, registry, service, or process-creation sink.
4. State confidence, unobserved paths, and safe validation method.

## 4. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** No permission change or indirect transfer targets the output buffer.
4. State confidence, unobserved paths, and safe validation method.

## 5. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Input token/data path reaches a bounded dispatcher and an indirect target with observed effects.
4. State confidence, unobserved paths, and safe validation method.

## 6. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** IOC is a concrete artifact/value; behavior is a semantic sequence that can survive repacking.
4. State confidence, unobserved paths, and safe validation method.

## 7. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Time/seed recurrence produces domain-like labels; suffix and no resolver call show inert scope here.
4. State confidence, unobserved paths, and safe validation method.

## 8. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Receive/input buffer, framing/token logic, branch, and downstream handler are all connected.
4. State confidence, unobserved paths, and safe validation method.

## 9. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Legitimate diagnostics can inspect the same properties; context and consequences matter.
4. State confidence, unobserved paths, and safe validation method.

## 10. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Real sample requires socket/bind/listen/accept/connect/forward flows; this specimen models only request parsing.
4. State confidence, unobserved paths, and safe validation method.

## 11. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Creator→artifact→trigger edges including cycles that restore removed components.
4. State confidence, unobserved paths, and safe validation method.

## 12. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Capture before/after, reproduce transform, check consumers, and test wrong key.
4. State confidence, unobserved paths, and safe validation method.

## 13. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** They can be dead, fake, encoded, or library data without reachable behavior.
4. State confidence, unobserved paths, and safe validation method.

## 14. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Disposable isolated host, no public/production route, fake services, external telemetry, snapshots.
4. State confidence, unobserved paths, and safe validation method.

## 15. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Trace exact path/artifact construction to destructive APIs; plan bits alone are not deletion.
4. State confidence, unobserved paths, and safe validation method.

## 16. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Staging collects/encodes locally; exfiltration requires an outbound sink/protocol/destination.
4. State confidence, unobserved paths, and safe validation method.

## 17. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Saying “no network” requires import/call/runtime evidence and is scoped to observed/analyzed paths.
4. State confidence, unobserved paths, and safe validation method.

## 18. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Find decode writes and execution transition, capture plaintext window, rebuild/analyze mappings.
4. State confidence, unobserved paths, and safe validation method.

## 19. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Static path, dynamic proof, preconditions, effects, and uncertainty for each claimed capability.
4. State confidence, unobserved paths, and safe validation method.

## 20. Solution

1. Separate observed capability from assumed operator intent.
2. Trace input through parser/transform to a concrete sink.
3. **Answer:** Independently reverse all fifteen stripped specimens and produce behavior/IOC/persistence/protocol reports matching executed evidence.
4. State confidence, unobserved paths, and safe validation method.


Return to [[Chapter 08 - Reversing Malware]].
