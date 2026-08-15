# Chapter 5 — Fifteen Complete Undocumented-API Walkthroughs

> [!evidence]
> This is an executed clean-room generic-table investigation designed to reproduce the chapter’s method. One stripped binary exposes fifteen mutually corroborating functions.

## Baseline

```text
chapter05 evidence=8880656752 empty=1
Ghidra analyzed stripped artifact; pwndbg installed 15 symbol-correlated evidence breakpoints.
```

## Complete source (ground truth opened only after blind recovery)

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NI __attribute__((noinline))
volatile uint64_t evidence_sink;
typedef int (*cmp_fn)(const void*,const void*);
typedef void *(*alloc_fn)(size_t);
typedef void (*free_fn)(void*);

typedef struct Node{
 struct Node *left,*right,*parent,*prev,*next;
 uint32_t size;
 unsigned char data[];
}Node;
typedef struct Table{
 Node *root,*head,*tail,*cache;
 size_t count,cache_index;
 cmp_fn compare;alloc_fn allocate;free_fn release;
}Table;

NI int keycmp(const void*a,const void*b){int x,y;memcpy(&x,a,4);memcpy(&y,b,4);return (x>y)-(x<y);}
NI void lab01_initialize(Table*t,cmp_fn c,alloc_fn a,free_fn f){memset(t,0,sizeof *t);t->compare=c;t->allocate=a;t->release=f;}
NI size_t lab02_count(const Table*t){return t->count;}
NI int lab03_empty(const Table*t){return t->root==0;}
NI void *lab04_payload(Node*n){return n?n->data:0;}
NI Node *lab05_locate(Table*t,const void*key,Node**parent,int*side){
 Node*n=t->root,*p=0;int s=0;while(n){p=n;s=t->compare(key,n->data);if(!s){*parent=p;*side=0;return n;}n=s<0?n->left:n->right;}
 *parent=p;*side=s<0?-1:1;return 0;
}
NI void lab06_link_list(Table*t,Node*n){n->prev=t->tail;n->next=0;if(t->tail)t->tail->next=n;else t->head=n;t->tail=n;}
NI void lab07_link_tree(Table*t,Node*n,Node*p,int side){n->parent=p;if(!p)t->root=n;else if(side<0)p->left=n;else p->right=n;}
NI void *lab08_insert(Table*t,const void*data,uint32_t size,int*created){
 Node*p=0;int side=0;Node*found=lab05_locate(t,data,&p,&side);if(found){*created=0;return found->data;}
 Node*n=t->allocate(sizeof(Node)+size);if(!n){*created=0;return 0;}memset(n,0,sizeof *n);n->size=size;memcpy(n->data,data,size);
 lab07_link_tree(t,n,p,side);lab06_link_list(t,n);t->count++;t->cache=n;t->cache_index=t->count-1;*created=1;return n->data;
}
NI void *lab09_lookup(Table*t,const void*key){Node*p;int side;Node*n=lab05_locate(t,key,&p,&side);return n?n->data:0;}
NI void *lab10_get_index(Table*t,size_t index){
 if(index>=t->count)return 0;Node*n;size_t i;
 if(t->cache&&index>=t->cache_index){n=t->cache;i=t->cache_index;}else{n=t->head;i=0;}
 while(i<index){n=n->next;i++;}t->cache=n;t->cache_index=i;return n->data;
}
NI Node *lab11_minimum(Node*n){if(!n)return 0;while(n->left)n=n->left;return n;}
NI void lab12_transplant(Table*t,Node*u,Node*v){if(!u->parent)t->root=v;else if(u==u->parent->left)u->parent->left=v;else u->parent->right=v;if(v)v->parent=u->parent;}
NI void lab13_unlink_list(Table*t,Node*n){if(n->prev)n->prev->next=n->next;else t->head=n->next;if(n->next)n->next->prev=n->prev;else t->tail=n->prev;}
NI int lab14_delete(Table*t,const void*key){
 Node*p;int side;Node*z=lab05_locate(t,key,&p,&side);if(!z)return 0;
 if(!z->left)lab12_transplant(t,z,z->right);else if(!z->right)lab12_transplant(t,z,z->left);else{Node*y=lab11_minimum(z->right);
 if(y->parent!=z){lab12_transplant(t,y,y->right);y->right=z->right;y->right->parent=y;}lab12_transplant(t,z,y);y->left=z->left;y->left->parent=y;}
 lab13_unlink_list(t,z);t->count--;t->cache=0;t->cache_index=0;t->release(z);return 1;
}
NI uint64_t lab15_invariant(const Table*t){
 size_t list_count=0;uint64_t h=0;for(Node*n=t->head;n;n=n->next){list_count++;int k;memcpy(&k,n->data,4);h=h*131u+(uint32_t)k;if(n->next&&n->next->prev!=n)return UINT64_MAX;}
 return list_count==t->count?h:UINT64_MAX;
}
int main(void){Table t;lab01_initialize(&t,keycmp,malloc,free);int vals[]={30,10,20,40,35},created;uint64_t total=0;
 total+=lab02_count(&t)+lab03_empty(&t);for(int i=0;i<5;i++){int*p=lab08_insert(&t,&vals[i],4,&created);total+=p?*p:0;total+=created;}
 int dup=20;lab08_insert(&t,&dup,4,&created);total+=created;int key=35;int*p=lab09_lookup(&t,&key);total+=p?*p:0;
 for(size_t i=0;i<t.count;i++){p=lab10_get_index(&t,i);total+=p?*p:0;}total+=lab15_invariant(&t);key=30;total+=lab14_delete(&t,&key);total+=lab15_invariant(&t);
 while(t.head){int k;memcpy(&k,t.head->data,4);lab14_delete(&t,&k);}evidence_sink=total;printf("chapter05 evidence=%llu empty=%d\n",(unsigned long long)total,lab03_empty(&t));return 0;}
```

# Walkthrough 01 — Initialize header and callbacks

## Target

Analyze stripped `FUN_00101420`. Zero table state and recover compare/allocate/free callback fields.

## Ghidra output

```c
FUNCTION FUN_00101420
ENTRY 00101420
SIGNATURE undefined FUN_00101420(void)
CALLERS 0010206c, 0010215c, 001010d6

void FUN_00101420(undefined1 (*param_1) [16],undefined8 param_2,undefined8 param_3,
                 undefined8 param_4)

{
  *(undefined8 *)param_1[3] = param_2;
  *(undefined8 *)(param_1[3] + 8) = param_3;
  *(undefined8 *)param_1[4] = param_4;
  *param_1 = (undefined1  [16])0x0;
  param_1[1] = (undefined1  [16])0x0;
  param_1[2] = (undefined1  [16])0x0;
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001420 <lab01_initialize>:
    1420:	66 0f ef c0          	pxor   xmm0,xmm0
    1424:	48 89 77 30          	mov    QWORD PTR [rdi+0x30],rsi
    1428:	48 89 57 38          	mov    QWORD PTR [rdi+0x38],rdx
    142c:	48 89 4f 40          	mov    QWORD PTR [rdi+0x40],rcx
    1430:	0f 11 07             	movups XMMWORD PTR [rdi],xmm0
    1433:	0f 11 47 10          	movups XMMWORD PTR [rdi+0x10],xmm0
    1437:	0f 11 47 20          	movups XMMWORD PTR [rdi+0x20],xmm0
    143b:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  0x7fffffffe120 ◂— 0xb700000006
 RCX  0x7ffff7ca9080 (free) ◂— endbr64
 RDX  0x7ffff7ca8b30 (malloc) ◂— endbr64
 RDI  0x7fffffffe0d0 ◂— 0x40 /* '@' */
 RSI  0x555555555400 (keycmp) ◂— mov eax, dword ptr [rsi]
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555550db (main+91) ◂— mov dword ptr [rbp - 0x30], 0x23
 RIP  0x555555555420 (lab01_initialize) ◂— pxor xmm0, xmm0
   0x555555555424 <lab01_initialize+4>     mov    qword ptr [rdi + 0x30], rsi        [0x7fffffffe100] <= 0x555555555400 (keycmp) ◂— mov eax, dword ptr [rsi]
   0x555555555428 <lab01_initialize+8>     mov    qword ptr [rdi + 0x38], rdx        [0x7fffffffe108] <= 0x7ffff7ca8b30 (malloc) ◂— endbr64
   0x55555555542c <lab01_initialize+12>    mov    qword ptr [rdi + 0x40], rcx        [0x7fffffffe110] <= 0x7ffff7ca9080 (free) ◂— endbr64
   0x555555555430 <lab01_initialize+16>    movups xmmword ptr [rdi], xmm0
   0x555555555433 <lab01_initialize+19>    movups xmmword ptr [rdi + 0x10], xmm0
   0x555555555437 <lab01_initialize+23>    movups xmmword ptr [rdi + 0x20], xmm0
   0x55555555543b <lab01_initialize+27>    ret                                <main+91>
   0x5555555550db <main+91>                mov    dword ptr [rbp - 0x30], 0x23        [0x7fffffffe130] <= 0x23
   0x5555555550e2 <main+98>                mov    rsi, qword ptr [rbp - 0x88]         RSI, [0x7fffffffe0d8] => 0
   0x5555555550e9 <main+105>               movdqa xmm0, xmmword ptr [rip + 0xf3f]
=> 0x555555555420 <lab01_initialize>:	pxor   xmm0,xmm0
   0x555555555424 <lab01_initialize+4>:	mov    QWORD PTR [rdi+0x30],rsi
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab01_initialize` at RVA `0x1420`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 02 — Count accessor

## Target

Analyze stripped `FUN_00101440`. Identify the size_t count field from a minimal accessor.

## Ghidra output

```c
FUNCTION FUN_00101440
ENTRY 00101440
SIGNATURE undefined FUN_00101440(void)
CALLERS 00102074, 00102170, 001010f9

undefined8 FUN_00101440(long param_1)

{
  return *(undefined8 *)(param_1 + 0x20);
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001440 <lab02_count>:
    1440:	48 8b 47 20          	mov    rax,QWORD PTR [rdi+0x20]
    1444:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  0x7fffffffe120 ◂— 0xa0000001e
 RCX  0
 RDX  0x7ffff7ca8b30 (malloc) ◂— endbr64
 RDI  0x7fffffffe0d0 ◂— 0
 RSI  0
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555550fe (main+126) ◂— mov rdx, rax
 RIP  0x555555555440 (lab02_count) ◂— mov rax, qword ptr [rdi + 0x20]
   0x555555555444 <lab02_count+4>    ret                                <main+126>
   0x5555555550fe <main+126>         mov    rdx, rax                        RDX => 0
   0x555555555101 <main+129>         call   lab03_empty                 <lab03_empty>
   0x555555555106 <main+134>         mov    r12d, eax
   0x555555555109 <main+137>         add    r12, rdx
   0x55555555510c <main+140>         mov    qword ptr [rbp - 0x70], rcx
   0x555555555110 <main+144>         mov    edx, 4                          EDX => 4
   0x555555555115 <main+149>         lea    rcx, [rbp - 0xa0]
   0x55555555511c <main+156>         lea    rdi, [rbp - 0x90]
   0x555555555123 <main+163>         mov    qword ptr [rbp - 0x88], rsi
=> 0x555555555440 <lab02_count>:	mov    rax,QWORD PTR [rdi+0x20]
   0x555555555444 <lab02_count+4>:	ret
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab02_count` at RVA `0x1440`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 03 — Emptiness predicate

## Target

Analyze stripped `FUN_00101450`. Distinguish root-null representation from count comparison.

## Ghidra output

```c
FUNCTION FUN_00101450
ENTRY 00101450
SIGNATURE undefined FUN_00101450(void)
CALLERS 0010207c, 00102184, 00101101, 001012a9

bool FUN_00101450(long *param_1)

{
  return *param_1 == 0;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001450 <lab03_empty>:
    1450:	31 c0                	xor    eax,eax
    1452:	48 83 3f 00          	cmp    QWORD PTR [rdi],0x0
    1456:	0f 94 c0             	sete   al
    1459:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  0x7fffffffe120 ◂— 0xa0000001e
 RCX  0
 RDX  0
 RDI  0x7fffffffe0d0 ◂— 0
 RSI  0
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x555555555106 (main+134) ◂— mov r12d, eax
 RIP  0x555555555450 (lab03_empty) ◂— xor eax, eax
   0x555555555452 <lab03_empty+2>    cmp    qword ptr [rdi], 0     0 - 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555456 <lab03_empty+6>    sete   al
   0x555555555459 <lab03_empty+9>    ret                                <main+134>
   0x555555555106 <main+134>         mov    r12d, eax                       R12D => 1
   0x555555555109 <main+137>         add    r12, rdx                        R12 => 1 (1 + 0)
   0x55555555510c <main+140>         mov    qword ptr [rbp - 0x70], rcx     [0x7fffffffe0f0] <= 0
   0x555555555110 <main+144>         mov    edx, 4                          EDX => 4
   0x555555555115 <main+149>         lea    rcx, [rbp - 0xa0]               RCX => 0x7fffffffe0c0 ◂— 0x400000
   0x55555555511c <main+156>         lea    rdi, [rbp - 0x90]               RDI => 0x7fffffffe0d0 ◂— 0
   0x555555555123 <main+163>         mov    qword ptr [rbp - 0x88], rsi     [0x7fffffffe0d8] <= 0
=> 0x555555555450 <lab03_empty>:	xor    eax,eax
   0x555555555452 <lab03_empty+2>:	cmp    QWORD PTR [rdi],0x0
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab03_empty` at RVA `0x1450`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 04 — Internal node to payload

## Target

Analyze stripped `FUN_00101460`. Recover fixed hidden-header adjustment and null behavior.

## Ghidra output

```c
FUNCTION FUN_00101460
ENTRY 00101460
SIGNATURE undefined FUN_00101460(void)
CALLERS 00102084, 00102198

long FUN_00101460(long param_1)

{
  long lVar1;

  lVar1 = param_1 + 0x2c;
  if (param_1 == 0) {
    lVar1 = 0;
  }
  return lVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001460 <lab04_payload>:
    1460:	31 d2                	xor    edx,edx
    1462:	48 8d 47 2c          	lea    rax,[rdi+0x2c]
    1466:	48 85 ff             	test   rdi,rdi
    1469:	48 0f 44 c2          	cmove  rax,rdx
    146d:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text

```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab04_payload` at RVA `0x1460`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 05 — Comparator-driven BST search

## Target

Analyze stripped `FUN_00101470`. Recover compare callback arguments, three-way branch, parent/side outputs, and equality.

## Ghidra output

```c
FUNCTION FUN_00101470
ENTRY 00101470
SIGNATURE undefined FUN_00101470(void)
CALLERS 0010208c, 001021ac, 001015b9, 001016ad, 00101811

undefined8 * FUN_00101470(long *param_1,undefined8 param_2,long *param_3,uint *param_4)

{
  int iVar1;
  uint uVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;

  puVar4 = (undefined8 *)*param_1;
  puVar3 = puVar4;
  if (puVar4 == (undefined8 *)0x0) {
    puVar3 = (undefined8 *)0x0;
    uVar2 = 1;
  }
  else {
    do {
      puVar4 = puVar3;
      iVar1 = (*(code *)param_1[6])(param_2,(long)puVar4 + 0x2c);
      if (iVar1 == 0) {
        uVar2 = 0;
        puVar3 = puVar4;
        goto LAB_001014d1;
      }
      puVar3 = (undefined8 *)puVar4[1];
      if (iVar1 < 0) {
        puVar3 = (undefined8 *)*puVar4;
      }
    } while (puVar3 != (undefined8 *)0x0);
    uVar2 = iVar1 >> 0x1f | 1;
  }
LAB_001014d1:
  *param_3 = (long)puVar4;
  *param_4 = uVar2;
  return puVar3;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001470 <lab05_locate>:
    1470:	55                   	push   rbp
    1471:	48 89 e5             	mov    rbp,rsp
    1474:	48 83 ec 30          	sub    rsp,0x30
    1478:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    147c:	4c 8b 3f             	mov    r15,QWORD PTR [rdi]
    147f:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1483:	49 89 cd             	mov    r13,rcx
    1486:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    148a:	49 89 d6             	mov    r14,rdx
    148d:	4d 85 ff             	test   r15,r15
    1490:	74 6e                	je     1500 <lab05_locate+0x90>
    1492:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    1496:	48 89 fb             	mov    rbx,rdi
    1499:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    149d:	49 89 f4             	mov    r12,rsi
    14a0:	eb 16                	jmp    14b8 <lab05_locate+0x48>
    14a2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    14a8:	49 8b 57 08          	mov    rdx,QWORD PTR [r15+0x8]
    14ac:	49 0f 48 17          	cmovs  rdx,QWORD PTR [r15]
    14b0:	48 85 d2             	test   rdx,rdx
    14b3:	74 3b                	je     14f0 <lab05_locate+0x80>
    14b5:	49 89 d7             	mov    r15,rdx
    14b8:	49 8d 77 2c          	lea    rsi,[r15+0x2c]
    14bc:	4c 89 e7             	mov    rdi,r12
    14bf:	ff 53 30             	call   QWORD PTR [rbx+0x30]
    14c2:	85 c0                	test   eax,eax
    14c4:	75 e2                	jne    14a8 <lab05_locate+0x38>
    14c6:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    14ca:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    14ce:	4c 89 fa             	mov    rdx,r15
    14d1:	4d 89 3e             	mov    QWORD PTR [r14],r15
    14d4:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    14d8:	41 89 45 00          	mov    DWORD PTR [r13+0x0],eax
    14dc:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    14e0:	48 89 d0             	mov    rax,rdx
    14e3:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    14e7:	c9                   	leave
    14e8:	c3                   	ret
    14e9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    14f0:	c1 f8 1f             	sar    eax,0x1f
    14f3:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    14f7:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    14fb:	83 c8 01             	or     eax,0x1
    14fe:	eb d1                	jmp    14d1 <lab05_locate+0x61>
    1500:	31 d2                	xor    edx,edx
    1502:	b8 01 00 00 00       	mov    eax,0x1
    1507:	eb c8                	jmp    14d1 <lab05_locate+0x61>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0x7fffffffe0d0 ◂— 0
 RCX  0x7fffffffe06c ◂— 0x4000000000
 RDX  0x7fffffffe070 {p} ◂— 0x40 /* '@' */
 RDI  0x7fffffffe0d0 ◂— 0
 RSI  0x7fffffffe120 ◂— 0xa0000001e
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe048 —▸ 0x5555555555be (lab08_insert+62) ◂— test rax, rax
 RIP  0x555555555470 (lab05_locate) ◂— push rbp
   0x555555555471 <lab05_locate+1>     mov    rbp, rsp                        RBP => 0x7fffffffe040 —▸ 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 ◂— ...
   0x555555555474 <lab05_locate+4>     sub    rsp, 0x30                       RSP => 0x7fffffffe010 (0x7fffffffe040 - 0x30)
   0x555555555478 <lab05_locate+8>     mov    qword ptr [rbp - 8], r15        [0x7fffffffe038] <= 4
   0x55555555547c <lab05_locate+12>    mov    r15, qword ptr [rdi]            R15, [0x7fffffffe0d0] => 0
   0x55555555547f <lab05_locate+15>    mov    qword ptr [rbp - 0x18], r13     [0x7fffffffe028] <= 0x7fffffffe120 ◂— 0xa0000001e
   0x555555555483 <lab05_locate+19>    mov    r13, rcx                        R13 => 0x7fffffffe06c ◂— 0x4000000000
   0x555555555486 <lab05_locate+22>    mov    qword ptr [rbp - 0x10], r14     [0x7fffffffe030] <= 0x7fffffffe0c0 ◂— 0x400000
   0x55555555548a <lab05_locate+26>    mov    r14, rdx                        R14 => 0x7fffffffe070 ◂— 0x40 /* '@' */
   0x55555555548d <lab05_locate+29>    test   r15, r15                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555490 <lab05_locate+32>  ✔ je     lab05_locate+144            <lab05_locate+144>
=> 0x555555555470 <lab05_locate>:	push   rbp
   0x555555555471 <lab05_locate+1>:	mov    rbp,rsp
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab05_locate` at RVA `0x1470`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 06 — Insertion-order list link

## Target

Analyze stripped `FUN_00101510`. Recover head/tail fields and prev/next node offsets.

## Ghidra output

```c
FUNCTION FUN_00101510
ENTRY 00101510
SIGNATURE undefined FUN_00101510(void)
CALLERS 00102094, 001021e8, 0010164a

void FUN_00101510(long param_1,long param_2)

{
  undefined8 uVar1;

  uVar1 = *(undefined8 *)(param_1 + 0x10);
  *(undefined8 *)(param_2 + 0x20) = 0;
  *(undefined8 *)(param_2 + 0x18) = uVar1;
  if (*(long *)(param_1 + 0x10) != 0) {
    *(long *)(*(long *)(param_1 + 0x10) + 0x20) = param_2;
    *(long *)(param_1 + 0x10) = param_2;
    return;
  }
  *(long *)(param_1 + 8) = param_2;
  *(long *)(param_1 + 0x10) = param_2;
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001510 <lab06_link_list>:
    1510:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
    1514:	48 c7 46 20 00 00 00 	mov    QWORD PTR [rsi+0x20],0x0
    151b:	00
    151c:	48 89 46 18          	mov    QWORD PTR [rsi+0x18],rax
    1520:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
    1524:	48 85 c0             	test   rax,rax
    1527:	74 0f                	je     1538 <lab06_link_list+0x28>
    1529:	48 89 70 20          	mov    QWORD PTR [rax+0x20],rsi
    152d:	48 89 77 10          	mov    QWORD PTR [rdi+0x10],rsi
    1531:	c3                   	ret
    1532:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1538:	48 89 77 08          	mov    QWORD PTR [rdi+0x8],rsi
    153c:	48 89 77 10          	mov    QWORD PTR [rdi+0x10],rsi
    1540:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x55555555903c ◂— 0x55555555903c
 RBX  0x7fffffffe0d0 —▸ 0x555555559010 ◂— 0x555555559010
 RCX  1
 RDX  0
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 ◂— 0x555555559010
 RSI  0x555555559010 ◂— 0x555555559010
 R8   0x21001
 R9   0
 RSP  0x7fffffffe048 —▸ 0x55555555564f (lab08_insert+207) ◂— mov rax, qword ptr [rbx + 0x20]
 RIP  0x555555555510 (lab06_link_list) ◂— mov rax, qword ptr [rdi + 0x10]
   0x555555555514 <lab06_link_list+4>     mov    qword ptr [rsi + 0x20], 0       [0x555555559030] <= 0
   0x55555555551c <lab06_link_list+12>    mov    qword ptr [rsi + 0x18], rax     [0x555555559028] <= 0
   0x555555555520 <lab06_link_list+16>    mov    rax, qword ptr [rdi + 0x10]     RAX, [0x7fffffffe0e0] => 0
   0x555555555524 <lab06_link_list+20>    test   rax, rax                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555527 <lab06_link_list+23>  ✔ je     lab06_link_list+40          <lab06_link_list+40>
   0x555555555538 <lab06_link_list+40>    mov    qword ptr [rdi + 8], rsi        [0x7fffffffe0d8] <= 0x555555559010
   0x55555555553c <lab06_link_list+44>    mov    qword ptr [rdi + 0x10], rsi     [0x7fffffffe0e0] <= 0x555555559010
   0x555555555540 <lab06_link_list+48>    ret                                <lab08_insert+207>
   0x55555555564f <lab08_insert+207>      mov    rax, qword ptr [rbx + 0x20]     RAX, [0x7fffffffe0f0] => 0
   0x555555555653 <lab08_insert+211>      mov    qword ptr [rbx + 0x18], r12     [0x7fffffffe0e8] <= 0x555555559010
=> 0x555555555510 <lab06_link_list>:	mov    rax,QWORD PTR [rdi+0x10]
   0x555555555514 <lab06_link_list+4>:	mov    QWORD PTR [rsi+0x20],0x0
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab06_link_list` at RVA `0x1510`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 07 — Parent-child tree link

## Target

Analyze stripped `FUN_00101550`. Recover root special case and left/right selection.

## Ghidra output

```c
FUNCTION FUN_00101550
ENTRY 00101550
SIGNATURE undefined FUN_00101550(void)
CALLERS 0010209c, 001021fc, 00101645

void FUN_00101550(long *param_1,long param_2,long *param_3,int param_4)

{
  *(long **)(param_2 + 0x10) = param_3;
  if (param_3 == (long *)0x0) {
    *param_1 = param_2;
    return;
  }
  if (-1 < param_4) {
    param_3[1] = param_2;
    return;
  }
  *param_3 = param_2;
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001550 <lab07_link_tree>:
    1550:	48 89 56 10          	mov    QWORD PTR [rsi+0x10],rdx
    1554:	48 85 d2             	test   rdx,rdx
    1557:	74 17                	je     1570 <lab07_link_tree+0x20>
    1559:	85 c9                	test   ecx,ecx
    155b:	78 0b                	js     1568 <lab07_link_tree+0x18>
    155d:	48 89 72 08          	mov    QWORD PTR [rdx+0x8],rsi
    1561:	c3                   	ret
    1562:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1568:	48 89 32             	mov    QWORD PTR [rdx],rsi
    156b:	c3                   	ret
    156c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1570:	48 89 37             	mov    QWORD PTR [rdi],rsi
    1573:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x55555555903c ◂— 0x55555555903c
 RBX  0x7fffffffe0d0 ◂— 0
 RCX  1
 RDX  0
 RDI  0x7fffffffe0d0 ◂— 0
 RSI  0x555555559010 ◂— 0x555555559010
 R8   0x21001
 R9   0
 RSP  0x7fffffffe048 —▸ 0x55555555564a (lab08_insert+202) ◂— call lab06_link_list
 RIP  0x555555555550 (lab07_link_tree) ◂— mov qword ptr [rsi + 0x10], rdx
   0x555555555554 <lab07_link_tree+4>     test   rdx, rdx                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555557 <lab07_link_tree+7>   ✔ je     lab07_link_tree+32          <lab07_link_tree+32>
   0x555555555570 <lab07_link_tree+32>    mov    qword ptr [rdi], rsi            [0x7fffffffe0d0] <= 0x555555559010
   0x555555555573 <lab07_link_tree+35>    ret                                <lab08_insert+202>
   0x55555555564a <lab08_insert+202>      call   lab06_link_list             <lab06_link_list>
   0x55555555564f <lab08_insert+207>      mov    rax, qword ptr [rbx + 0x20]
   0x555555555653 <lab08_insert+211>      mov    qword ptr [rbx + 0x18], r12
   0x555555555657 <lab08_insert+215>      mov    r12, qword ptr [rbp - 0x20]
   0x55555555565b <lab08_insert+219>      lea    rdx, [rax + 1]
   0x55555555565f <lab08_insert+223>      mov    qword ptr [rbx + 0x28], rax
=> 0x555555555550 <lab07_link_tree>:	mov    QWORD PTR [rsi+0x10],rdx
   0x555555555554 <lab07_link_tree+4>:	test   rdx,rdx
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab07_link_tree` at RVA `0x1550`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 08 — Complete generic insertion

## Target

Analyze stripped `FUN_00101580`. Compose locate, allocate, metadata init, payload copy, tree/list linkage, count/cache, and created flag.

## Ghidra output

```c
FUNCTION FUN_00101580
ENTRY 00101580
SIGNATURE undefined FUN_00101580(void)
CALLERS 001020a4, 00102210, 0010112d, 00101181

void * FUN_00101580(long param_1,void *param_2,uint param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  long lVar2;
  undefined1 (*pauVar3) [16];
  void *__dest;
  long in_FS_OFFSET;
  undefined4 local_4c;
  undefined8 local_48;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  lVar2 = FUN_00101470(param_1,param_2,&local_48,&local_4c);
  if (lVar2 == 0) {
    pauVar3 = (undefined1 (*) [16])(**(code **)(param_1 + 0x38))((ulong)param_3 + 0x30);
    if (pauVar3 == (undefined1 (*) [16])0x0) {
      __dest = (void *)0x0;
      uVar1 = 0;
    }
    else {
      pauVar3[2] = (undefined1  [16])0x0;
      *(uint *)(pauVar3[2] + 8) = param_3;
      __dest = pauVar3[2] + 0xc;
      *pauVar3 = (undefined1  [16])0x0;
      pauVar3[1] = (undefined1  [16])0x0;
      memcpy(__dest,param_2,(ulong)param_3);
      FUN_00101550(param_1,pauVar3,local_48,local_4c);
      FUN_00101510();
      *(undefined1 (**) [16])(param_1 + 0x18) = pauVar3;
      *(long *)(param_1 + 0x28) = *(long *)(param_1 + 0x20);
      uVar1 = 1;
      *(long *)(param_1 + 0x20) = *(long *)(param_1 + 0x20) + 1;
    }
  }
  else {
    __dest = (void *)(lVar2 + 0x2c);
    uVar1 = 0;
  }
  *param_4 = uVar1;
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return __dest;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001580 <lab08_insert>:
    1580:	55                   	push   rbp
    1581:	48 89 e5             	mov    rbp,rsp
    1584:	48 83 ec 60          	sub    rsp,0x60
    1588:	48 89 5d d8          	mov    QWORD PTR [rbp-0x28],rbx
    158c:	48 89 fb             	mov    rbx,rdi
    158f:	4c 89 6d e8          	mov    QWORD PTR [rbp-0x18],r13
    1593:	49 89 f5             	mov    r13,rsi
    1596:	4c 89 7d f8          	mov    QWORD PTR [rbp-0x8],r15
    159a:	41 89 d7             	mov    r15d,edx
    159d:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
    15a1:	4c 89 75 f0          	mov    QWORD PTR [rbp-0x10],r14
    15a5:	64 4c 8b 34 25 28 00 	mov    r14,QWORD PTR fs:0x28
    15ac:	00 00
    15ae:	4c 89 75 c8          	mov    QWORD PTR [rbp-0x38],r14
    15b2:	49 89 ce             	mov    r14,rcx
    15b5:	48 8d 4d bc          	lea    rcx,[rbp-0x44]
    15b9:	e8 b2 fe ff ff       	call   1470 <lab05_locate>
    15be:	48 85 c0             	test   rax,rax
    15c1:	74 35                	je     15f8 <lab08_insert+0x78>
    15c3:	4c 8d 78 2c          	lea    r15,[rax+0x2c]
    15c7:	31 c0                	xor    eax,eax
    15c9:	41 89 06             	mov    DWORD PTR [r14],eax
    15cc:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
    15d0:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    15d7:	00 00
    15d9:	0f 85 a7 00 00 00    	jne    1686 <lab08_insert+0x106>
    15df:	4c 89 f8             	mov    rax,r15
    15e2:	48 8b 5d d8          	mov    rbx,QWORD PTR [rbp-0x28]
    15e6:	4c 8b 6d e8          	mov    r13,QWORD PTR [rbp-0x18]
    15ea:	4c 8b 75 f0          	mov    r14,QWORD PTR [rbp-0x10]
    15ee:	4c 8b 7d f8          	mov    r15,QWORD PTR [rbp-0x8]
    15f2:	c9                   	leave
    15f3:	c3                   	ret
    15f4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    15f8:	44 89 fa             	mov    edx,r15d
    15fb:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    15ff:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
    1603:	48 8d 7a 30          	lea    rdi,[rdx+0x30]
    1607:	ff 53 38             	call   QWORD PTR [rbx+0x38]
    160a:	49 89 c4             	mov    r12,rax
    160d:	48 85 c0             	test   rax,rax
    1610:	74 66                	je     1678 <lab08_insert+0xf8>
    1612:	66 0f ef c0          	pxor   xmm0,xmm0
    1616:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    161a:	4c 89 ee             	mov    rsi,r13
    161d:	0f 11 40 20          	movups XMMWORD PTR [rax+0x20],xmm0
    1621:	44 89 78 28          	mov    DWORD PTR [rax+0x28],r15d
    1625:	4c 8d 78 2c          	lea    r15,[rax+0x2c]
    1629:	4c 89 ff             	mov    rdi,r15
    162c:	0f 11 00             	movups XMMWORD PTR [rax],xmm0
    162f:	0f 11 40 10          	movups XMMWORD PTR [rax+0x10],xmm0
    1633:	e8 18 fa ff ff       	call   1050 <memcpy@plt>
    1638:	48 8b 55 c0          	mov    rdx,QWORD PTR [rbp-0x40]
    163c:	8b 4d bc             	mov    ecx,DWORD PTR [rbp-0x44]
    163f:	4c 89 e6             	mov    rsi,r12
    1642:	48 89 df             	mov    rdi,rbx
    1645:	e8 06 ff ff ff       	call   1550 <lab07_link_tree>
    164a:	e8 c1 fe ff ff       	call   1510 <lab06_link_list>
    164f:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
    1653:	4c 89 63 18          	mov    QWORD PTR [rbx+0x18],r12
    1657:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    165b:	48 8d 50 01          	lea    rdx,[rax+0x1]
    165f:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
    1663:	b8 01 00 00 00       	mov    eax,0x1
    1668:	48 89 53 20          	mov    QWORD PTR [rbx+0x20],rdx
    166c:	e9 58 ff ff ff       	jmp    15c9 <lab08_insert+0x49>
    1671:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1678:	4c 8b 65 e0          	mov    r12,QWORD PTR [rbp-0x20]
    167c:	45 31 ff             	xor    r15d,r15d
    167f:	31 c0                	xor    eax,eax
    1681:	e9 43 ff ff ff       	jmp    15c9 <lab08_insert+0x49>
    1686:	4c 89 65 e0          	mov    QWORD PTR [rbp-0x20],r12
    168a:	e8 a1 f9 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  1
 RBX  0x7fffffffe120 ◂— 0xa0000001e
 RCX  0x7fffffffe0c0 ◂— 0x400000
 RDX  4
 RDI  0x7fffffffe0d0 ◂— 0
 RSI  0x7fffffffe120 ◂— 0xa0000001e
 R8   0x7ffff7e13680 —▸ 0x7ffff7e14fa0 ◂— 0
 R9   0x7ffff7e14fa0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x555555555132 (main+178) ◂— mov rsi, qword ptr [rbp - 0x88]
 RIP  0x555555555580 (lab08_insert) ◂— push rbp
   0x555555555581 <lab08_insert+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555584 <lab08_insert+4>     sub    rsp, 0x60                       RSP => 0x7fffffffe050 (0x7fffffffe0b0 - 0x60)
   0x555555555588 <lab08_insert+8>     mov    qword ptr [rbp - 0x28], rbx     [0x7fffffffe088] <= 0x7fffffffe120 ◂— 0xa0000001e
   0x55555555558c <lab08_insert+12>    mov    rbx, rdi                        RBX => 0x7fffffffe0d0 ◂— 0
   0x55555555558f <lab08_insert+15>    mov    qword ptr [rbp - 0x18], r13     [0x7fffffffe098] <= 0x7fffffffe134 ◂— 0x873d860000000000
   0x555555555593 <lab08_insert+19>    mov    r13, rsi                        R13 => 0x7fffffffe120 ◂— 0xa0000001e
   0x555555555596 <lab08_insert+22>    mov    qword ptr [rbp - 8], r15        [0x7fffffffe0a8] <= 0x555555557dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555390 (__do_global_dtors_aux) ◂— endbr64
   0x55555555559a <lab08_insert+26>    mov    r15d, edx                       R15D => 4
   0x55555555559d <lab08_insert+29>    lea    rdx, [rbp - 0x40]               RDX => 0x7fffffffe070 ◂— 0x40 /* '@' */
   0x5555555555a1 <lab08_insert+33>    mov    qword ptr [rbp - 0x10], r14     [0x7fffffffe0a0] <= 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— ...
=> 0x555555555580 <lab08_insert>:	push   rbp
   0x555555555581 <lab08_insert+1>:	mov    rbp,rsp
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab08_insert` at RVA `0x1580`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 09 — Key lookup wrapper

## Target

Analyze stripped `FUN_00101690`. Recover payload return layered over internal locate.

## Ghidra output

```c
FUNCTION FUN_00101690
ENTRY 00101690
SIGNATURE undefined FUN_00101690(void)
CALLERS 001020ac, 0010224c, 001011b3

long FUN_00101690(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  long in_FS_OFFSET;
  undefined1 local_1c [4];
  undefined1 local_18 [8];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = FUN_00101470(param_1,param_2,local_18,local_1c);
  if (lVar1 != 0) {
    lVar1 = lVar1 + 0x2c;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return lVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001690 <lab09_lookup>:
    1690:	55                   	push   rbp
    1691:	48 89 e5             	mov    rbp,rsp
    1694:	48 83 ec 20          	sub    rsp,0x20
    1698:	64 48 8b 0c 25 28 00 	mov    rcx,QWORD PTR fs:0x28
    169f:	00 00
    16a1:	48 89 4d f8          	mov    QWORD PTR [rbp-0x8],rcx
    16a5:	48 8d 4d ec          	lea    rcx,[rbp-0x14]
    16a9:	48 8d 55 f0          	lea    rdx,[rbp-0x10]
    16ad:	e8 be fd ff ff       	call   1470 <lab05_locate>
    16b2:	48 8d 50 2c          	lea    rdx,[rax+0x2c]
    16b6:	48 85 c0             	test   rax,rax
    16b9:	48 0f 45 c2          	cmovne rax,rdx
    16bd:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    16c1:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    16c8:	00 00
    16ca:	75 02                	jne    16ce <lab09_lookup+0x3e>
    16cc:	c9                   	leave
    16cd:	c3                   	ret
    16ce:	e8 5d f9 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0
 RBX  5
 RCX  0x7fffffffe06c ◂— 0x5555909000000000
 RDX  0x555555559090 ◂— 0x555555559090
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  0x7fffffffe0c8 ◂— 0x23 /* '#' */
 R8   0x34
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555551b8 (main+312) ◂— xor r8d, r8d
 RIP  0x555555555690 (lab09_lookup) ◂— push rbp
   0x555555555691 <lab09_lookup+1>     mov    rbp, rsp                     RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x555555555694 <lab09_lookup+4>     sub    rsp, 0x20                    RSP => 0x7fffffffe090 (0x7fffffffe0b0 - 0x20)
   0x555555555698 <lab09_lookup+8>     mov    rcx, qword ptr fs:[0x28]     RCX, [0x7ffff7f7f768] => 0xdec4e0a5873d8600
   0x5555555556a1 <lab09_lookup+17>    mov    qword ptr [rbp - 8], rcx     [0x7fffffffe0a8] <= 0xdec4e0a5873d8600
   0x5555555556a5 <lab09_lookup+21>    lea    rcx, [rbp - 0x14]            RCX => 0x7fffffffe09c ◂— 0xf7ffd00000007fff
   0x5555555556a9 <lab09_lookup+25>    lea    rdx, [rbp - 0x10]            RDX => 0x7fffffffe0a0 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— ...
   0x5555555556ad <lab09_lookup+29>    call   lab05_locate                <lab05_locate>
   0x5555555556b2 <lab09_lookup+34>    lea    rdx, [rax + 0x2c]
   0x5555555556b6 <lab09_lookup+38>    test   rax, rax
   0x5555555556b9 <lab09_lookup+41>    cmovne rax, rdx
=> 0x555555555690 <lab09_lookup>:	push   rbp
   0x555555555691 <lab09_lookup+1>:	mov    rbp,rsp
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab09_lookup` at RVA `0x1690`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 10 — Cached ordinal traversal

## Target

Analyze stripped `FUN_001016e0`. Recover bounds, cache-versus-head start, next walk, cache update, and payload.

## Ghidra output

```c
FUNCTION FUN_001016e0
ENTRY 001016e0
SIGNATURE undefined FUN_001016e0(void)
CALLERS 001020b4, 0010226c, 001011e2

long FUN_001016e0(long param_1,ulong param_2)

{
  long lVar1;
  ulong uVar2;

  if (*(ulong *)(param_1 + 0x20) <= param_2) {
    return 0;
  }
  lVar1 = *(long *)(param_1 + 0x18);
  if ((lVar1 == 0) || (uVar2 = *(ulong *)(param_1 + 0x28), param_2 < uVar2)) {
    lVar1 = *(long *)(param_1 + 8);
    uVar2 = 0;
  }
  if (uVar2 < param_2) {
    if (((int)param_2 - (int)uVar2 & 1U) != 0) {
      uVar2 = uVar2 + 1;
      lVar1 = *(long *)(lVar1 + 0x20);
      if (param_2 == uVar2) goto LAB_00101731;
    }
    do {
      uVar2 = uVar2 + 2;
      lVar1 = *(long *)(*(long *)(lVar1 + 0x20) + 0x20);
    } while (param_2 != uVar2);
  }
LAB_00101731:
  *(long *)(param_1 + 0x18) = lVar1;
  *(ulong *)(param_1 + 0x28) = uVar2;
  return lVar1 + 0x2c;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000016e0 <lab10_get_index>:
    16e0:	48 3b 77 20          	cmp    rsi,QWORD PTR [rdi+0x20]
    16e4:	73 6a                	jae    1750 <lab10_get_index+0x70>
    16e6:	48 8b 47 18          	mov    rax,QWORD PTR [rdi+0x18]
    16ea:	48 85 c0             	test   rax,rax
    16ed:	74 51                	je     1740 <lab10_get_index+0x60>
    16ef:	48 8b 57 28          	mov    rdx,QWORD PTR [rdi+0x28]
    16f3:	48 39 d6             	cmp    rsi,rdx
    16f6:	72 48                	jb     1740 <lab10_get_index+0x60>
    16f8:	48 39 f2             	cmp    rdx,rsi
    16fb:	73 34                	jae    1731 <lab10_get_index+0x51>
    16fd:	48 89 f1             	mov    rcx,rsi
    1700:	48 29 d1             	sub    rcx,rdx
    1703:	83 e1 01             	and    ecx,0x1
    1706:	74 18                	je     1720 <lab10_get_index+0x40>
    1708:	48 83 c2 01          	add    rdx,0x1
    170c:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    1710:	48 39 d6             	cmp    rsi,rdx
    1713:	74 1c                	je     1731 <lab10_get_index+0x51>
    1715:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    171c:	00 00 00 00
    1720:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    1724:	48 83 c2 02          	add    rdx,0x2
    1728:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
    172c:	48 39 d6             	cmp    rsi,rdx
    172f:	75 ef                	jne    1720 <lab10_get_index+0x40>
    1731:	48 89 47 18          	mov    QWORD PTR [rdi+0x18],rax
    1735:	48 83 c0 2c          	add    rax,0x2c
    1739:	48 89 57 28          	mov    QWORD PTR [rdi+0x28],rdx
    173d:	c3                   	ret
    173e:	66 90                	xchg   ax,ax
    1740:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
    1744:	31 d2                	xor    edx,edx
    1746:	eb b0                	jmp    16f8 <lab10_get_index+0x18>
    1748:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    174f:	00
    1750:	31 c0                	xor    eax,eax
    1752:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x55555555913c ◂— 0x55555555913c
 RBX  5
 RCX  0x7fffffffe09c {side} ◂— 0x5555911000000000
 RDX  0
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  0
 R8   0xb0
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x5555555551e7 (main+359) ◂— test rax, rax
 RIP  0x5555555556e0 (lab10_get_index) ◂— cmp rsi, qword ptr [rdi + 0x20]
   0x5555555556e4 <lab10_get_index+4>    ✘ jae    lab10_get_index+112         <lab10_get_index+112>
   0x5555555556e6 <lab10_get_index+6>      mov    rax, qword ptr [rdi + 0x18]     RAX, [0x7fffffffe0e8] => 0x555555559110
   0x5555555556ea <lab10_get_index+10>     test   rax, rax                        0x555555559110 & 0x555555559110     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x5555555556ed <lab10_get_index+13>   ✘ je     lab10_get_index+96          <lab10_get_index+96>
   0x5555555556ef <lab10_get_index+15>     mov    rdx, qword ptr [rdi + 0x28]     RDX, [0x7fffffffe0f8] => 4
   0x5555555556f3 <lab10_get_index+19>     cmp    rsi, rdx                        0 - 4     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ac ]
   0x5555555556f6 <lab10_get_index+22>   ✔ jb     lab10_get_index+96          <lab10_get_index+96>
   0x555555555740 <lab10_get_index+96>     mov    rax, qword ptr [rdi + 8]        RAX, [0x7fffffffe0d8] => 0x555555559010
   0x555555555744 <lab10_get_index+100>    xor    edx, edx                        EDX => 0
   0x555555555746 <lab10_get_index+102>    jmp    lab10_get_index+24          <lab10_get_index+24>
=> 0x5555555556e0 <lab10_get_index>:	cmp    rsi,QWORD PTR [rdi+0x20]
   0x5555555556e4 <lab10_get_index+4>:	jae    0x555555555750 <lab10_get_index+112>
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab10_get_index` at RVA `0x16e0`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 11 — Tree minimum

## Target

Analyze stripped `FUN_00101760`. Recognize repeated left-child descent and null handling.

## Ghidra output

```c
FUNCTION FUN_00101760
ENTRY 00101760
SIGNATURE undefined FUN_00101760(void)
CALLERS 001020bc, 00102280, 0010183b

long * FUN_00101760(long *param_1)

{
  long *plVar1;

  if (param_1 == (long *)0x0) {
    return (long *)0x0;
  }
  do {
    plVar1 = param_1;
    param_1 = (long *)*param_1;
  } while (param_1 != (long *)0x0);
  return plVar1;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001760 <lab11_minimum>:
    1760:	48 85 ff             	test   rdi,rdi
    1763:	74 17                	je     177c <lab11_minimum+0x1c>
    1765:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    176c:	00 00 00 00
    1770:	48 89 f8             	mov    rax,rdi
    1773:	48 8b 3f             	mov    rdi,QWORD PTR [rdi]
    1776:	48 85 ff             	test   rdi,rdi
    1779:	75 f5                	jne    1770 <lab11_minimum+0x10>
    177b:	c3                   	ret
    177c:	31 c0                	xor    eax,eax
    177e:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RBX  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RCX  0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RDX  0x555555559050 ◂— 0x555555559050
 RDI  0x5555555590d0 —▸ 0x555555559110 ◂— 0x555555559110
 RSI  0x55555555903c ◂— 0x55555555903c
 R8   0x137
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe078 —▸ 0x555555555840 (lab14_delete+80) ◂— mov r8, rax
 RIP  0x555555555760 (lab11_minimum) ◂— test rdi, rdi
   0x555555555763 <lab11_minimum+3>   ✘ je     lab11_minimum+28            <lab11_minimum+28>
   0x555555555765 <lab11_minimum+5>     nop    word ptr [rax + rax]
   0x555555555770 <lab11_minimum+16>    mov    rax, rdi                 RAX => 0x5555555590d0
   0x555555555773 <lab11_minimum+19>    mov    rdi, qword ptr [rdi]     RDI, [0x5555555590d0]
   0x555555555776 <lab11_minimum+22>    test   rdi, rdi                 0x555555559110 & 0x555555559110     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555779 <lab11_minimum+25>  ✔ jne    lab11_minimum+16            <lab11_minimum+16>
   0x555555555770 <lab11_minimum+16>    mov    rax, rdi                 RAX => 0x555555559110
   0x555555555773 <lab11_minimum+19>    mov    rdi, qword ptr [rdi]     RDI, [0x555555559110]
   0x555555555776 <lab11_minimum+22>    test   rdi, rdi                 0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555779 <lab11_minimum+25>  ✘ jne    lab11_minimum+16            <lab11_minimum+16>
=> 0x555555555760 <lab11_minimum>:	test   rdi,rdi
   0x555555555763 <lab11_minimum+3>:	je     0x55555555577c <lab11_minimum+28>
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab11_minimum` at RVA `0x1760`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 12 — BST subtree transplant

## Target

Analyze stripped `FUN_00101780`. Recover root/left/right parent cases and parent-pointer repair.

## Ghidra output

```c
FUNCTION FUN_00101780
ENTRY 00101780
SIGNATURE undefined FUN_00101780(void)
CALLERS 001020c4, 00102294, 00101853, 0010186d, 001018c6, 001018e1

void FUN_00101780(long *param_1,long param_2,long param_3)

{
  long *plVar1;

  plVar1 = *(long **)(param_2 + 0x10);
  if (plVar1 == (long *)0x0) {
    *param_1 = param_3;
  }
  else if (*plVar1 == param_2) {
    *plVar1 = param_3;
  }
  else {
    plVar1[1] = param_3;
  }
  if (param_3 != 0) {
    *(undefined8 *)(param_3 + 0x10) = *(undefined8 *)(param_2 + 0x10);
  }
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

0000000000001780 <lab12_transplant>:
    1780:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    1784:	48 85 c0             	test   rax,rax
    1787:	74 1f                	je     17a8 <lab12_transplant+0x28>
    1789:	48 39 30             	cmp    QWORD PTR [rax],rsi
    178c:	74 12                	je     17a0 <lab12_transplant+0x20>
    178e:	48 89 50 08          	mov    QWORD PTR [rax+0x8],rdx
    1792:	48 85 d2             	test   rdx,rdx
    1795:	74 08                	je     179f <lab12_transplant+0x1f>
    1797:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
    179b:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
    179f:	c3                   	ret
    17a0:	48 89 10             	mov    QWORD PTR [rax],rdx
    17a3:	eb ed                	jmp    1792 <lab12_transplant+0x12>
    17a5:	0f 1f 00             	nop    DWORD PTR [rax]
    17a8:	48 89 17             	mov    QWORD PTR [rdi],rdx
    17ab:	eb e5                	jmp    1792 <lab12_transplant+0x12>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x555555559110 ◂— 0x555555559110
 RBX  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RCX  0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RDX  0
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  0x555555559110 ◂— 0x555555559110
 R8   0x555555559110 ◂— 0x555555559110
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe078 —▸ 0x555555555858 (lab14_delete+104) ◂— mov rax, qword ptr [rcx + 8]
 RIP  0x555555555780 (lab12_transplant) ◂— mov rax, qword ptr [rsi + 0x10]
   0x555555555784 <lab12_transplant+4>     test   rax, rax                        0x5555555590d0 & 0x5555555590d0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555555787 <lab12_transplant+7>   ✘ je     lab12_transplant+40         <lab12_transplant+40>
   0x555555555789 <lab12_transplant+9>     cmp    qword ptr [rax], rsi            EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x55555555578c <lab12_transplant+12>  ✔ je     lab12_transplant+32         <lab12_transplant+32>
   0x5555555557a0 <lab12_transplant+32>    mov    qword ptr [rax], rdx            [0x5555555590d0] <= 0
   0x5555555557a3 <lab12_transplant+35>    jmp    lab12_transplant+18         <lab12_transplant+18>
   0x555555555792 <lab12_transplant+18>    test   rdx, rdx                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x555555555795 <lab12_transplant+21>  ✔ je     lab12_transplant+31         <lab12_transplant+31>
   0x55555555579f <lab12_transplant+31>    ret                                <lab14_delete+104>
   0x555555555858 <lab14_delete+104>       mov    rax, qword ptr [rcx + 8]        RAX, [0x555555559018]
=> 0x555555555780 <lab12_transplant>:	mov    rax,QWORD PTR [rsi+0x10]
   0x555555555784 <lab12_transplant+4>:	test   rax,rax
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab12_transplant` at RVA `0x1780`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 13 — Doubly linked removal

## Target

Analyze stripped `FUN_001017b0`. Recover four boundary cases for head/tail and neighbor repair.

## Ghidra output

```c
FUNCTION FUN_001017b0
ENTRY 001017b0
SIGNATURE undefined FUN_001017b0(void)
CALLERS 001020cc, 001022a8, 00101882

void FUN_001017b0(long param_1,long param_2)

{
  if (*(long *)(param_2 + 0x18) == 0) {
    *(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_2 + 0x20);
  }
  else {
    *(undefined8 *)(*(long *)(param_2 + 0x18) + 0x20) = *(undefined8 *)(param_2 + 0x20);
  }
  if (*(long *)(param_2 + 0x20) != 0) {
    *(undefined8 *)(*(long *)(param_2 + 0x20) + 0x18) = *(undefined8 *)(param_2 + 0x18);
    return;
  }
  *(undefined8 *)(param_1 + 0x10) = *(undefined8 *)(param_2 + 0x18);
  return;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017b0 <lab13_unlink_list>:
    17b0:	48 8b 46 18          	mov    rax,QWORD PTR [rsi+0x18]
    17b4:	48 8b 56 20          	mov    rdx,QWORD PTR [rsi+0x20]
    17b8:	48 85 c0             	test   rax,rax
    17bb:	74 23                	je     17e0 <lab13_unlink_list+0x30>
    17bd:	48 89 50 20          	mov    QWORD PTR [rax+0x20],rdx
    17c1:	48 8b 46 20          	mov    rax,QWORD PTR [rsi+0x20]
    17c5:	48 8b 56 18          	mov    rdx,QWORD PTR [rsi+0x18]
    17c9:	48 85 c0             	test   rax,rax
    17cc:	74 0a                	je     17d8 <lab13_unlink_list+0x28>
    17ce:	48 89 50 18          	mov    QWORD PTR [rax+0x18],rdx
    17d2:	c3                   	ret
    17d3:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    17d8:	48 89 57 10          	mov    QWORD PTR [rdi+0x10],rdx
    17dc:	c3                   	ret
    17dd:	0f 1f 00             	nop    DWORD PTR [rax]
    17e0:	48 89 57 08          	mov    QWORD PTR [rdi+0x8],rdx
    17e4:	eb db                	jmp    17c1 <lab13_unlink_list+0x11>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x555555559050 ◂— 0x555555559050
 RBX  0x7fffffffe0d0 —▸ 0x555555559110 —▸ 0x555555559050 ◂— 0x555555559050
 RCX  0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RDX  0x555555559110 —▸ 0x555555559050 ◂— 0x555555559050
 RDI  0x7fffffffe0d0 —▸ 0x555555559110 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 R8   0x555555559110 —▸ 0x555555559050 ◂— 0x555555559050
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe078 —▸ 0x555555555887 (lab14_delete+151) ◂— sub qword ptr [rbx + 0x20], 1
 RIP  0x5555555557b0 (lab13_unlink_list) ◂— mov rax, qword ptr [rsi + 0x18]
   0x5555555557b4 <lab13_unlink_list+4>     mov    rdx, qword ptr [rsi + 0x20]     RDX, [0x555555559030]
   0x5555555557b8 <lab13_unlink_list+8>     test   rax, rax                        0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
   0x5555555557bb <lab13_unlink_list+11>  ✔ je     lab13_unlink_list+48        <lab13_unlink_list+48>
   0x5555555557e0 <lab13_unlink_list+48>    mov    qword ptr [rdi + 8], rdx        [0x7fffffffe0d8] <= 0x555555559050
   0x5555555557e4 <lab13_unlink_list+52>    jmp    lab13_unlink_list+17        <lab13_unlink_list+17>
   0x5555555557c1 <lab13_unlink_list+17>    mov    rax, qword ptr [rsi + 0x20]     RAX, [0x555555559030]
   0x5555555557c5 <lab13_unlink_list+21>    mov    rdx, qword ptr [rsi + 0x18]     RDX, [0x555555559028]
   0x5555555557c9 <lab13_unlink_list+25>    test   rax, rax                        0x555555559050 & 0x555555559050     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x5555555557cc <lab13_unlink_list+28>  ✘ je     lab13_unlink_list+40        <lab13_unlink_list+40>
   0x5555555557ce <lab13_unlink_list+30>    mov    qword ptr [rax + 0x18], rdx     [0x555555559068] <= 0
=> 0x5555555557b0 <lab13_unlink_list>:	mov    rax,QWORD PTR [rsi+0x18]
   0x5555555557b4 <lab13_unlink_list+4>:	mov    rdx,QWORD PTR [rsi+0x20]
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab13_unlink_list` at RVA `0x17b0`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 14 — Full BST deletion

## Target

Analyze stripped `FUN_001017f0`. Recover lookup, zero/one/two-child cases, successor transplant, list unlink, cache invalidation, count, and free.

## Ghidra output

```c
FUNCTION FUN_001017f0
ENTRY 001017f0
SIGNATURE undefined FUN_001017f0(void)
CALLERS 001020d4, 001022bc, 00101227, 00101283

undefined8 FUN_001017f0(long param_1,undefined8 param_2)

{
  long lVar1;
  long *plVar2;
  long *plVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  undefined1 local_2c [4];
  undefined1 local_28 [8];
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  plVar2 = (long *)FUN_00101470(param_1,param_2,local_28,local_2c);
  if (plVar2 == (long *)0x0) {
    uVar4 = 0;
  }
  else {
    if (*plVar2 == 0) {
      FUN_00101780(param_1,plVar2,plVar2[1]);
    }
    else if (plVar2[1] == 0) {
      FUN_00101780(param_1,plVar2);
    }
    else {
      plVar3 = (long *)FUN_00101760();
      if ((long *)plVar3[2] != plVar2) {
        FUN_00101780(param_1,plVar3,plVar3[1]);
        lVar1 = plVar2[1];
        plVar3[1] = lVar1;
        *(long **)(lVar1 + 0x10) = plVar3;
      }
      FUN_00101780(param_1,plVar2,plVar3);
      lVar1 = *plVar2;
      *plVar3 = lVar1;
      *(long **)(lVar1 + 0x10) = plVar3;
    }
    FUN_001017b0(param_1,plVar2);
    *(long *)(param_1 + 0x20) = *(long *)(param_1 + 0x20) + -1;
    *(undefined8 *)(param_1 + 0x18) = 0;
    *(undefined8 *)(param_1 + 0x28) = 0;
    (**(code **)(param_1 + 0x40))(plVar2);
    uVar4 = 1;
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000017f0 <lab14_delete>:
    17f0:	55                   	push   rbp
    17f1:	48 89 e5             	mov    rbp,rsp
    17f4:	53                   	push   rbx
    17f5:	48 8d 4d dc          	lea    rcx,[rbp-0x24]
    17f9:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
    17fd:	48 83 ec 28          	sub    rsp,0x28
    1801:	64 48 8b 1c 25 28 00 	mov    rbx,QWORD PTR fs:0x28
    1808:	00 00
    180a:	48 89 5d e8          	mov    QWORD PTR [rbp-0x18],rbx
    180e:	48 89 fb             	mov    rbx,rdi
    1811:	e8 5a fc ff ff       	call   1470 <lab05_locate>
    1816:	48 85 c0             	test   rax,rax
    1819:	0f 84 b1 00 00 00    	je     18d0 <lab14_delete+0xe0>
    181f:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    1822:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
    1826:	48 89 c1             	mov    rcx,rax
    1829:	48 85 d2             	test   rdx,rdx
    182c:	0f 84 a6 00 00 00    	je     18d8 <lab14_delete+0xe8>
    1832:	48 85 ff             	test   rdi,rdi
    1835:	0f 84 85 00 00 00    	je     18c0 <lab14_delete+0xd0>
    183b:	e8 20 ff ff ff       	call   1760 <lab11_minimum>
    1840:	49 89 c0             	mov    r8,rax
    1843:	48 39 48 10          	cmp    QWORD PTR [rax+0x10],rcx
    1847:	74 1b                	je     1864 <lab14_delete+0x74>
    1849:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
    184d:	48 89 c6             	mov    rsi,rax
    1850:	48 89 df             	mov    rdi,rbx
    1853:	e8 28 ff ff ff       	call   1780 <lab12_transplant>
    1858:	48 8b 41 08          	mov    rax,QWORD PTR [rcx+0x8]
    185c:	49 89 40 08          	mov    QWORD PTR [r8+0x8],rax
    1860:	4c 89 40 10          	mov    QWORD PTR [rax+0x10],r8
    1864:	4c 89 c2             	mov    rdx,r8
    1867:	48 89 ce             	mov    rsi,rcx
    186a:	48 89 df             	mov    rdi,rbx
    186d:	e8 0e ff ff ff       	call   1780 <lab12_transplant>
    1872:	48 8b 01             	mov    rax,QWORD PTR [rcx]
    1875:	49 89 00             	mov    QWORD PTR [r8],rax
    1878:	4c 89 40 10          	mov    QWORD PTR [rax+0x10],r8
    187c:	48 89 ce             	mov    rsi,rcx
    187f:	48 89 df             	mov    rdi,rbx
    1882:	e8 29 ff ff ff       	call   17b0 <lab13_unlink_list>
    1887:	48 83 6b 20 01       	sub    QWORD PTR [rbx+0x20],0x1
    188c:	48 89 cf             	mov    rdi,rcx
    188f:	48 c7 43 18 00 00 00 	mov    QWORD PTR [rbx+0x18],0x0
    1896:	00
    1897:	48 c7 43 28 00 00 00 	mov    QWORD PTR [rbx+0x28],0x0
    189e:	00
    189f:	ff 53 40             	call   QWORD PTR [rbx+0x40]
    18a2:	b8 01 00 00 00       	mov    eax,0x1
    18a7:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
    18ab:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    18b2:	00 00
    18b4:	75 32                	jne    18e8 <lab14_delete+0xf8>
    18b6:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
    18ba:	c9                   	leave
    18bb:	c3                   	ret
    18bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    18c0:	48 89 c6             	mov    rsi,rax
    18c3:	48 89 df             	mov    rdi,rbx
    18c6:	e8 b5 fe ff ff       	call   1780 <lab12_transplant>
    18cb:	eb af                	jmp    187c <lab14_delete+0x8c>
    18cd:	0f 1f 00             	nop    DWORD PTR [rax]
    18d0:	31 c0                	xor    eax,eax
    18d2:	eb d3                	jmp    18a7 <lab14_delete+0xb7>
    18d4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    18d8:	48 89 fa             	mov    rdx,rdi
    18db:	48 89 c6             	mov    rsi,rax
    18de:	48 89 df             	mov    rdi,rbx
    18e1:	e8 9a fe ff ff       	call   1780 <lab12_transplant>
    18e6:	eb 94                	jmp    187c <lab14_delete+0x8c>
    18e8:	e8 43 f7 ff ff       	call   1030 <__stack_chk_fail@plt>

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x20ff7b6db
 RBX  0x20ff7b812
 RCX  5
 RDX  0xffffffffffffffff
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  0x7fffffffe0c8 ◂— 0x1e
 R8   0x137
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x55555555522c (main+428) ◂— lea rdi, [rbp - 0x90]
 RIP  0x5555555557f0 (lab14_delete) ◂— push rbp
   0x5555555557f1 <lab14_delete+1>     mov    rbp, rsp                        RBP => 0x7fffffffe0b0 —▸ 0x7fffffffe160 —▸ 0x7fffffffe210 —▸ 0x7fffffffe270 ◂— ...
   0x5555555557f4 <lab14_delete+4>     push   rbx
   0x5555555557f5 <lab14_delete+5>     lea    rcx, [rbp - 0x24]               RCX => 0x7fffffffe08c ◂— 0x6900005555 /* 'UU' */
   0x5555555557f9 <lab14_delete+9>     lea    rdx, [rbp - 0x20]               RDX => 0x7fffffffe090 ◂— 0x69 /* 'i' */
   0x5555555557fd <lab14_delete+13>    sub    rsp, 0x28                       RSP => 0x7fffffffe080 (0x7fffffffe0a8 - 0x28)
   0x555555555801 <lab14_delete+17>    mov    rbx, qword ptr fs:[0x28]        RBX, [0x7ffff7f7f768] => 0xdec4e0a5873d8600
   0x55555555580a <lab14_delete+26>    mov    qword ptr [rbp - 0x18], rbx     [0x7fffffffe098] <= 0xdec4e0a5873d8600
   0x55555555580e <lab14_delete+30>    mov    rbx, rdi                        RBX => 0x7fffffffe0d0 ◂— 0x555555559010
   0x555555555811 <lab14_delete+33>    call   lab05_locate                <lab05_locate>
   0x555555555816 <lab14_delete+38>    test   rax, rax
=> 0x5555555557f0 <lab14_delete>:	push   rbp
   0x5555555557f1 <lab14_delete+1>:	mov    rbp,rsp
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab14_delete` at RVA `0x17f0`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Walkthrough 15 — Cross-representation validation

## Target

Analyze stripped `FUN_001018f0`. Walk list, verify backward links/count, compute key hash, and return failure sentinel.

## Ghidra output

```c
FUNCTION FUN_001018f0
ENTRY 001018f0
SIGNATURE undefined FUN_001018f0(void)
CALLERS 001020dc, 001022e0, 0010120d, 0010123d

long FUN_001018f0(long param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  bool bVar5;

  lVar2 = 0;
  lVar3 = 0;
  lVar4 = *(long *)(param_1 + 8);
  if (*(long *)(param_1 + 8) != 0) {
    while( true ) {
      lVar3 = lVar3 + 1;
      lVar2 = lVar2 * 0x83 + (ulong)*(uint *)(lVar4 + 0x2c);
      lVar1 = *(long *)(lVar4 + 0x20);
      if (lVar1 == 0) break;
      bVar5 = *(long *)(lVar1 + 0x18) != lVar4;
      lVar4 = lVar1;
      if (bVar5) {
        return -1;
      }
    }
  }
  if (*(long *)(param_1 + 0x20) != lVar3) {
    lVar2 = -1;
  }
  return lVar2;
}
```

## Full assembly

```asm
reversing-walkthrough-lab/build/ch05/ch05_debug:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .text:

00000000000018f0 <lab15_invariant>:
    18f0:	48 8b 57 08          	mov    rdx,QWORD PTR [rdi+0x8]
    18f4:	31 c0                	xor    eax,eax
    18f6:	31 c9                	xor    ecx,ecx
    18f8:	48 85 d2             	test   rdx,rdx
    18fb:	74 33                	je     1930 <lab15_invariant+0x40>
    18fd:	0f 1f 00             	nop    DWORD PTR [rax]
    1900:	48 69 c0 83 00 00 00 	imul   rax,rax,0x83
    1907:	8b 72 2c             	mov    esi,DWORD PTR [rdx+0x2c]
    190a:	48 83 c1 01          	add    rcx,0x1
    190e:	48 01 f0             	add    rax,rsi
    1911:	48 89 d6             	mov    rsi,rdx
    1914:	48 8b 52 20          	mov    rdx,QWORD PTR [rdx+0x20]
    1918:	48 85 d2             	test   rdx,rdx
    191b:	74 13                	je     1930 <lab15_invariant+0x40>
    191d:	48 39 72 18          	cmp    QWORD PTR [rdx+0x18],rsi
    1921:	74 dd                	je     1900 <lab15_invariant+0x10>
    1923:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
    192a:	c3                   	ret
    192b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1930:	48 39 4f 20          	cmp    QWORD PTR [rdi+0x20],rcx
    1934:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
    193b:	48 0f 45 c2          	cmovne rax,rdx
    193f:	c3                   	ret

Disassembly of section .fini:
```

## Actual pwndbg state

```text
RAX  0x23
 RBX  5
 RCX  1
 RDX  4
 RDI  0x7fffffffe0d0 —▸ 0x555555559010 —▸ 0x555555559050 ◂— 0x555555559050
 RSI  5
 R8   0x137
 R9   0x7ffff7e13ac0 ◂— 0
 RSP  0x7fffffffe0b8 —▸ 0x555555555212 (main+402) ◂— lea rsi, [rbp - 0x98]
 RIP  0x5555555558f0 (lab15_invariant) ◂— mov rdx, qword ptr [rdi + 8]
   0x5555555558f4 <lab15_invariant+4>     xor    eax, eax                     EAX => 0
   0x5555555558f6 <lab15_invariant+6>     xor    ecx, ecx                     ECX => 0
   0x5555555558f8 <lab15_invariant+8>     test   rdx, rdx                     0x555555559010 & 0x555555559010     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x5555555558fb <lab15_invariant+11>  ✘ je     lab15_invariant+64          <lab15_invariant+64>
   0x5555555558fd <lab15_invariant+13>    nop    dword ptr [rax]
   0x555555555900 <lab15_invariant+16>    imul   rax, rax, 0x83
   0x555555555907 <lab15_invariant+23>    mov    esi, dword ptr [rdx + 0x2c]     ESI, [0x55555555903c]
   0x55555555590a <lab15_invariant+26>    add    rcx, 1                          RCX => 1 (0 + 1)
   0x55555555590e <lab15_invariant+30>    add    rax, rsi                        RAX => 0x1e (0x0 + 0x1e)
   0x555555555911 <lab15_invariant+33>    mov    rsi, rdx                        RSI => 0x555555559010
=> 0x5555555558f0 <lab15_invariant>:	mov    rdx,QWORD PTR [rdi+0x8]
   0x5555555558f4 <lab15_invariant+4>:	xor    eax,eax
```

## Reconstruction

1. Record table/node offsets without names.
2. Identify direct stores, pointer adjustments, and indirect calls.
3. Cross-reference the same offsets in earlier/later functions.
4. State tree, list, count, cache, and ownership invariants touched here.
5. Validate with the executed insert/duplicate/lookup/index/delete sequence.

## Finding

The function is `lab15_invariant` at RVA `0x18f0`. Its semantic label is justified by its role in the complete API, not by one isolated instruction sequence.

# Twenty Practice Questions

1. Why analyze accessors first?
2. What proves a callback prototype?
3. Why return payload not Node?
4. How is duplicate insertion handled?
5. Why keep tree and list?
6. What does cache_index mean?
7. What must deletion invalidate?
8. How is successor chosen?
9. What is transplant?
10. What proves left versus right fields?
11. How do allocation bytes reveal header?
12. Why compare one function across callers?
13. How test duplicate semantics?
14. How test cache?
15. What invariants does lab15 check?
16. Why is root-null emptiness valid?
17. What is ownership evidence?
18. How identify output parameters?
19. Why is a coherent model stronger than a decompile?
20. Mastery test?

# Complete Solutions

## 1. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** They label header fields with little ambiguity.
4. Design an operation sequence that would falsify it.

## 2. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Indirect-call argument setup and return use across call sites.
4. Design an operation sequence that would falsify it.

## 3. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Metadata is API-private and precedes caller bytes.
4. Design an operation sequence that would falsify it.

## 4. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Locate equality returns existing payload, created=0, no allocation/count change.
4. Design an operation sequence that would falsify it.

## 5. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Key search and insertion-order ordinal access have different optimal representations.
4. Design an operation sequence that would falsify it.

## 6. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Ordinal corresponding to cached node, enabling forward reuse.
4. Design an operation sequence that would falsify it.

## 7. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Count, list/tree links, cache, and ownership.
4. Design an operation sequence that would falsify it.

## 8. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Minimum of right subtree for two-child deletion.
4. Design an operation sequence that would falsify it.

## 9. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Replace one subtree root with another while fixing parent/root link.
4. Design an operation sequence that would falsify it.

## 10. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Comparator sign consistently selects distinct child offsets.
4. Design an operation sequence that would falsify it.

## 11. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Request equals sizeof internal Node plus payload size.
4. Design an operation sequence that would falsify it.

## 12. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Shared invariants disambiguate fields and prototypes.
4. Design an operation sequence that would falsify it.

## 13. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Insert same key with different non-key bytes and observe pointer/count/allocation/status.
4. Design an operation sequence that would falsify it.

## 14. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Request increasing ordinals and watch cached node/index updates and start point.
4. Design an operation sequence that would falsify it.

## 15. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** List count equals header count and each next node points back to predecessor.
4. Design an operation sequence that would falsify it.

## 16. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Table invariant equates no root with no nodes/count zero.
4. Design an operation sequence that would falsify it.

## 17. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Allocation callback on insert and free callback on successful delete.
4. Design an operation sequence that would falsify it.

## 18. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Callee stores through argument pointers and caller reads them after return.
4. Design an operation sequence that would falsify it.

## 19. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** All fifteen functions agree on offsets, callbacks, and invariants.
4. Design an operation sequence that would falsify it.

## 20. Solution

1. Locate the relevant fields/calls.
2. Cross-check at least two functions.
3. **Answer:** Reimplement client/API from stripped contract and pass insert/lookup/index/delete boundary suite.
4. Design an operation sequence that would falsify it.


Return to [[Chapter 05 - Beyond the Documentation]].
