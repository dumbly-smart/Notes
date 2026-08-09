# Mentor Code Labs I — Foundations, Machine Code, Windows, and Tools


Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] for the exact static/dynamic procedure in every exercise.
These labs integrate with Chapters 1–4. Each follows:

```text
source intent → compiled pattern → state trace → recognition clues
→ experiment → expected result → common wrong conclusion
```

Build every program yourself at unoptimized and optimized settings.

## Lab 1 — Recover a Function Contract

### C source (hide it while practicing)

```c
#include <stddef.h>
int score(const unsigned char *p, size_t n) {
    unsigned acc = 0;
    for (size_t i = 0; i < n; i++)
        acc = (acc << 5) - acc + p[i]; /* acc*31 + byte */
    return (int)(acc & 0x7fffffff);
}
```

### Representative x86-64

```asm
; p=RDI, n=RSI, return=EAX
xor eax, eax
xor edx, edx
cmp rdx, rsi
jae done
loop:
movzx ecx, byte [rdi+rdx]
imul eax, eax, 31
add eax, ecx
inc rdx
cmp rdx, rsi
jb loop
done:
and eax, 0x7fffffff
ret
```

For bytes `A,B`, accumulator states are `0 → 65 → 65*31+66 = 2081`. Pointer-plus-index means byte traversal; `movzx` says unsigned byte; comparison with `n` gives a counted loop; multiplication by 31 is hash-like recurrence.

**Exercise:** reverse only the binary. Recover prototype, pseudocode, test vectors, and confidence ledger. Prove that shift/subtract and multiplication by 31 are equivalent modulo 32 bits.

## Lab 2 — Recover an If and Switch

```c
int classify(unsigned x) {
    if (x > 100) return -1;
    switch (x & 3) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return 40;
    }
}
```

```asm
cmp edi, 100
ja invalid
and edi, 3
lea rax, [jump_table]
jmp qword [rax+rdi*8]
case0: mov eax,10; ret
case1: mov eax,20; ret
case2: mov eax,30; ret
case3: mov eax,40; ret
invalid: mov eax,-1; ret
```

`JA` is unsigned. The mask bounds the jump-table index. Recover the range check, index normalization, table base, entry width, each target, and default edge before emitting a switch.

## Lab 3 — Stack Frame and Calling Convention

```c
__declspec(noinline) int add_bias(int a, int b) {
    int temp = a + b;
    return temp + 7;
}
```

```asm
push ebp
mov  ebp, esp
sub  esp, 4
mov  eax, [ebp+8]
add  eax, [ebp+12]
mov  [ebp-4], eax
mov  eax, [ebp-4]
add  eax, 7
mov  esp, ebp
pop  ebp
ret
```

```text
[ebp+12] b
[ebp+8 ] a
[ebp+4 ] return address
[ebp   ] saved EBP
[ebp-4 ] temp
```

At optimization, the local and frame pointer may vanish. That is a storage decision, not proof the source lacked a local.

## Lab 4 — Structure and Linked-List Recovery

```c
struct Node { struct Node *next; unsigned id; unsigned flags; };

struct Node *find(struct Node *p, unsigned id) {
    while (p) {
        if (p->id == id) return p;
        p = p->next;
    }
    return 0;
}
```

```asm
test rdi, rdi
jz not_found
loop:
cmp dword [rdi+8], esi
je found
mov rdi, [rdi]
test rdi, rdi
jnz loop
not_found: xor eax,eax; ret
found: mov rax,rdi; ret
```

| Offset | Use | Hypothesis |
|---:|---|---|
| +0 | pointer load and null test | next |
| +8 | 32-bit comparison with argument | id |
| +12 | unused here | unknown |

Do not invent `flags` from this function. Cross-function evidence is required.

## Lab 5 — Windows Handles and Mapped Files

```c
HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
HANDLE m = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
void *view = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
UnmapViewOfFile(view);
CloseHandle(m);
CloseHandle(f);
```

```asm
; Windows x64: RCX,RDX,R8,R9 then stack arguments
lea rcx, [path]
mov edx, GENERIC_READ
mov r8d, FILE_SHARE_READ
xor r9d, r9d
call CreateFileW
mov [file_handle], rax
...
mov rcx, [file_handle]
call CreateFileMappingW
...
call MapViewOfFile
```

The file handle, mapping handle, and view pointer are different semantic types. The view is unmapped; handles are closed.

## Lab 6 — API to System-Call Boundary

```c
BOOL ok = ReadFile(h, buffer, capacity, &got, NULL);
```

Conceptual layers:

```asm
caller:
  call kernel32!ReadFile
ReadFile:
  ; adapt public contract
  call ntdll!NtReadFile
NtReadFile:
  mov r10, rcx
  mov eax, service_number
  syscall
  ret
```

Service numbers vary by Windows build. Recover arguments and semantic boundary instead of memorizing a number.

## Lab 7 — Structured Exception Flow

```c
__try {
    risky_read(p);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    report_failure();
}
```

```text
normal call → continuation
     │ fault
     ▼
exception dispatch → filter/handler → recovery
```

Add exception edges to the CFG. Otherwise the recovery code looks unreachable. On modern Windows x64 inspect unwind metadata; historical x86 may expose explicit handler-chain manipulation.

## Lab 8 — Tool Correlation

Use `score` from Lab 1.

1. Locate entry, function, loop, and return statically.
2. Predict register values for input `AB`.
3. Break at loop entry/return and record `RAX/RDX/RCX`.
4. Rename variables only after values confirm roles.
5. Test `n=0` and the longest safe input.
6. Compare decompiler output with manual trace.
7. Record one claim the decompiler expresses more confidently than evidence supports.

Static analysis supplies path breadth; dynamic analysis supplies exact state for executed paths. Mastery means predicting the debugger state before running.
