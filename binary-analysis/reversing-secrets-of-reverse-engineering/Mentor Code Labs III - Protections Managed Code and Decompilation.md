# Mentor Code Labs III — Protections, Antireversing, Managed Code, and Decompilation


Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] for the exact static/dynamic procedure in every exercise.
These labs integrate Chapters 9–13. Use only your own crackmes/protection experiments.

## Lab 1 — Signed License Verification Boundary

### Defensive application source

```c
int enable_features(const unsigned char *license, size_t n,
                    const unsigned char signature[64]) {
    if (!verify_signature(public_key, license, n, signature))
        return 0;
    struct Claims c;
    if (!parse_claims(license, n, &c)) return 0;
    if (c.expired || c.product_id != EXPECTED_PRODUCT) return 0;
    return apply_features(c.feature_mask);
}
```

Representative decision pattern:

```asm
call verify_signature
test eax, eax
jz reject
call parse_claims
test eax, eax
jz reject
cmp dword [claims+product_id], EXPECTED_PRODUCT
jne reject
```

A signature check does not validate claim semantics by itself. Reverse each gate and its ordering. Defensively, parse safely, bind signature to canonical bytes, validate product/user/time, and keep private issuance keys off clients.

## Lab 2 — Toy Serial Relation

```c
#include <stdint.h>
uint16_t user_code(const unsigned char *s) {
    uint16_t h = 0x1234;
    while (*s) h = (uint16_t)(h * 33u + *s++);
    return h ^ 0xbeef;
}
```

```asm
movzx edx, word [seed]
loop:
movzx eax, byte [rdi]
test al, al
jz done
imul edx, edx, 33
add edx, eax
movzx edx, dx          ; truncate to 16 bits
inc rdi
jmp loop
done:
xor edx, 0xbeef
movzx eax, dx
ret
```

Reimplement with truncation after every recurrence. Test empty, one byte, high-bit bytes, and overflow cases. This is a local educational relation, not a method for bypassing third-party licensing.

## Lab 3 — Debugger-Presence Check

### Windows source

```c
#include <windows.h>
int guarded(void) {
    if (IsDebuggerPresent())
        return -1;
    return do_work();
}
```

```asm
call IsDebuggerPresent
test eax, eax
jne detected
call do_work
ret
detected:
mov eax, -1
ret
```

### Analysis

In Ghidra, follow the import thunk and both branch outcomes. In a debugger, stop after the call and observe the return value and every use. Do not assume the branch is the only consequence; compile a variant that also mixes the Boolean into state to demonstrate why blind branch flipping fails.

## Lab 4 — Code Checksum

```c
uint32_t checksum(const unsigned char *p, size_t n) {
    uint32_t x = 0;
    while (n--) x = (x << 5) ^ (x >> 27) ^ *p++;
    return x;
}

int intact(void) {
    return checksum(code_begin, code_end-code_begin) == expected;
}
```

```asm
rol eax, 5
movzx ecx, byte [rdi]
xor eax, ecx
inc rdi
dec rsi
jnz loop
cmp eax, [expected]
sete al
```

Recover start, length, recurrence, expected source, and all uses of the result. Put a software breakpoint inside the covered range and compare bytes/checksum with a hardware breakpoint strategy.

## Lab 5 — Opaque Predicate

```c
int transformed(unsigned x) {
    if (((x * (x + 1u)) & 1u) == 0)
        return real_work(x);
    return fake_work(x);
}
```

```asm
lea eax, [rdi+1]
imul eax, edi
test al, 1
jnz fake
jmp real_work
```

One of consecutive integers is even, so the low bit is always zero even modulo a power of two. Prove it, mark fake edge unreachable, then verify with boundary samples. Do not generalize this proof to overflow-sensitive identities without bit-vector reasoning.

## Lab 6 — Control-Flow Flattening

```c
int flat(int x) {
    int state = 0, y = 0;
    for (;;) {
        switch (state) {
        case 0: y = x + 1; state = (y > 10) ? 1 : 2; break;
        case 1: return y * 2;
        case 2: return y - 2;
        }
    }
}
```

Assembly shape:

```asm
dispatch:
cmp state, 2
ja dispatch
jmp qword [table+state*8]
case0:
lea y, [x+1]
cmp y, 10
setle state_byte
; normalize to state 1 or 2
jmp dispatch
case1: ...
case2: ...
```

Build a transition table:

| Current | Condition | Effect | Next/return |
|---:|---|---|---|
| 0 | y > 10 | y=x+1 | 1 |
| 0 | y <= 10 | y=x+1 | 2 |
| 1 | — | — | return y*2 |
| 2 | — | — | return y-2 |

Replace dispatcher edges in the analysis model, not the binary, and validate equivalence.

## Lab 7 — Variable Encoding

```c
static uint32_t encoded;
static const uint32_t key = 0xa5a5a5a5;

void set_value(uint32_t x) { encoded = (x + 7) ^ key; }
uint32_t get_value(void) { return (encoded ^ key) - 7; }
```

```asm
set_value:
lea eax, [rdi+7]
xor eax, 0xa5a5a5a5
mov [encoded], eax
ret
get_value:
mov eax, [encoded]
xor eax, 0xa5a5a5a5
sub eax, 7
ret
```

Pair writers with readers. Prove inverse under 32-bit modular arithmetic. Rename the global by logical value and retain encoded representation in comments.

## Lab 8 — Self-Decrypting Function Window Without Executing It

Use a byte array representing harmless data:

```c
void transform(unsigned char *p, size_t n, uint32_t state) {
    for (size_t i=0; i<n; i++) {
        state = state * 1664525u + 1013904223u;
        p[i] ^= (unsigned char)(state >> 24);
    }
}
```

Representative assembly:

```asm
imul edx, edx, 1664525
add edx, 1013904223
mov eax, edx
shr eax, 24
xor byte [rdi+rcx], al
inc rcx
cmp rcx, rsi
jb loop
```

Break before and after transformation, dump bytes, reproduce the state recurrence, and verify reapplying the stream transform restores the original. This models encrypted-function mechanics without executing generated code.

## Lab 9 — .NET Evaluation Stack

```csharp
static int ClampAdd(int a, int b) {
    int x = a + b;
    return x > 100 ? 100 : x;
}
```

```il
ldarg.0
ldarg.1
add
stloc.0
ldloc.0
ldc.i4.s 100
ble.s KEEP
ldc.i4.s 100
ret
KEEP:
ldloc.0
ret
```

Trace stack at every instruction and ensure both predecessors of each merge have compatible state. Resolve local and argument types from signature metadata.

## Lab 10 — Assembly to SSA

```c
int choose(int flag) {
    int x;
    if (flag) x = 10; else x = 20;
    return x + 1;
}
```

```asm
test edi, edi
jz zero
mov eax, 10
jmp join
zero:
mov eax, 20
join:
add eax, 1
ret
```

SSA:

```text
eax_1=10
eax_2=20
eax_3=phi(eax_1,eax_2)
return eax_3+1
```

Use definition sites, not register names, to separate logical values.

## Lab 11 — Type Recovery

```c
struct Record {
    uint32_t id;
    int8_t delta;
    unsigned char pad[3];
    void *next;
};

int adjusted(const struct Record *r) {
    return (int)r->id + r->delta;
}
```

```asm
mov eax, dword [rdi]
movsx ecx, byte [rdi+4]
add eax, ecx
ret
```

`movsx` proves signed byte interpretation at offset 4. A separate pointer load from `[rdi+8]` supports the structure layout. Apply a tentative structure in Ghidra and verify all cross-references.

## Lab 12 — Ghidra/Pwndbg Round Trip

For every prior lab:

1. Import stripped binary into Ghidra and run default analysis.
2. Record image base, entry, function RVAs, and file offsets.
3. Fix function boundaries before trusting decompilation.
4. Apply types/structures and rename with confidence markers.
5. Launch under GDB/pwndbg.
6. Use `vmmap` to find runtime base and translate Ghidra RVA.
7. Use `breakrva` or `break *base+RVA`.
8. At each stop use `context`, `regs`, `disasm`, `telescope`, and GDB `x`.
9. Use `watch` for the exact object field whose mutation proves the hypothesis.
10. Transfer confirmed values/edges back into Ghidra comments and types.
11. Export a function map and evidence table.
12. Repeat until pseudocode predicts every test vector.

## Completion Standard

You must explain both representations: source-level intent and the exact assembly/IL mechanism. For protection code, also state the invariant preserved by the transform and every downstream dependency.
