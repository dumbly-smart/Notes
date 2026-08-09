# Appendices — Code Structures, Compiled Arithmetic, and Program Data

The book’s appendices are field references. This companion expands each pattern with C and assembly.

## Appendix A — Deciphering Code Structures

## A.1 Function Frames

```c
int square_plus(int x, int bias) {
    int y = x * x;
    return y + bias;
}
```

Unoptimized x86:

```asm
push ebp
mov ebp, esp
sub esp, 4
mov eax, [ebp+8]
imul eax, eax
mov [ebp-4], eax
mov eax, [ebp-4]
add eax, [ebp+12]
leave
ret
```

Optimized form may be only:

```asm
imul edi, edi
lea eax, [rdi+rsi]
ret
```

Frame artifacts are compiler choices. Recover data flow, not source storage.

## A.2 Conditions

```c
if ((unsigned)a < (unsigned)b) x();
else y();
```

```asm
cmp eax, ebx
jae else_block
call x
jmp join
else_block:
call y
join:
```

Key x86 branch relations after `CMP a,b`:

| Relation | Signed | Unsigned |
|---|---|---|
| equal | JE | JE |
| not equal | JNE | JNE |
| less | JL | JB |
| less/equal | JLE | JBE |
| greater | JG | JA |
| greater/equal | JGE | JAE |

## A.3 Short-Circuit Logic

```c
if (p != NULL && p->ready) use(p);
```

```asm
test rdi, rdi
jz skip
cmp dword [rdi+ready_off], 0
jz skip
call use
skip:
```

The first branch protects the dereference. A decompiler that combines conditions is correct only if evaluation order and side effects are preserved.

## A.4 Loops

### While

```c
while (n) { sum += *p++; n--; }
```

```asm
test rsi,rsi
jz done
loop:
movzx eax, byte [rdi]
add edx,eax
inc rdi
dec rsi
jnz loop
done:
```

### Do-while

```c
do { process(*p++); } while (--n);
```

The body precedes the test; zero initial count may be invalid or still execute once. Determine entry edges before selecting loop syntax.

## A.5 Switches

```c
switch (x) { case 10: a(); break; case 11: b(); break; default: d(); }
```

```asm
sub edi, 10
cmp edi, 1
ja default
jmp qword [table+rdi*8]
```

The logical case value is `index + 10`. Record duplicate table targets and fall-through.

## A.6 Recursion

```c
unsigned factorial(unsigned n) {
    return n < 2 ? 1 : n * factorial(n-1);
}
```

```asm
cmp edi,2
jb base
push rbx
mov ebx,edi
lea edi,[rdi-1]
call factorial
imul eax,ebx
pop rbx
ret
base:
mov eax,1
ret
```

Recognition: self-call with transformed argument, base branch, and result combination. Optimization may convert tail recursion to a loop.

## A.7 Virtual Calls

Conceptual C++:

```cpp
struct Base { virtual int run(int)=0; };
int invoke(Base *p, int x) { return p->run(x); }
```

```asm
mov rax, [rdi]          ; vtable
mov rax, [rax]          ; slot 0 function
jmp rax                 ; this remains in RDI, x in ESI
```

Recover object pointer, vtable pointer, slot offset, and target set. Ghidra structures plus runtime indirect targets are complementary.

## A.8 Exception and Cleanup Shapes

Compilers introduce landing pads, cleanup calls, and rethrow paths. A destructor call on an error edge may not exist in the apparent source path but preserves language semantics. Use unwind metadata and exception tables; do not force all edges into ordinary branches.

# Appendix B — Understanding Compiled Arithmetic

## B.1 Fixed Width

For unsigned width `w`:

\[
result = mathematical\_result \bmod 2^w
\]

```c
uint8_t x = 250;
x += 10;  /* 4 */
```

```asm
mov al,250
add al,10       ; AL=4, carry set
```

## B.2 Multiplication by Constants

```c
int f(int x) { return x * 10; }
```

Possible assembly:

```asm
lea eax, [rdi+rdi*4]   ; 5x
add eax, eax           ; 10x
ret
```

Address-generation instructions can be arithmetic without memory access.

## B.3 Division by Powers of Two

Unsigned division by 8 can be `shr eax,3`. Signed division requires rounding toward zero, so negative inputs may require bias before arithmetic shift. Do not translate every `sar` to C division without checking adjustment.

## B.4 Magic-Number Division

Compilers replace constant division with wide multiplication and shifts:

```c
uint32_t q(uint32_t x) { return x / 10; }
```

Representative pattern:

```asm
mov eax, edi
mov edx, 0xCCCCCCCD
imul rax, rdx
shr rax, 35
ret
```

The constant and shift approximate reciprocal division exactly over the type range. Recognize using compiler-reference experiments; retain width and high-half product semantics.

## B.5 Carry Chains

```c
uint64_t add64_on_32(uint32_t alo, uint32_t ahi,
                     uint32_t blo, uint32_t bhi);
```

```asm
mov eax, alo
add eax, blo
mov edx, ahi
adc edx, bhi
```

`ADC` consumes carry from the low word. Separate instructions form one multiword operation.

## B.6 Signed Overflow versus Carry

- Carry indicates unsigned overflow/borrow.
- Overflow indicates signed result outside range.
- Zero and sign reflect stored result.
- Branch choice reveals interpretation.

One `ADD` can set both differently. Example: `0xffffffff + 1` sets carry and yields zero; signed interpretation is `-1 + 1 = 0` with no signed overflow.

## B.7 Rotates and Hashes

```c
x = (x << 7) | (x >> 25);
```

```asm
rol eax,7
```

Rotates commonly appear in hashes, checksums, ciphers, and bitfield code. Context distinguishes them.

## B.8 Floating Point and x87

```c
out = (a + b) * c;
```

```asm
fld dword [a]       ; [a]
fld dword [b]       ; [b,a]
faddp st1,st0       ; [a+b]
fld dword [c]       ; [c,a+b]
fmulp st1,st0       ; [(a+b)*c]
fstp dword [out]    ; []
```

Always write the x87 stack after every instruction.

## B.9 SIMD

```c
for (int i=0;i<4;i++) out[i]=a[i]+b[i];
```

Possible SSE:

```asm
movdqu xmm0, [rdi]
movdqu xmm1, [rsi]
paddd xmm0, xmm1
movdqu [rdx], xmm0
```

`paddd` performs four 32-bit integer additions. Determine lane width, signed saturation versus wrap, alignment, and loop tail.

# Appendix C — Deciphering Program Data

## C.1 Globals and Sections

| Section tendency | Typical content |
|---|---|
| executable/text | instructions, sometimes inline constants |
| read-only data | strings, constant tables, vtables |
| initialized writable | global state with file bytes |
| zero-initialized | globals allocated at load |
| imports/relocations | dynamic-link metadata |

Permissions are clues, not absolute truth; packers and JITs change them.

## C.2 Arrays

```c
sum += values[i];
```

```asm
add eax, dword [rdi+rcx*4]
```

Scale 4 supports four-byte elements. Bounds and base provenance determine array length.

## C.3 Two-Dimensional Arrays

```c
x = matrix[row][col];  /* 8 columns, int elements */
```

```asm
lea rax, [rsi*8]       ; row*8
add rax, rdx           ; +col
mov eax, [rdi+rax*4]
```

Physical index is `row*8+col`. Dynamic row pointers produce an extra load instead.

## C.4 Structures

Cross-function offset table:

| Offset | Function A | Function B | Interpretation |
|---:|---|---|---|
| 0 | compare | print | ID |
| 8 | dereference | null check | pointer |
| 16 | increment | return accessor | count |

Require alignment/allocation/stride evidence before final definition.

## C.5 Tagged Unions

```c
struct Value {
    unsigned tag;
    union { int i; double d; void *p; } u;
};
```

Assembly first branches on `tag`, then interprets the same payload offset differently. Do not force one static type onto all paths.

## C.6 Strings

Determine:

- narrow versus UTF-16/UTF-32;
- terminated versus length-prefixed;
- byte count versus character count;
- owned versus borrowed storage;
- normalization/case behavior.

Windows wide-string loops often advance by 2 and test a 16-bit zero. UTF-8 variable-width processing is not a simple character array.

## C.7 Function-Pointer Tables

```c
handlers[opcode](ctx);
```

```asm
cmp edi, MAX_OPCODE
ja bad
mov rax, [handlers+rdi*8]
mov rdi, ctx
call rax
```

The range check and scaled pointer load support a dispatch table. Runtime targets validate entries.

## C.8 Linked Trees

A binary-tree lookup commonly compares a key then selects one of two child offsets. Parent pointers, color/balance fields, or rotations distinguish tree variants. Model graph invariants before exact algorithm labels.

## Appendix Mastery Drill

For an unseen function, produce:

1. calling convention and prototype;
2. CFG and exception edges;
3. source/assembly paired pseudocode;
4. all widths and signedness;
5. structure/array/string hypotheses;
6. arithmetic expressions with modular semantics;
7. Ghidra markup;
8. GDB/pwndbg validation trace;
9. counterexample test;
10. confidence-labelled final report.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] for the full tool workflow.
