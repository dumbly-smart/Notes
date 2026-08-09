# Chapter 12 — Reversing .NET

> [!workthroughs] Complete tool-backed labs: [[Walkthroughs - Chapter 12 - Fifteen Complete Analyses]]


## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs III - Protections Managed Code and Decompilation]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
> [!source]
> **From the book:** managed-code foundations, CTS, IL, evaluation stack, activation records, code samples, decompilers, and obfuscator examples.
> **Added mentor material:** metadata workflow, paired C#/IL examples, stack traces, and deobfuscation labs.

## Chapter Overview

.NET assemblies preserve types, signatures, metadata tokens, exceptions, and stack-based Intermediate Language (IL). That makes decompilation unusually effective, but it also gives obfuscators rich structures to transform.

```text
PE/assembly
├── CLR header and metadata
├── types, methods, fields, references
├── IL method bodies
└── resources
        ↓
metadata resolution + evaluation-stack simulation + CFG
        ↓
high-level managed representation
```

## 12.1 Ground Rules and Execution Model

Managed code executes under the Common Language Runtime (CLR). Source becomes IL plus metadata; a JIT or ahead-of-time compiler eventually produces native instructions.

```text
C#/VB/etc. → IL + metadata → CLR loader/verifier → JIT/native code
```

Treat decompiler output as a hypothesis. Validate security-sensitive statements against IL, metadata, and—when necessary—JIT-generated native code.

## 12.2 Common Type System

| Concept | Meaning | Reversing clue |
|---|---|---|
| value type | value stored directly in its location | copying duplicates value |
| reference type | slot contains managed object reference | copies can alias one object |
| boxing | value wrapped in an object | `box` instruction |
| unboxing | checked recovery of value | `unbox` / `unbox.any` |
| managed pointer | tracked reference to a location | address loads and by-ref calls |
| metadata token | identifier into a metadata table | operand resolves to type/member/string |

### Paired example: value versus reference

```csharp
struct Point { public int X; }
class Box { public int X; }

Point p1 = new Point { X = 1 };
Point p2 = p1;
p2.X = 9;              // p1.X remains 1

Box b1 = new Box { X = 1 };
Box b2 = b1;
b2.X = 9;              // b1.X becomes 9
```

Conceptual IL signatures differ because the struct is manipulated by value/address while the class local contains an object reference. In a reverse-engineering notebook, annotate whether a local is the data or a pointer-like managed reference before interpreting copies.

## 12.3 IL and the Evaluation Stack

Most IL pushes operands and pops them to compute results.

### Paired C#/IL example: arithmetic

```csharp
static int Scale(int a, int b) {
    int sum = a + b;
    return sum * 3;
}
```

```il
ldarg.0       // [a]
ldarg.1       // [a, b]
add           // [a+b]
stloc.0       // []
ldloc.0       // [sum]
ldc.i4.3      // [sum, 3]
mul           // [sum*3]
ret           // []
```

For `a=4, b=5`, the stack evolves `[] → [4] → [4,5] → [9] → [] → [9] → [9,3] → [27]`. This trace is more reliable than guessing from decompiler syntax.

### Activation records

A managed frame contains arguments, locals, evaluation stack state, return state, and protected exception regions. `ldarg/starg` and `ldloc/stloc` address stable slots; the evaluation stack is transient.

### Important instruction families

| Family | Examples | Effect |
|---|---|---|
| constants | `ldc.i4`, `ldstr`, `ldnull` | push value |
| arguments/locals | `ldarg`, `starg`, `ldloc`, `stloc` | frame access |
| fields | `ldfld`, `stfld`, `ldsfld` | member access |
| calls | `call`, `callvirt`, `newobj` | invocation/allocation |
| branches | `br`, `brtrue`, `beq`, `switch` | CFG edges |
| arrays | `newarr`, `ldelem.*`, `stelem.*` | indexed data |
| types | `box`, `unbox.any`, `castclass`, `isinst` | representation/type checks |
| exceptions | `throw`, `leave`, `endfinally` | protected control flow |

`callvirt` can be emitted for a non-virtual instance method to obtain a null check. Resolve the target metadata before claiming virtual dispatch.

## 12.4 Counting Items: Full Reconstruction

### Source-level behavior

```csharp
static int CountPositive(int[] values) {
    int count = 0;
    for (int i = 0; i < values.Length; i++)
        if (values[i] > 0) count++;
    return count;
}
```

### Conceptual IL

```il
ldc.i4.0
stloc count
ldc.i4.0
stloc i
br CHECK
BODY:
  ldarg values
  ldloc i
  ldelem.i4
  ldc.i4.0
  ble NEXT
  ldloc count
  ldc.i4.1
  add
  stloc count
NEXT:
  ldloc i
  ldc.i4.1
  add
  stloc i
CHECK:
  ldloc i
  ldarg values
  ldlen
  conv.i4
  blt BODY
ldloc count
ret
```

### Recognition

1. Two zeroed locals are candidates for count and index.
2. The initial branch to `CHECK` identifies a pre-tested loop.
3. `ldelem.i4` consumes array reference and index.
4. `ble NEXT` skips the increment for non-positive elements.
5. The back edge implements `i < Length`.
6. The returned local is the count.

The original source might have used `while`; the decompiler chooses equivalent structured syntax.

## 12.5 Linked-List Sample

### Source

```csharp
sealed class Node {
    public int Value;
    public Node? Next;
}

static int Sum(Node? current) {
    int total = 0;
    while (current != null) {
        total += current.Value;
        current = current.Next;
    }
    return total;
}
```

### Conceptual IL body

```il
ldc.i4.0
stloc total
br TEST
LOOP:
  ldloc total
  ldarg current
  ldfld int32 Node::Value
  add
  stloc total
  ldarg current
  ldfld class Node Node::Next
  starg current
TEST:
  ldarg current
  brtrue LOOP
ldloc total
ret
```

For `total += current.Value`, stack state is `[total] → [total,current] → [total,value] → [newTotal] → []`. Repeated `Next` loads plus a null-controlled back edge identify traversal.

### Object construction pattern

```il
newobj instance void Node::.ctor()  // [node]
dup                                  // [node,node]
ldloc value                          // [node,node,value]
stfld int32 Node::Value              // [node]
```

`dup` preserves the new reference for later use after `stfld` consumes one copy.

## 12.6 Metadata as Evidence

Metadata tables describe assemblies, types, methods, fields, parameters, attributes, and member references. IL operands resolve through tokens.

### Mentor workflow

1. Record assembly identity, target runtime, architecture, and entry point.
2. Enumerate types, base classes, interfaces, and public surface.
3. Resolve suspicious method/field/string tokens.
4. Inspect resources and embedded assemblies.
5. Trace reflection and dynamic loading separately.
6. Rename by proven behavior while preserving original token/address.

Even after renaming obfuscation, signatures, inheritance, interface contracts, call relationships, constants, and resources survive.

## 12.7 Decompilers and Verification

Managed decompilers reconstruct high-level syntax from IL and metadata. They can be wrong around optimized/obfuscated control flow, iterator/async state machines, reflection, dynamic methods, unsafe/native interop, and unusual exception regions.

```text
decompiled statement
   ↓ verify
IL basic blocks and stack
   ↓ resolve
metadata token/signature
   ↓ if necessary
JIT native behavior
```

## 12.8 Obfuscation Techniques

### Renaming

```csharp
// before
bool ValidateLicense(string name)

// after (conceptually)
bool a(string b)
```

The IL behavior is unchanged. Restore names from callers, types, strings, field roles, and effects.

### Control-flow flattening

```csharp
int state = 0;
while (true) {
    switch (state) {
        case 0: x = Read(); state = x > 0 ? 1 : 2; break;
        case 1: return x * 2;
        case 2: return -1;
    }
}
```

Conceptual IL repeatedly branches to a `switch` dispatcher. Recover each case’s state assignment and replace the dispatcher with direct CFG edges. Prove the state set before deleting cases.

### String encryption

```csharp
Console.WriteLine(Decode(new byte[] { /* encoded */ }, key));
```

Recognition sequence: encoded blob/token → decoder call → returned `string` → UI/log/network consumer. Instrument immediately after the decoder in a local test and map plaintext back to call site.

### Breaking decompilation

At every CFG merge, evaluation stack heights and types must be compatible for ordinary valid IL. If one predecessor has `[int32]` and another `[]`, the graph is wrong, an edge is unreachable, exception semantics intervene, or the tool is being confused.

## 12.9 Book Obfuscator Survey

The book examines XenoCode, DotFuscator, Remotesoft Obfuscator/Linker, and Remotesoft Protector. Product behavior is version-specific; the durable categories are:

- symbol renaming;
- control-flow transformation;
- metadata/tool-assumption abuse;
- dependency merging;
- native precompilation;
- assembly encryption and runtime loading.

### Encrypted assembly boundary

```csharp
byte[] encrypted = LoadResource();
byte[] image = Decrypt(encrypted, key);
Assembly a = Assembly.Load(image);
```

```il
call      byte[] LoadResource()
stloc encrypted
ldloc encrypted
ldloc key
call      byte[] Decrypt(byte[], byte[])
stloc image
ldloc image
call      class Assembly Assembly::Load(byte[])
```

The byte array between `Decrypt` and `Assembly.Load` is the critical observation boundary. Capture it only in an isolated authorized process, then validate DOS/PE/CLR metadata.

### Precompiled assemblies

If ordinary IL is absent, inspect native images, runtime registration, remaining metadata, fallback IL, and interoperability boundaries. The problem shifts toward native reversing rather than disappearing.

## 12.10 Full Managed-Reversing Lab

Build a small assembly containing arithmetic, a list, an exception, an interface call, reflection, and a string decoder.

1. Compile Debug and Release variants.
2. Record hashes and metadata differences.
3. Decompile both and mark syntax differences.
4. Disassemble IL for each method.
5. Hand-trace evaluation stacks at branches and calls.
6. JIT-break one method and compare native calling convention.
7. Rename symbols, add a dispatcher, and encode one string in your own source.
8. Reverse the transformed build without consulting source.
9. Validate recovered pseudocode against a test vector suite.
10. Write an evidence table linking C#, IL offsets/tokens, and native observations.

## Common Mistakes

**Mistake:** treating decompiled C# as original source.
**Correction:** it is one equivalent representation; verify IL.

**Mistake:** ignoring stack height/type.
**Correction:** simulate every instruction and merge.

**Mistake:** assuming every `callvirt` is virtual dispatch.
**Correction:** resolve method/type metadata.

**Mistake:** stopping when names are unreadable.
**Correction:** behavior, types, signatures, and graph structure remain.

## Mastery Checklist

- [ ] Trace an IL evaluation stack instruction by instruction.
- [ ] Recover a loop from branch targets.
- [ ] Resolve metadata tokens.
- [ ] Explain value/reference/boxing semantics.
- [ ] Normalize a flattened dispatcher.
- [ ] Capture the boundary where encrypted managed bytes become loadable.
- [ ] Validate decompiler output against IL and tests.

## Practice Questions and Solutions

1. **Why does managed code decompile cleanly?** Metadata retains types and member signatures, while IL preserves a regular stack machine and structured runtime semantics.
2. **What does `stfld` need?** An object reference and the value to store, plus the field token encoded in the instruction.
3. **How do you recognize list traversal?** A current reference, null exit, field load, `Next` update, and back edge.
4. **What survives renaming?** Signatures, types, interfaces, calls, constants, resources, and behavior.
5. **Why can `callvirt` target a non-virtual method?** The compiler may want its null-check semantics.
6. **What does incompatible stack state at a merge mean?** A bad CFG/tool model, unreachable edge, exceptional transfer, or intentionally invalid/confusing IL.
7. **How do you recover decoded strings?** Trace encoded source into decoder and capture the returned managed string immediately before its consumer.
8. **How can code execute without visible disk IL?** Native precompilation, dynamic generation, encrypted runtime loading, dependency linking, or native interop.

---

Previous: [[Chapter 11 - Breaking Protections]]
Next: [[Chapter 13 - Decompilation]]
