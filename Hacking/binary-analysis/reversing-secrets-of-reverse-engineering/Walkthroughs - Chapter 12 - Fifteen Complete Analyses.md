# Chapter 12 — Fifteen Complete Managed-Code Reversing Walkthroughs

> [!evidence]
> This chapter was produced from an actual .NET 10 Release build. Every walkthrough uses a separate `LabNN` method. The executable printed `chapter12 evidence=100664639`; the IL below came from `MethodBody.GetILAsByteArray`, while pwndbg stopped in the real `coreclr_initialize` and `coreclr_execute_assembly` native boundaries. Ghidra analyzed the native apphost but emitted CLR-metadata warnings on the .NET 10 DLL. That distinction is essential: apphost machine code is not the managed program's CIL.

## Complete C# specimen

```csharp
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

sealed class Node { public int Value; public Node? Next; }
interface ICalc { int Apply(int x); }
sealed class Doubler : ICalc { public int Apply(int x) => x * 2; }

static class Labs {
    public static int Lab01CountPositive(int[] a) { int n=0; foreach(int x in a) if(x>0)n++; return n; }
    public static int Lab02LinkedSum(Node? p) { int s=0; while(p!=null){s+=p.Value;p=p.Next;} return s; }
    public static T Lab03GenericMax<T>(T a,T b) where T:IComparable<T> => a.CompareTo(b)>=0?a:b;
    public static int Lab04Boxing(int x) { object o=x; return (int)o+1; }
    public static int Lab05Interface(ICalc c,int x) => c.Apply(x)+3;
    public static int Lab06Exception(string s) { try{return int.Parse(s);}catch(FormatException){return-1;}finally{GC.KeepAlive(s);} }
    public static IEnumerable<int> Lab07Iterator(int n) { for(int i=0;i<n;i++)if((i&1)==0)yield return i*i; }
    public static async Task<int> Lab08Async(int x) { await Task.Yield(); return x*7; }
    public static int Lab09Switch(int x) => x switch {0=>11,1=>22,2=>33,7=>77,_=>-1};
    public static int Lab10Array(int[,] m) { int s=0;for(int r=0;r<m.GetLength(0);r++)for(int c=0;c<m.GetLength(1);c++)s+=m[r,c];return s; }
    public static string Lab11Decode(byte[] p,byte k) { for(int i=0;i<p.Length;i++)p[i]^=(byte)(k+i*17);return Encoding.UTF8.GetString(p); }
    public static int Lab12Reflection(string name) { MethodInfo? m=typeof(Labs).GetMethod(name);return m?.MetadataToken??-1; }
    public static int Lab13Delegate(int[] a,Func<int,int> f) { int s=0;foreach(int x in a)s+=f(x);return s; }
    public static int Lab14Span(ReadOnlySpan<byte> p) { int h=0;foreach(byte b in p)h=(h*33)^b;return h; }
    public static int Lab15Pattern(object? o) => o switch { int x when x>0=>x, string s=>s.Length, null=>-1,_=>0};
}

static class IlDump {
    static readonly Dictionary<short,OpCode> Ops = typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static)
        .Where(f=>f.FieldType==typeof(OpCode)).Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>o.Value);
    public static void Dump(MethodInfo m) {
        Console.WriteLine($"=== IL {m.Name} token=0x{m.MetadataToken:x8} ===");
        byte[] il=m.GetMethodBody()?.GetILAsByteArray()??Array.Empty<byte>();int p=0;
        while(p<il.Length){int off=p;short v=il[p++];if(v==0xfe)v=(short)(0xfe00|il[p++]);OpCode op=Ops[v];
            int size=op.OperandType switch{OperandType.InlineNone=>0,OperandType.ShortInlineI or OperandType.ShortInlineVar or OperandType.ShortInlineBrTarget=>1,
                OperandType.InlineVar=>2,OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineSig or OperandType.InlineString or OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR=>4,
                OperandType.InlineI8 or OperandType.InlineR=>8,OperandType.InlineSwitch=>4+4*BitConverter.ToInt32(il,p),_=>0};
            string operand=size==0?"":Convert.ToHexString(il.AsSpan(p,size));Console.WriteLine($"{off:x4}: {op.Name,-12} {operand}");p+=size;}
    }
}

class Program {
    static async Task Main(){
        Node n=new(){Value=1,Next=new(){Value=2}};int[,]m={{1,2},{3,4}};byte[] enc=Encoding.UTF8.GetBytes("mentor");for(int i=0;i<enc.Length;i++)enc[i]^=(byte)(7+i*17);
        long total=Labs.Lab01CountPositive([-1,2,3])+Labs.Lab02LinkedSum(n)+Labs.Lab03GenericMax(4,9)+Labs.Lab04Boxing(5)+Labs.Lab05Interface(new Doubler(),6);
        total+=Labs.Lab06Exception("bad")+Labs.Lab07Iterator(6).Sum()+await Labs.Lab08Async(3)+Labs.Lab09Switch(7)+Labs.Lab10Array(m);
        total+=Labs.Lab11Decode(enc,7).Length+Labs.Lab12Reflection(nameof(Labs.Lab01CountPositive))+Labs.Lab13Delegate([1,2,3],x=>x*x)+Labs.Lab14Span([1,2,3])+Labs.Lab15Pattern("abcd");
        Console.WriteLine($"chapter12 evidence={total}");
        foreach(MethodInfo mi in typeof(Labs).GetMethods(BindingFlags.Public|BindingFlags.Static).Where(m=>m.Name.StartsWith("Lab")).OrderBy(m=>m.Name))IlDump.Dump(mi);
    }
}
```

## Build and tool boundary

```bash
dotnet build ManagedLabs.csproj -c Release -o build/ch12
dotnet build/ch12/ManagedLabs.dll
file build/ch12/ManagedLabs build/ch12/ManagedLabs.dll
ghidraRun                         # import the native apphost and managed DLL separately
pwndbg -nx --args build/ch12/ManagedLabs
```

The first file is an ELF native apphost; the DLL is a PE32 managed assembly. In pwndbg, pending breakpoints on `coreclr_initialize` and `coreclr_execute_assembly` resolved when `libcoreclr.so` loaded. The observed stack was apphost → `libhostfxr.so` → `libhostpolicy.so` → `libcoreclr.so`. Do not assign C# semantics to apphost functions merely because they launch the application.

# Walkthrough 01 — Recover an array loop from evaluation-stack IL

## Evidence

```cil
0000 ldc.i4.0; 0001 stloc.0; 0002 ldarg.0; 0003 stloc.1
0004 ldc.i4.0; 0005 stloc.2; 0006 br.s 0E
0008 ldloc.1; 0009 ldloc.2; 000a ldelem.i4
000b ldc.i4.0; 000c ble.s 04
000e ldloc.0; 000f ldc.i4.1; 0010 add; 0011 stloc.0
0012 ldloc.2; 0013 ldc.i4.1; 0014 add; 0015 stloc.2
0016 ldloc.2; 0017 ldloc.1; 0018 ldlen; 0019 conv.i4; 001a blt.s EC
001c ldloc.0; 001d ret
```

## Full reconstruction

Track the abstract stack at each offset. `ldelem.i4` consumes array and index and produces the element. `ble.s` consumes element and zero, proving the increment executes only for a positive value. Local 2 is the induction variable because it is initialized to zero, incremented, and compared with `ldlen`. Local 0 is the accumulator. Rename those locals to `count` and `i`, turn the backward branch into `for (i=0; i<a.Length; i++)`, and preserve signed comparison: `ble` is not an unsigned test. Validate with empty, all-negative, zero-only, and mixed arrays. The reconstructed C# is `if (a[i] > 0) count++`, returning 2 for `[-1,2,3]`.

# Walkthrough 02 — Infer a managed linked-list layout

```cil
0000 ldc.i4.0; 0001 stloc.0; 0002 br.s 11
0004 ldloc.0; 0005 ldarg.0; 0006 ldfld 01000004; 000b add; 000c stloc.0
000d ldarg.0; 000e ldfld 02000004; 0013 starg.s 00
0015 ldarg.0; 0016 brtrue.s EC; 0018 ldloc.0; 0019 ret
```

Two `ldfld` tokens applied to the same object imply two instance fields. One participates in integer addition; the other replaces the object argument and is null-tested. Therefore token `0x04000001` is the integer payload and token `0x04000002` is a self-referential next pointer. Resolve tokens through metadata before naming them. The back edge at `brtrue.s` creates `while (p != null)`. On the constructed nodes 1→2→null, the answer is 3. A cycle is an edge case: this routine has no visited set and would not terminate.

# Walkthrough 03 — Decode constrained generic dispatch

```cil
0000 ldarga.s 00; 0002 ldarg.1
0003 constrained. 0400001B
0009 callvirt 1C00000A
000e ldc.i4.0; 000f bge.s 02
0011 ldarg.1; 0012 ret; 0013 ldarg.0; 0014 ret
```

`ldarga` loads the address of generic argument `a`. The `constrained.` prefix tells the runtime that the following virtual/interface call must work for either value or reference instantiations without blindly boxing. Resolve the method token as `IComparable<T>.CompareTo`. The signed `bge` selects `a` when the comparison is nonnegative; otherwise it selects `b`. Test equal values as well as greater/lesser values because equality chooses the first operand, an observable detail for reference types.

# Walkthrough 04 — Recognize boxing and unboxing

```cil
0000 ldarg.0; 0001 box 2F000001
0006 unbox.any 2F000001
000b ldc.i4.1; 000c add; 000d ret
```

Both type tokens resolve to `System.Int32`. `box` allocates/wraps a value as an object; `unbox.any` extracts a value of the named type. Because there is no intervening use of the object, an optimizing JIT may erase the allocation. The semantic reconstruction remains `object o=x; return (int)o+1`. Distinguish this from `unbox`, which produces a managed pointer. Supplying an object of the wrong runtime type to an independently reconstructed routine would throw `InvalidCastException`, not numerically convert it.

# Walkthrough 05 — Recover interface dispatch

```cil
0000 ldarg.0; 0001 ldarg.1; 0002 callvirt 02000006
0007 ldc.i4.3; 0008 add; 0009 ret
```

Resolve the MemberRef token rather than guessing from `callvirt`. Its declaring type is `ICalc`, signature is `int Apply(int)`. The receiver and integer argument are pushed left-to-right, and the return is incremented by three. With a `Doubler`, input 6 returns 15. Dynamic analysis should compare at least two implementations: the same IL call site may reach different native JIT addresses because dispatch depends on the receiver's method table.

# Walkthrough 06 — Reconstruct exception regions, not just branches

```cil
0000 ldarg.0; 0001 call 1D00000A; 0006 stloc.0; 0007 leave.s 0C
0009 pop; 000a ldc.i4.m1; 000b stloc.0; 000c leave.s 07
000e ldarg.0; 000f call 1E00000A; 0014 endfinally
0015 ldloc.0; 0016 ret
```

The byte stream alone does not identify which handler catches which type; inspect `MethodBody.ExceptionHandlingClauses`. The first protected region calls `Int32.Parse`. Its typed handler catches `FormatException`, discards the exception with `pop`, and stores −1. The finally handler calls `GC.KeepAlive`. `leave` differs from `br`: it exits a protected region and executes required finally clauses. Confirm `"12" → 12`, `"bad" → -1`, but overflow is not caught because `OverflowException` is a different type.

# Walkthrough 07 — Find the iterator state machine hidden behind a stub

```cil
0000 ldc.i4.s FE
0002 newobj 19000006
0007 dup; 0008 ldarg.0; 0009 stfld 0C000004; 000e ret
```

This method does not contain the visible loop. It creates a compiler-generated iterator object with initial state −2, stores captured `n`, and returns it. Follow the constructed type to `MoveNext`; locate state, current value, captured input, and loop-index fields. Reconstruct suspension points from writes to the state field and `MoveNext` returning true. Enumeration for `n=6` yields 0, 4, 16. Calling the method without enumerating executes no loop body—an important dynamic-analysis trap.

# Walkthrough 08 — Recover an async state machine

```cil
0000 ldloca.s 00; 0002 call 1F00000A; 0007 stfld 0F000004
000c ldloca.s 00; 000e ldarg.0; 000f stfld 10000004
0014 ldloca.s 00; 0016 ldc.i4.m1; 0017 stfld 0E000004
001c ldloca.s 00; 001e ldflda 0F000004; 0023 ldloca.s 00
0025 call 0100002B; 002a ldloca.s 00; 002c ldflda 0F000004
0031 call 2100000A; 0036 ret
```

This is the kickoff method. Identify the generated struct from the local signature, then inspect its `MoveNext`. Fields correspond to builder, captured `x`, state, and awaiter. The −1 state means started/not suspended; `Start<TStateMachine>` invokes `MoveNext`, and the final call obtains `Task<int>`. In `MoveNext`, `Task.Yield` stores an awaiter and state before returning; resumption computes `x*7` and calls `SetResult`. For x=3 the awaited result is 21. Do not mistake kickoff `ret` for a void semantic return.

# Walkthrough 09 — Decode a switch table correctly

```cil
0000 ldarg.0
0001 switch 03000000060000000B00000010000000
0012 ldarg.0; 0013 ldc.i4.7; 0014 beq.s 11; 0016 br.s 14
0018 ldc.i4.s 0B; 001d ldc.i4.s 16; 0022 ldc.i4.s 21
0027 ldc.i4.s 4D; 002c ldc.i4.m1; 002e ldloc.0; 002f ret
```

`switch` has a 4-byte case count followed by signed 32-bit displacements relative to the end of the table. The operand starts with count 3, so indexes 0,1,2 map to 11,22,33. Value 7 is handled by a separate comparison and maps to 77; all others map to −1. A naïve decoder that treats all operand bytes as one integer loses the table. Test −1, 0, 2, 3, 7, and a large integer.

# Walkthrough 10 — Reconstruct rectangular-array access

```cil
000a ldloc.0; 000b ldarg.0; 000c ldloc.1; 000d ldloc.2
000e call 2200000A; 0013 add; 0014 stloc.0
0019 ldloc.2; 001a ldarg.0; 001b ldc.i4.1; 001c callvirt 2300000A; 0021 blt.s E7
0027 ldloc.1; 0028 ldarg.0; 0029 ldc.i4.0; 002a callvirt 2300000A; 002f blt.s D5
```

Resolve `0x0A000022` as the special rectangular-array `Get(int,int)` method and the other MemberRef as `Array.GetLength(int)`. Local 1 is row, local 2 column. The inner bound uses dimension 1; outer uses dimension 0. This is not a jagged `int[][]`, which would use `ldelem.ref` followed by `ldelem.i4`. The 2×2 matrix sums to 10; a 0×N array exits through the outer bound without indexing.

# Walkthrough 11 — Reverse a byte decoder with truncation semantics

```cil
0004 ldarg.0; 0005 ldloc.0; 0006 ldelema 32000001
000b dup; 000c ldind.u1; 000d ldarg.1; 000e ldloc.0
000f ldc.i4.s 11; 0011 mul; 0012 add; 0013 xor
0014 conv.u1; 0015 stind.i1
0021 call 2400000A; 0026 ldarg.0; 0027 callvirt 2500000A; 002c ret
```

`ldelema` and `dup` preserve the destination address while loading the old byte. The key expression is `k + i*17`; `conv.u1` truncates modulo 256 before `stind.i1`. The final calls resolve `Encoding.UTF8` and `GetString`. Reimplement with explicit byte wrapping, test indexes beyond 15, and retain mutation: the input array is decoded in place. The specimen recovers `mentor`.

# Walkthrough 12 — Resolve reflection and null propagation

```cil
0000 ldtoken 05000002; 0005 call 2600000A
000a ldarg.0; 000b call 2700000A
0010 dup; 0011 brtrue.s 03; 0013 pop; 0014 ldc.i4.m1; 0015 ret
0016 callvirt 2800000A; 001b ret
```

`ldtoken` names the `Labs` type, `Type.GetTypeFromHandle` turns it into a `Type`, and `GetMethod(name)` performs dynamic lookup. `dup/brtrue/pop` is the compiler's null-conditional lowering. A found method returns its metadata token; a missing method returns −1. Static call graphs miss the possible targets because the method name is data. Search constant strings and trace `GetMethod` arguments at runtime.

# Walkthrough 13 — Follow a delegate invocation

```cil
000c ldloc.0; 000d ldarg.1; 000e ldloc.3
000f callvirt 2900000A; 0014 add; 0015 stloc.0
001a ldloc.2; 001b ldloc.1; 001c ldlen; 001d conv.i4; 001e blt.s E8
```

Resolve the token to `Func<int,int>.Invoke`. The delegate object contains a target and method pointer/invocation list; the call graph is therefore data-dependent. The surrounding array loop is structurally like Walkthrough 1 but accumulates callback results. For `[1,2,3]` and `x=>x*x`, the result is 14. Test a capturing lambda as an edge case: the target becomes a closure object with captured fields.

# Walkthrough 14 — Understand Span without inventing an array

```cil
0002 ldarg.0; 0003 stloc.1; 0004 ldc.i4.0; 0005 stloc.2
0008 ldloca.s 01; 000a ldloc.2; 000b call 2A00000A; 0010 ldind.u1
0012 ldloc.0; 0013 ldc.i4.s 21; 0015 mul; 0016 ldloc.3; 0017 xor
001d ldloc.2; 001e ldloca.s 01; 0020 call 2B00000A; 0025 blt.s E1
```

The address of local 1 is passed to Span accessors because `ReadOnlySpan<byte>` is a byref-like value type. The indexer returns a managed reference, consumed by `ldind.u1`; the length accessor controls the loop. Reconstruct `h=(h*33)^b`. Do not model Span as a heap array or allow it to escape. For bytes 1,2,3 the sequence is 1, 35, 1152. Native JIT output may inline both accessors and keep pointer plus length in registers.

# Walkthrough 15 — Rebuild pattern-matching decision order

```cil
0000 ldarg.0; 0001 stloc.3; 0002 ldloc.3; 0003 isinst 2F000001
0008 brfalse.s 09; 000a ldloc.3; 000b unbox.any 2F000001; 0010 stloc.0
0013 ldloc.3; 0014 isinst 37000001; 0019 stloc.1; 001a ldloc.1; 001b brtrue.s 0D
001d ldloc.3; 001e brfalse.s 13
0022 ldloc.0; 0023 ldc.i4.0; 0024 ble.s 11
0026 ldloc.0; 002a ldloc.1; 002b callvirt 2C00000A
0033 ldc.i4.m1; 0037 ldc.i4.0; 0039 ldloc.2; 003a ret
```

The order is part of semantics. First test boxed int, then string, then null, then fallback. A positive int returns itself; nonpositive int reaches fallback 0 because its guard fails and later type arms are not reconsidered. A string returns length, null returns −1, another object returns 0. Preserve `isinst` null behavior and the guard branch. Validate with `5`, `0`, `-2`, `"abcd"`, `null`, and `new object()`.

# Practice Questions

1. Decode the abstract stack at Walkthrough 1 offset `000a`.
2. How can field roles in Walkthrough 2 be inferred before names are resolved?
3. Why is `constrained.` important for a generic value type?
4. Distinguish `box`, `unbox`, and `unbox.any`.
5. Why is an interface `callvirt` not necessarily a class virtual override?
6. Why must exception tables be analyzed in addition to IL bytes?
7. Where is the original body of an iterator method found?
8. What does an async kickoff method return before the logical result exists?
9. How are CIL switch destinations calculated?
10. What IL distinction separates rectangular and jagged arrays?
11. Why does the decoder require modulo-256 arithmetic?
12. Why can reflection hide call-graph edges?
13. What extra object may appear for a capturing lambda?
14. Why must Span not be reconstructed as an ordinary array?
15. What does pattern-arm ordering change for a nonpositive boxed integer?
16. Explain the native apphost/managed DLL distinction.
17. Why did the Ghidra failure matter as evidence?
18. Design a dynamic experiment distinguishing iterator creation from execution.
19. Design boundary tests for `Lab06Exception`.
20. Give a rigorous workflow for an unfamiliar managed method.

# Complete Solutions

## 1. Solution

Before `ldelem.i4`, the stack is `[array,index]`; it consumes both and leaves `[element]`. The next `ldc.i4.0` gives `[element,0]`, and `ble.s` consumes those operands. This proves both the indexed access and signed positive test.

## 2. Solution

Use data flow and types. The first field is added to an integer accumulator, so it is numeric payload. The second replaces the object argument and is null-tested, so it is a reference link. Metadata resolution confirms rather than originates that inference.

## 3. Solution

It allows the following interface/virtual call to dispatch correctly for unknown `T`, using an unboxed value-type implementation when possible and normal reference dispatch otherwise. Omitting it from a rewriter can change boxing and semantics.

## 4. Solution

`box T` produces an object representation. `unbox T` produces a managed pointer to the boxed value; `unbox.any T` extracts a value. Wrong types can throw, so these are not general numeric conversions.

## 5. Solution

The opcode also supplies null checking and late-bound interface/delegate calls. Resolve the method token's declaring type and signature; the receiver's runtime type selects the implementation.

## 6. Solution

Handler type, protected ranges, filter/finally kind, and handler ranges live in method metadata. A `leave` byte sequence cannot alone tell which finally clauses execute or what exception a handler catches.

## 7. Solution

Follow the `newobj` target to the compiler-generated iterator type and analyze `MoveNext`, plus `Current` and state fields. The user-facing stub merely constructs the state machine.

## 8. Solution

It constructs/starts a state machine and returns `Task<int>`. The eventual integer is delivered by the builder's `SetResult`; a kickoff `ret` is not the logical method completion.

## 9. Solution

Read the 32-bit case count, then that many signed 32-bit relative offsets. Each target is relative to the address immediately following the entire switch table, not the opcode start.

## 10. Solution

Rectangular arrays use special rank-specific `Get`/`Set` MemberRefs and dimension-aware `GetLength`. Jagged arrays are arrays of references and normally show `ldelem.ref` followed by another element operation.

## 11. Solution

CIL performs the arithmetic on stack integers, then `conv.u1` truncates before the byte store. An independent clone using unbounded integers will disagree once `k+i*17` exceeds 255.

## 12. Solution

The target name is a runtime string passed to metadata lookup. There may be no direct call instruction to the selected method, so static call edges must be supplemented by string/data flow and dynamic tracing.

## 13. Solution

A compiler-generated closure object holds captured variables and becomes the delegate target. A noncapturing lambda may use a cached static delegate instead.

## 14. Solution

Span is a byref-like value describing a contiguous region with pointer/reference and length semantics. It cannot be boxed or freely escape to the heap. Treating it as an array invents allocation and ownership behavior.

## 15. Solution

The int type test succeeds, but its `x>0` guard fails. Control proceeds to the default result 0, not to the string/null tests as if the first type test had failed. Preserve the compiler's decision DAG.

## 16. Solution

The apphost is native ELF startup code that locates hostfxr and CoreCLR. The DLL contains CLR metadata and CIL for `Labs`. Ghidra's apphost decompilation explains hosting, not the managed algorithms; use IL/metadata tools for those.

## 17. Solution

It prevents false confidence. The log reported invalid custom-attribute fields and an EOF metadata error on this .NET 10 file, so its incomplete DLL model cannot be treated as authoritative. Cross-check with runtime reflection and raw method bodies.

## 18. Solution

Call `Lab07Iterator(6)` without enumeration and observe no yielded values/body-side effects. Then invoke `MoveNext` once at a time while watching state/current fields; observed outputs 0,4,16 demonstrate deferred execution and suspension.

## 19. Solution

Use valid decimal, malformed text, empty string, maximum/minimum Int32, and one-above/one-below range. Expected results are parsed value or −1 only for format errors; overflow must escape because the code catches only `FormatException`.

## 20. Solution

Identify file/CLR metadata, enumerate types and method tokens, decode method headers and exception clauses, simulate the evaluation stack per basic block, resolve tokens/signatures, reconstruct structured flow and generated state machines, inspect host/JIT boundaries dynamically, then differential-test a clean reimplementation on normal and edge inputs. Record tool limitations and never confuse CIL, metadata, and JIT-native code.

## Chapter result

You have now analyzed arrays, object graphs, generics, boxing, interfaces, exceptions, iterators, async, switches, multidimensional arrays, byte transforms, reflection, delegates, Span, and pattern matching from actual CIL, while also tracing the native CLR host boundary.
