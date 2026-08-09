# Chapter 5 — Beyond the Documentation

> [!source]
> **From the book:** the NTDLL generic-table case study and its reconstruction process.
> **Added explanation:** explicit hypotheses, invariants, pseudocode, validation tactics, and exercises are labeled as such.

## Chapter Overview

This chapter changes the question from “what does this function do?” to “how can I recover an interface that was never documented for me?” The author investigates the native Windows generic-table API, starting only with exported names and machine code. The important lesson is not the historical API itself. It is the disciplined way incomplete observations become a defensible data model, function prototypes, callback contracts, and reconstructed algorithms.

By the end, you should be able to:

- locate a family of related undocumented functions;
- distinguish evidence from guesses;
- infer parameters, return types, structures, and callback roles;
- combine several functions to recover shared invariants;
- reconstruct traversal, insertion, lookup, and deletion behavior;
- validate a recovered interface with a small client program.

```text
Export names and call sites
│
├── easiest functions → table header fields
├── element access → list layout and cache
├── insertion → callbacks, allocation, and tree nodes
├── lookup/deletion → comparison and ownership
└── cross-checks → coherent API and structures
```

## 5.1 Reversing and Interoperability

### Core Idea

Undocumented code can still be used safely enough for research when its **observable contract** has been reconstructed: how it is called, what memory it expects, what it returns, and which invariants it maintains.

Interoperability is a stronger goal than recognizing an algorithm. To call a function, you need its ABI-level contract:

| Question | Evidence to seek |
|---|---|
| Calling convention | stack cleanup, register use, prologue/epilogue |
| Parameter count | caller setup and callee accesses |
| Parameter meaning | data flow from each argument |
| Return value | value placed in `EAX`, caller tests |
| Structure layout | repeated offsets across functions |
| Callback prototypes | indirect-call arguments and results |
| Ownership | allocation/free callbacks and failure paths |

> [!warning]
> An internal API can change between operating-system versions. A correct reconstruction for one binary is not a promise of compatibility with another.

## 5.2 Laying the Ground Rules

The book’s investigation is primarily static. Static analysis is useful because it exposes every branch and does not require a ready-made caller, but ambiguous findings should later be checked dynamically.

### A practical evidence ledger — added method

Maintain four columns while reversing:

| Observation | Interpretation | Confidence | How to test |
|---|---|---:|---|
| `[table+0x14]` is incremented after insertion | element count | high | compare with count API |
| indirect call receives `(table, a, b)` | comparison callback | medium | inspect return-value branches |
| returned node is adjusted by a fixed offset | hidden node header precedes user bytes | high | compare allocation size |

This prevents an attractive early guess from silently becoming “fact.” Rename fields only when evidence improves.

## 5.3 Locating Undocumented APIs

### What are we looking for?

The author first identifies exported NTDLL names belonging to one family, including initialization, counting, emptiness, indexed retrieval, insertion, lookup, and deletion. Names supply hypotheses, not definitions. `RtlGetElementGenericTable`, for example, might retrieve by ordinal rather than by key; only the code settles that distinction.

### Step-by-step discovery workflow

1. Enumerate exports from the target module.
2. Group names by a stable stem such as `GenericTable`.
3. Separate alternative implementations—here, names with an `Avl` suffix—from the target family.
4. Begin with the shortest functions. Tiny accessors reveal structure fields cheaply.
5. Record common offsets and indirect calls.
6. Analyze increasingly complex functions only after the shared vocabulary is known.
7. Search callers or build a controlled harness to validate the recovered interface.

### Why begin with easy functions?

A complex insertion routine may touch a dozen fields without revealing what any means. If a two-instruction routine returns `[table+offset]`, and its name is a number-of-elements accessor, the same offset acquires a strong semantic label everywhere else.

## 5.4 Case Study: The Generic Table API in NTDLL.DLL

### Mental model recovered across the chapter

The generic table combines two views of the same elements:

```text
TABLE HEADER
├── tree root ───────────────► ordered splay tree
├── insertion-order list ───► node ⇄ node ⇄ node
├── element count
├── ordered-access cache
└── callbacks
    ├── compare
    ├── allocate
    └── free

NODE
├── tree links
├── list links
└── caller's element bytes
```

The tree supports key-based search. The linked list supports retrieval by insertion ordinal. A cached list position accelerates nearby ordinal requests. The API is “generic” because it delegates comparison and memory management to caller callbacks.

## 5.5 `RtlInitializeGenericTable`

### Core Idea

Initialization is the best place to infer the table header because writes to a fresh object reveal default state and persistent configuration.

### Reconstruction procedure

1. Identify the first parameter as the table address: most stores use it as a base.
2. Classify zeroed fields as roots, counts, or cache state—not yet by exact name.
3. Recognize a self-referential pair of pointers as an empty doubly linked-list sentinel.
4. Match later parameters to fields that store function pointers.
5. Treat the final opaque value as caller context because it is preserved and later passed to callbacks.

### Why a self-linked list head represents “empty”

```text
head.Flink ─┐
            ▼
          [head]
            ▲
head.Blink ─┘
```

No `NULL` special case is required. Insertion links a node between the head’s two directions; removal restores the head’s self-links.

### Reconstructed conceptual prototype

```c
void InitializeTable(
    TABLE *table,
    COMPARE_CALLBACK compare,
    ALLOCATE_CALLBACK allocate,
    FREE_CALLBACK free,
    void *context
);
```

This is a semantic prototype, not a claim that names or exact types appeared in source.

## 5.6 Counting and Emptiness

`RtlNumberGenericTableElements` exposes the count field. `RtlIsGenericTableEmpty` tests a representation of emptiness—typically the root or count. Together they produce cross-function evidence:

- the count must be zero after initialization;
- successful unique insertion increments it;
- successful deletion decrements it;
- lookup does not change it.

### Common misunderstanding

Do not conclude that any tested zero field is “the count.” The count accessor identifies the count directly; the emptiness function may test the root because a null root is cheaper and equivalent under the table invariant.

## 5.7 `RtlGetElementGenericTable`

### Core Idea

Despite its name, this function retrieves an element by **zero-based insertion-order index**, not by comparison key. Its long body implements a cached bidirectional list walk.

### Setup and initialization

The function first rejects an out-of-range index. It then decides where traversal should begin:

- the list head;
- a cached node and cached index;
- or the tail, when the requested index is nearer the end.

### Logic and structure

The multiple “search loops” in the disassembly are optimized versions of the same operation: walk forward or backward until current index equals requested index.

```c
void *GetElement(TABLE *t, unsigned wanted) {
    if (wanted >= t->count)
        return NULL;

    POSITION p = choose_nearest_start(t, wanted);
    while (p.index < wanted) { p.node = p.node->Flink; p.index++; }
    while (p.index > wanted) { p.node = p.node->Blink; p.index--; }

    t->cache_node = p.node;
    t->cache_index = p.index;
    return user_bytes(p.node);
}
```

### Why the returned pointer is adjusted

The list/tree metadata is internal. The caller should see only its stored record. A fixed addition to the node address therefore reveals the size of a hidden header:

```text
allocation base                  returned pointer
      │                                │
      ▼                                ▼
[ tree/list metadata ][ caller's bytes ........ ]
```

### Worked trace

Suppose a table has ten elements, the cache points to ordinal 6, and the caller requests ordinal 8.

1. Bounds check succeeds because `8 < 10`.
2. Starting at ordinal 6 requires two forward steps.
3. Starting at the head requires eight; starting at the tail requires one or two depending on representation.
4. The routine selects the nearest valid anchor encoded by its branch logic.
5. It updates the cache to ordinal 8 and returns the payload pointer.

The key lesson is to reduce several assembly loops to one abstract traversal rule.

## 5.8 `RtlInsertElementGenericTable`

Insertion separates **locating** from **allocating/linking**.

### `RtlLocateNodeGenericTable`

This helper traverses the ordered tree and invokes the caller’s comparison callback. The callback’s three-way result means:

```text
less    → follow one child
equal   → element already exists
greater → follow the other child
```

It returns enough information to say either “found this node” or “insert beneath this parent on this side.” This avoids traversing twice.

### `RtlRealInsertElementWorker`

When no equal element exists, the worker:

1. asks the allocation callback for metadata plus payload size;
2. initializes tree and list links;
3. copies caller bytes into the payload region;
4. attaches the node at the located parent/side;
5. appends it to the insertion-order list;
6. increments the element count;
7. splays the inserted node toward the root;
8. returns the payload pointer and reports that a new element was created.

When an equal item exists, no allocation is needed; the existing payload is returned and the “new element” flag is false.

### Callback contracts

```c
int compare(TABLE *table, const void *left, const void *right);
void *allocate(TABLE *table, unsigned bytes);
void free(TABLE *table, void *allocation);
```

The exact typedef spelling is platform-specific. The indirect call sites establish the semantics.

### Splay trees

A splay tree is a binary search tree that rotates a recently accessed node toward the root. It does not store an explicit balance factor. Individual operations can be expensive, but a sequence has good amortized behavior, especially when access has locality.

| Property | Ordinary unbalanced BST | Splay tree |
|---|---|---|
| Search ordering | comparison key | comparison key |
| Explicit balance metadata | none | none |
| Reorganization | normally none | after access/update |
| Useful behavior | simple | frequently used nodes move near root |

> [!deep dive]
> A rotation changes links without changing in-order key order. That invariant explains why lookup remains correct after splaying. Reverse the pointer writes as a small graph transformation; do not reason about each store in isolation.

## 5.9 Lookup and Deletion

### `RtlLookupElementGenericTable`

Lookup performs a tree search through the same locator/helper logic used by insertion. On equality it returns the user payload rather than the internal node. Unlike ordinal retrieval, lookup requires the comparison callback and follows tree edges, not list links.

### `RtlDeleteElementGenericTable`

The book reduces deletion to three conceptual phases:

1. locate the node by comparison key;
2. remove it from both the splay tree and insertion-order list;
3. invoke the caller’s free callback and return success.

Every successful deletion must preserve these invariants:

- tree ordering remains valid;
- list neighbors bypass the deleted node;
- count decreases exactly once;
- cached ordinal state cannot refer to freed storage;
- caller-owned payload is no longer accessible.

## 5.10 Putting the Pieces Together

### Reconstructed API-level behavior

| Function | Input interpretation | Main representation | Result |
|---|---|---|---|
| Initialize | callbacks + context | header/list | empty table |
| Count | table | header | element count |
| IsEmpty | table | header/root | Boolean |
| GetElement | ordinal | linked list/cache | payload or null |
| Lookup | key record | splay tree | payload or null |
| Insert | record + size | tree and list | existing/new payload |
| Delete | key record | tree and list | success Boolean |

### Controlled validation harness — added example

Use a table of records `{id, name}` with comparison based only on `id`.

1. Initialize with logging allocation/free callbacks.
2. Insert IDs `30, 10, 20` and record returned pointers.
3. Insert ID `20` again with a different name. Verify count does not rise.
4. Retrieve ordinals `0,1,2`; verify they reflect insertion order of unique items.
5. Lookup ID `10`; verify key search is independent of ordinal.
6. Delete ID `30`; verify one free call and count reduction.
7. Query out-of-range ordinal; expect null and no mutation.

The harness tests contract and invariants rather than private pointer values.

## Common Mistakes

**Mistake:** assigning structure names from one function.
**Why wrong:** optimized code often gives several fields similar-looking roles.
**Correction:** require cross-function corroboration.

**Mistake:** treating export names as specifications.
**Correction:** use names to generate hypotheses, then prove them with data flow.

**Mistake:** confusing internal-node and payload pointers.
**Correction:** track every fixed pointer adjustment and allocation-size addition.

**Mistake:** reconstructing assembly line-by-line without identifying invariants.
**Correction:** model tree order, list integrity, count, cache validity, and ownership.

## Chapter in One View

```text
small accessors establish fields
        ↓
ordinal retrieval reveals list + hidden node header + cache
        ↓
insertion reveals comparison/allocation callbacks + tree
        ↓
lookup and deletion confirm representations and ownership
        ↓
all observations become a testable external contract
```

## What You Should Be Able to Explain

- [ ] Why several related functions are stronger evidence than one function.
- [ ] How indirect calls reveal callback prototypes.
- [ ] Why the table maintains both a tree and a list.
- [ ] How an adjusted return pointer reveals hidden metadata.
- [ ] What splaying changes and what it must preserve.

## What You Should Be Able to Do

- [ ] Recover a tentative structure from repeated offsets.
- [ ] Convert four optimized traversal loops into one pseudocode model.
- [ ] Design a harness that distinguishes lookup-by-key from get-by-index.
- [ ] State confidence and a falsification test for every inferred field.

## Practice Questions

1. Why is initialization often a better starting point than insertion?
2. What observations distinguish an empty list sentinel from two null pointers?
3. How would you prove that a field is a count rather than a Boolean?
4. Why might an insertion routine return an existing element?
5. Which invariants must deletion preserve when two representations share nodes?
6. A function compares a requested integer with a count, walks `Flink`, and adds a constant before returning. Reconstruct its likely contract.
7. Design a test that reveals whether duplicate keys replace, reject, or reuse records.
8. Explain why a dynamically observed root address is not part of the stable API contract.

## Practice Question Solutions

1. Initialization writes known baseline values and persistent callbacks, making offsets easier to classify; insertion mixes many transient operations.
2. Both link fields point back to the head, and insertion/removal code treats the head as a node rather than testing for null.
3. Find a direct accessor, then observe increment/decrement exactly once on successful insert/delete and no change on lookup.
4. Generic set/table semantics commonly preserve a unique key; returning the existing payload lets the caller learn what already occupies that key.
5. Tree order, list linkage, count, cache validity, and allocation ownership.
6. It is likely indexed retrieval: reject out-of-range ordinal, traverse an internal list, then return payload after a hidden node header.
7. Insert one key twice with different non-key bytes; inspect count, returned pointer identity, stored bytes, allocation count, and status flag.
8. ASLR, allocator state, and tree rotations can change addresses while input/output behavior and invariants remain stable.

---

Next: [[Chapter 06 - Deciphering File Formats]]

## Integrated Hands-On Code

Work the paired source/assembly exercises in [[Mentor Code Labs II - Formats Vulnerabilities and Malware]]. For this chapter, do not claim mastery until you can predict the relevant registers, stack/memory state, branches, and outputs before running the debugger.

Use [[Ghidra and GDB-pwndbg - Complete Integrated Field Manual]] alongside the lab: establish the static hypothesis in Ghidra, prove it with breakpoints/watchpoints and machine state in GDB/pwndbg, then transfer the confirmed types, names, edges, and comments back to Ghidra.
