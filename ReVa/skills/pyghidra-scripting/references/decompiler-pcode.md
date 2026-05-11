# Decompiler internals: HighFunction, Varnode, PcodeOp

The Flat-API `getDecompiler().decompile(func)` flow gives you back C source as a string. Most of the time that's enough — `decompile-and-grep` is a fine workflow. The next step up is reaching into the decompiler's internal representation:

- **`HighFunction`** — the decompiler's view of a function (variables, basic blocks, PCode in SSA form).
- **`HighSymbol` / `HighVariable`** — typed, named locals/parameters/globals as the decompiler understands them, plus the storage and definition info that doesn't appear in the raw listing.
- **`Varnode`** — a single SSA value (a constant, a register read, a memory load, an intermediate). The atomic unit of PCode data flow.
- **`PcodeOp`** — a single operation (`COPY`, `LOAD`, `CALL`, `INT_ADD`, …). The atomic unit of PCode control flow.

When the LLM is asked "where does this argument come from", "what's the constant fed into this call", "which registers does this function touch as seen by the decompiler", this is the layer to reach for.

## Getting a `HighFunction`

```python
from ghidra.app.decompiler import DecompInterface, DecompileOptions

decomp = DecompInterface()
opts = DecompileOptions()
opts.grabFromProgram(currentProgram)
decomp.setOptions(opts)
decomp.openProgram(currentProgram)
try:
    res = decomp.decompileFunction(func, 30, monitor)
    if not res.decompileCompleted():
        print(f"decompile failed: {res.getErrorMessage()}")
    else:
        hf = res.getHighFunction()
        # hf is a HighFunction — see below
finally:
    decomp.dispose()
```

`HighFunction` is invalidated when the decompiler is disposed. Don't squirrel one away past the `dispose()` call; pull what you need (names, addresses, constants) and let it die.

## `HighFunction` essentials

| Call | Returns | Notes |
|---|---|---|
| `hf.getFunction()` | `Function` | The underlying `Function`. |
| `hf.getLocalSymbolMap()` | `LocalSymbolMap` | Locals, parameters, and globals seen in this function. |
| `hf.getGlobalSymbolMap()` | `GlobalSymbolMap` | Globals only (subset). |
| `hf.getPcodeOps()` | `Iterator<PcodeOpAST>` | Every PCode op in the function, in address order. |
| `hf.getPcodeOps(addr)` | `Iterator<PcodeOpAST>` | PCode ops at a specific address. |
| `hf.getBasicBlocks()` | `List<PcodeBlockBasic>` | SSA basic blocks. |
| `hf.getNumVarnodes()` | int | Sanity-check size. |

## `LocalSymbolMap` — looking up variables

```python
syms = hf.getLocalSymbolMap()
print(f"params={syms.getNumParams()} locals={syms.getNumLocals()}")

# Iterate all symbols (params + locals + globals seen here)
it = syms.getSymbols()           # Java Iterator — use hasNext()
while it.hasNext():
    sym = it.next()             # HighSymbol
    hv = sym.getHighVariable()  # HighVariable or None
    print(f"{sym.getName()}  {sym.getDataType()}  category={sym.getCategoryIndex()}")
```

`LocalSymbolMap.getSymbols()` returns a Java `Iterator`, not iterable — use `while it.hasNext():`. (One of the few places JPype's auto-conversion doesn't help.)

`HighSymbol` subtypes worth distinguishing:
- `HighParam` — a parameter; `sym.getSlot()` gives the 0-indexed position.
- `HighLocal` — a stack local.
- `HighGlobal` — a global variable referenced in this function.
- `HighFunctionShellSymbol` — the function itself.

Detecting decompiler-confused symbols (the classic "this analysis is incomplete" smell):

```python
for sym_name in ["in_", "unaff_", "extraout_"]:
    bad = []
    it = syms.getSymbols()
    while it.hasNext():
        s = it.next()
        if s.getName().startswith(sym_name):
            bad.append(s.getName())
    if bad:
        print(f"{sym_name}* symbols ({len(bad)}): {bad[:8]}")
```

These prefixes mean the decompiler couldn't fully resolve where a value came from — `unaff_*` is a register read of something the function didn't write, `in_*` is an input it couldn't bind to a parameter, `extraout_*` is an extra return value.

## Varnodes

A `Varnode` is one SSA value. The methods that matter:

| Call | Notes |
|---|---|
| `v.isConstant()` | True if it's a literal. `v.getOffset()` gives the value. |
| `v.isRegister()` | True if it represents a CPU register. |
| `v.isAddress()` | True if it's a memory address. |
| `v.isUnique()` | True if it's a decompiler-internal temporary. |
| `v.getAddress()` | The `Address` (for register / memory varnodes). |
| `v.getSize()` | Byte size. |
| `v.getDef()` | The `PcodeOp` that produced this varnode (None for inputs). |
| `v.getDescendants()` | Iterator of `PcodeOp` that consume this varnode. |
| `v.getHigh()` | The `HighVariable` this varnode belongs to (or None). |

The `getDef()` chain is what you walk **backwards** to answer "where did this value come from." The `getDescendants()` chain is what you walk **forwards** to answer "where does this value go."

## PcodeOps

A `PcodeOp` (or `PcodeOpAST` from a `HighFunction`) is one operation. The methods that matter:

| Call | Notes |
|---|---|
| `op.getOpcode()` | A `PcodeOp.*` constant — `COPY`, `LOAD`, `STORE`, `CALL`, `INT_ADD`, `INT_AND`, `INT_ZEXT`, `INT_SEXT`, `CAST`, `MULTIEQUAL`, `PTRSUB`, `PTRADD`, etc. |
| `op.getMnemonic()` | String form of the opcode. Easier for printing. |
| `op.getInputs()` / `op.getInput(i)` / `op.getNumInputs()` | Input varnodes. |
| `op.getOutput()` | Output varnode (or None for `STORE`, `CALL` with no return, etc.). |
| `op.getSeqnum().getTarget()` | The `Address` this op lives at. |
| `op.getBasicIter()` | The `PcodeBlockBasic` containing it. |

Common opcodes you'll match on:

```python
from ghidra.program.model.pcode import PcodeOp

# Direct copy
PcodeOp.COPY

# Memory access
PcodeOp.LOAD     # input(1) is the address, input(0) is the address-space id
PcodeOp.STORE    # input(1) addr, input(2) value

# Calls
PcodeOp.CALL           # direct, input(0) is callee address (a constant varnode)
PcodeOp.CALLIND        # indirect, input(0) is a varnode holding the target
PcodeOp.CALLOTHER      # processor-specific user-op

# Pointer arithmetic (decompiler-synthesised)
PcodeOp.PTRSUB         # struct/array offset
PcodeOp.PTRADD         # array index step

# Phi nodes
PcodeOp.MULTIEQUAL     # SSA join — value depends on which block we came from

# Bit / width manipulation
PcodeOp.INT_ZEXT       # zero-extend
PcodeOp.INT_SEXT       # sign-extend
PcodeOp.CAST           # type cast (no value change)
PcodeOp.INT_AND        # mask
PcodeOp.SUBPIECE       # extract a slice
```

The full set is in `ghidra.program.model.pcode.PcodeOp` — there are ~70 opcodes.

## Backward trace: argument → constant

This pattern shows up everywhere — "what value is passed to argN of this call?"

```python
def trace_to_constant(vn, max_hops=12):
    """Walk a Varnode's def-chain backwards, looking for a constant."""
    seen = set()
    while vn is not None and max_hops > 0:
        if vn.isConstant():
            return vn.getOffset()
        if vn in seen:
            return None      # cycle (phi node loop)
        seen.add(vn)
        defop = vn.getDef()
        if defop is None:
            return None      # function input, no definition in this scope
        op = defop.getOpcode()
        if op in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            vn = defop.getInput(0)            # follow the copy
        elif op == PcodeOp.INT_AND:
            # constant mask? collapse if input(1) is a constant
            a, b = defop.getInput(0), defop.getInput(1)
            if b.isConstant():
                vn = a
            else:
                return None
        elif op == PcodeOp.MULTIEQUAL:
            # SSA phi — only useful if all inputs trace to the same constant
            vals = {trace_to_constant(i, max_hops - 1) for i in defop.getInputs()}
            vals.discard(None)
            return vals.pop() if len(vals) == 1 else None
        else:
            return None
        max_hops -= 1
    return None
```

Walk `hf.getPcodeOps()`, find `CALL` ops, pick the input for the argument slot you care about, and feed it to `trace_to_constant`. Argument inputs to `CALL` start at index 1 (`input(0)` is the callee address).

## Forward trace: where does this value get used

```python
def find_uses(vn, max_hops=4):
    """Collect PcodeOps that consume vn, recursively, up to max_hops."""
    out = []
    frontier = [(vn, 0)]
    while frontier:
        cur, depth = frontier.pop()
        if depth > max_hops: continue
        for op in cur.getDescendants():
            out.append(op)
            if op.getOutput() is not None:
                frontier.append((op.getOutput(), depth + 1))
    return out
```

`getDescendants()` returns an `Iterator<PcodeOp>` and JPype usually makes it iterable; if it doesn't, swap for `while it.hasNext():`.

## ParallelDecompiler: batch-mode

When a script decompiles every function, building one `DecompInterface` per function is wasteful. Ghidra's `ParallelDecompiler` runs decompilation across all CPU cores with a callback per function:

```python
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.decompiler.parallel import (
    ParallelDecompiler, DecompilerCallback, DecompileConfigurer,
)

class Configurer(DecompileConfigurer):
    def configure(self, decompiler):
        opts = DecompileOptions()
        opts.grabFromProgram(currentProgram)
        decompiler.setOptions(opts)
        decompiler.toggleCCode(True)
        decompiler.toggleSyntaxTree(True)
        decompiler.setSimplificationStyle("decompile")

class MyCallback(DecompilerCallback):
    def __init__(self, prog):
        super().__init__(prog, Configurer())
    def process(self, results, monitor):
        if not results.decompileCompleted():
            return None
        hf = results.getHighFunction()
        # ... analyse hf; return a value you want collected, or None ...
        return (results.getFunction().getName(), hf.getNumVarnodes())

cb = MyCallback(currentProgram)
try:
    funcs = list(currentProgram.getFunctionManager().getFunctions(True))
    results = ParallelDecompiler.decompileFunctions(cb, funcs, monitor)
    # `results` is a List of whatever process() returned
    for r in results or []:
        if r: print(r)
finally:
    cb.dispose()
```

`ParallelDecompiler.decompileFunctions` is the right call when you'd otherwise decompile more than ~10 functions in a script. The serial form is fine for a handful.

## `HighFunctionDBUtil`: persist decompiler findings

Renames and retypes done via the Flat API (`func.setName(...)`) go straight to the symbol table. Renames done on a *high* symbol (a decompiler-derived local that doesn't have a database backing yet) need `HighFunctionDBUtil`:

```python
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

# Find the HighSymbol you want to rename
it = hf.getLocalSymbolMap().getSymbols()
while it.hasNext():
    sym = it.next()
    if sym.getName() == "iVar2":
        tx = currentProgram.startTransaction("Rename iVar2")
        try:
            HighFunctionDBUtil.updateDBVariable(
                sym, "loop_counter", None, SourceType.USER_DEFINED)
            currentProgram.endTransaction(tx, True)
        except Exception:
            currentProgram.endTransaction(tx, False)
            raise
        break
```

Pass `None` for the data type to keep the current type and only rename. Pass a `DataType` to change both.

For function signatures, the related helpers are `HighFunctionDBUtil.commitParamsToDatabase(hf, useDataTypes, sourceType)` and `commitReturnToDatabase(hf, sourceType)`. These take everything the decompiler inferred for parameters / return type and write it back permanently — useful after running data-flow analysis that improved signatures.

## Clang AST: the rendered C tree

The C source you get from `res.getDecompiledFunction().getC()` is the rendered form of a `ClangTokenGroup` tree. Walking that tree (`ClangNode`, `ClangStatement`, `ClangToken`) lets you map between source positions and PCode ops:

```python
ccode = res.getCCodeMarkup()    # ClangTokenGroup
# ccode.numChildren(), ccode.Child(i), token.getPcodeOp(), token.getHighVariable()
```

This is niche — most analyses are fine with the string form or pure PCode. Reach for the Clang AST when you need "what's the C statement at offset X" or "which token corresponds to varnode V".

## Pitfalls specific to this layer

- **`HighFunction` is invalidated by `decomp.dispose()`.** Pull everything you need before disposing.
- **`LocalSymbolMap.getSymbols()` is a Java `Iterator`,** not iterable. Use `while it.hasNext():`.
- **`Varnode` equality is reference identity,** not value identity. Two varnodes representing the same SSA value compare unequal if they're separate objects. Use `id(v)` if you need a hashable key, or compare `(v.getAddress(), v.getSize(), v.getDef())`.
- **`MULTIEQUAL` (phi) nodes cycle.** Always track visited varnodes when walking `getDef()` chains.
- **`getDescendants()` only sees ops *inside the same function*.** Cross-function data flow needs you to find the corresponding `Varnode` in the callee's `HighFunction` (typically the parameter at the matching slot).
- **Address-space ids in `LOAD`/`STORE`.** `input(0)` is a constant varnode whose offset is the address-space id, not an address. The actual address is `input(1)`.
- **PCode ops from `hf.getPcodeOps()` are `PcodeOpAST`,** a subclass of `PcodeOp` that also knows its parent basic block (`op.getParent()`). They're returned in address order but the SSA structure is what matters.
