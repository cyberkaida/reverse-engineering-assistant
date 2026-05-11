# `run-script` recipes

Copy-pasteable inline `code` for the well-trodden tasks. Each recipe is a complete script body — pass it as `run-script(programPath=..., code=...)`. They assume the contract documented in SKILL.md (globals bound, no auto-transaction, monitor cancellation cooperative).

## Iterate functions with a predicate

```python
import json
out = []
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    if monitor.isCancelled(): break
    body = f.getBody()
    if body.getNumAddresses() > 4096:
        out.append({
            "addr": str(f.getEntryPoint()),
            "name": f.getName(),
            "size": body.getNumAddresses(),
        })
print(json.dumps(out, indent=2))
```

## Find xrefs to a symbol with caller context

```python
import json
sym = getSymbol("interesting_func", None)   # None = global namespace
if sym is None:
    print(json.dumps({"error": "symbol not found"}))
else:
    out = []
    for ref in getReferencesTo(sym.getAddress()):
        if monitor.isCancelled(): break
        from_addr = ref.getFromAddress()
        caller = getFunctionContaining(from_addr)
        out.append({
            "from": str(from_addr),
            "type": str(ref.getReferenceType()),
            "in_function": caller.getName() if caller else None,
        })
    print(json.dumps(out, indent=2))
```

## Batch rename functions matching a regex

```python
import re
from ghidra.program.model.symbol import SourceType

pattern = re.compile(r"^FUN_(00)?40([0-9a-f]{4})$")
template = "candidate_{}"

renamed = 0
tx = currentProgram.startTransaction("Batch rename matching FUN_ pattern")
try:
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if monitor.isCancelled(): break
        m = pattern.match(f.getName())
        if m:
            f.setName(template.format(m.group(2)), SourceType.USER_DEFINED)
            renamed += 1
    currentProgram.endTransaction(tx, True)
except Exception:
    currentProgram.endTransaction(tx, False)
    raise
print(f"renamed: {renamed}")
```

## Find callers of an imported symbol (handles thunks)

PE/ELF binaries call imports through small thunk functions. The naive xrefs-to-symbol pattern finds the thunk, not the real users. `Function.getCallingFunctions(monitor)` walks back through thunks automatically — use it instead.

```python
import json
target_name = "WinExec"

# 1. Find the external function. Externals live in the symbol table with
#    isExternal()=True. The Function object for an external is what
#    getCallingFunctions traverses thunks against.
fm = currentProgram.getFunctionManager()
externals = [f for f in fm.getExternalFunctions() if f.getName() == target_name]
if not externals:
    print(json.dumps({"error": f"no external function {target_name}"})); raise SystemExit

callers = set()
for ext in externals:
    # getCallingFunctions chases thunks automatically — direct from external
    # to the real caller, skipping the trampoline that lives in .text.
    for c in ext.getCallingFunctions(monitor):
        if monitor.isCancelled(): break
        callers.add((str(c.getEntryPoint()), c.getName(), c.isThunk()))

# If you want both the thunk wrappers AND the real callers, also look at
# functions whose body calls a thunk pointing at the external:
for ext in externals:
    for thunk_addr in ext.getFunctionThunkAddresses() or []:
        thunk = fm.getFunctionAt(thunk_addr)
        if thunk is None: continue
        for c in thunk.getCallingFunctions(monitor):
            callers.add((str(c.getEntryPoint()), c.getName(), c.isThunk()))

out = [{"addr": a, "name": n, "is_thunk": t} for a, n, t in sorted(callers)]
print(json.dumps(out, indent=2))
```

`getCallingFunctions` returns a `Set<Function>`; it skips the thunk indirection so the result is the *real* user code, not the trampoline. `func.isThunk()` lets you flag thunks if you want them treated differently. Note that `currentProgram.getFunctionManager().getExternalFunctions()` is the easy way to enumerate imports — `SymbolTable.getExternalSymbols()` includes data imports too.

## Decompile-and-grep

```python
import json
import re
from ghidra.app.decompiler import DecompInterface

needle = re.compile(r"\b(?:strcpy|strcat|sprintf|gets)\s*\(")
hits = []

decomp = DecompInterface()
decomp.openProgram(currentProgram)
try:
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if monitor.isCancelled(): break
        res = decomp.decompileFunction(f, 20, monitor)
        if not res.decompileCompleted():
            continue
        c = res.getDecompiledFunction().getC()
        for m in needle.finditer(c):
            hits.append({
                "addr": str(f.getEntryPoint()),
                "name": f.getName(),
                "match": m.group(0),
            })
            break   # one hit per function is enough
finally:
    decomp.dispose()

print(json.dumps(hits, indent=2))
```

This decompiles every function — expensive. Filter first (e.g. by name pattern, or by whether the function references known-bad imports) before decompiling, when you can.

## Dump strings with their referencers

```python
import json
from ghidra.program.util import DefinedDataIterator

out = []
for data in DefinedDataIterator.definedStrings(currentProgram):
    if monitor.isCancelled(): break
    addr = data.getAddress()
    value = data.getValue()
    refs = []
    for r in getReferencesTo(addr):
        caller = getFunctionContaining(r.getFromAddress())
        refs.append({
            "from": str(r.getFromAddress()),
            "in": caller.getName() if caller else None,
        })
    if refs:   # skip orphan strings
        out.append({"addr": str(addr), "value": str(value), "refs": refs})

print(json.dumps(out, indent=2))
```

## Walk the call graph from a root function

```python
import json
from collections import deque

root = getFunction("main")
if root is None:
    print(json.dumps({"error": "no main"}))
else:
    visited = set()
    edges = []
    q = deque([root])
    while q:
        if monitor.isCancelled(): break
        f = q.popleft()
        if f.getEntryPoint() in visited:
            continue
        visited.add(f.getEntryPoint())
        for callee in f.getCalledFunctions(monitor):
            edges.append({
                "from": f.getName(),
                "to": callee.getName(),
                "to_addr": str(callee.getEntryPoint()),
            })
            q.append(callee)
    print(json.dumps({"functions": len(visited), "edges": edges[:200]}, indent=2))
```

## Find functions that reference a specific data address

```python
import json
target = toAddr(0x404020)
out = []
for ref in getReferencesTo(target):
    if monitor.isCancelled(): break
    caller = getFunctionContaining(ref.getFromAddress())
    out.append({
        "from": str(ref.getFromAddress()),
        "in_function": caller.getName() if caller else None,
        "type": str(ref.getReferenceType()),
    })
print(json.dumps(out, indent=2))
```

## Set a plate comment + EOL comment in one transaction

```python
tx = currentProgram.startTransaction("Annotate suspicious calls")
try:
    sites = [(toAddr(0x401234), "calls VirtualAlloc with RWX"),
             (toAddr(0x401290), "loop body — copies shellcode into RWX page")]
    for addr, note in sites:
        setEOLComment(addr, note)
    setPlateComment(toAddr(0x401200), "suspected shellcode loader")
    currentProgram.endTransaction(tx, True)
except Exception:
    currentProgram.endTransaction(tx, False)
    raise
print("done")
```

## Read raw bytes from `.text`

```python
import jpype
block = currentProgram.getMemory().getBlock(".text")
buf = jpype.JByte[64]
block.getBytes(block.getStart(), buf)
print(" ".join(f"{b & 0xff:02x}" for b in buf))
```

## Iterate every instruction in a function

```python
f = getFunctionContaining(toAddr(0x401000))
listing = currentProgram.getListing()
for instr in listing.getInstructions(f.getBody(), True):
    if monitor.isCancelled(): break
    print(f"{instr.getAddress()}  {instr}")
```

## Quick "is this binary stripped?" check

```python
import json
fm = currentProgram.getFunctionManager()
total = 0; named = 0
for f in fm.getFunctions(True):
    if monitor.isCancelled(): break
    total += 1
    n = f.getName()
    if not (n.startswith("FUN_") or n.startswith("thunk_FUN_")):
        named += 1
ratio = (named / total) if total else 0
print(json.dumps({"total": total, "named": named, "ratio": round(ratio, 3),
                  "verdict": "stripped" if ratio < 0.05 else "has-symbols"}))
```

## Print pagination-friendly tabular output

```python
out = []
for f in currentProgram.getFunctionManager().getFunctions(True):
    if monitor.isCancelled(): break
    out.append(f"{str(f.getEntryPoint()):>12}  {f.getBody().getNumAddresses():>6}  {f.getName()}")
print("\n".join(out[:500]))    # cap before printing to stay under output limit
if len(out) > 500:
    print(f"... ({len(out) - 500} more truncated)")
```

The output cap is per-stream (default 64K chars). If you have a lot of rows, truncate explicitly with a marker rather than letting the cap silently cut you off.

## Trace the constant passed to argN of every call to `target_func`

This is the canonical PCode data-flow trick — given a callee, find every callsite, and for each callsite figure out which constant was passed as the Nth argument. The use cases are endless: which file path is opened, which permission flag is requested, which crypto algorithm id is selected. See `decompiler-pcode.md` for the underlying APIs.

```python
import json
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp

target_name = "WinExec"          # the callee we care about
arg_slot = 0                     # 0-indexed argument

# Find the function (or external symbol) we're tracing into
target = getFunction(target_name)
target_addr = target.getEntryPoint() if target else None
if target_addr is None:
    # try external symbol
    for s in currentProgram.getSymbolTable().getExternalSymbols():
        if s.getName() == target_name:
            target_addr = s.getAddress(); break

if target_addr is None:
    print(json.dumps({"error": f"no symbol {target_name}"})); raise SystemExit

# Set of caller functions to decompile
callers = set()
for ref in getReferencesTo(target_addr):
    f = getFunctionContaining(ref.getFromAddress())
    if f: callers.add(f)

def trace_const(vn, depth=10):
    seen = set()
    while vn is not None and depth > 0:
        if vn.isConstant(): return vn.getOffset()
        key = id(vn)
        if key in seen: return None
        seen.add(key)
        d = vn.getDef()
        if d is None: return None
        op = d.getOpcode()
        if op in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            vn = d.getInput(0)
        else:
            return None
        depth -= 1
    return None

decomp = DecompInterface()
decomp.openProgram(currentProgram)
hits = []
try:
    for f in callers:
        if monitor.isCancelled(): break
        res = decomp.decompileFunction(f, 30, monitor)
        if not res.decompileCompleted(): continue
        hf = res.getHighFunction()
        ops = hf.getPcodeOps()
        while ops.hasNext():
            op = ops.next()
            if op.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND): continue
            # input(0) = callee addr; arguments are input(1..)
            inputs = op.getInputs()
            if len(inputs) <= arg_slot + 1: continue
            # only callsites of the target
            callee_vn = inputs[0]
            if not (callee_vn.isAddress() and callee_vn.getAddress() == target_addr): continue
            const = trace_const(inputs[arg_slot + 1])
            hits.append({
                "in_function": f.getName(),
                "call_site": str(op.getSeqnum().getTarget()),
                "arg_value": hex(const) if const is not None else None,
            })
finally:
    decomp.dispose()
print(json.dumps(hits, indent=2))
```

## Register touches per function

Lightweight read-only pass — for each function, list every register read or written. Useful for finding "this function clobbers RBX" or "this function reads from RDI without setting it" anomalies.

```python
import json
from ghidra.program.model.lang import Register

out = []
listing = currentProgram.getListing()
for f in currentProgram.getFunctionManager().getFunctions(True):
    if monitor.isCancelled(): break
    reads, writes = set(), set()
    for ins in listing.getInstructions(f.getBody(), True):
        for r in ins.getInputObjects():
            if isinstance(r, Register): reads.add(r.getName())
        for r in ins.getResultObjects():
            if isinstance(r, Register): writes.add(r.getName())
    # interesting cases: read-only registers (read but never written)
    read_only = sorted(reads - writes)
    if read_only:
        out.append({
            "addr": str(f.getEntryPoint()),
            "name": f.getName(),
            "read_only_regs": read_only,
        })
print(json.dumps(out[:50], indent=2))
```

## Parallel decompilation across the whole program

Use this when you'd otherwise decompile more than ~10 functions. `ParallelDecompiler` runs decompilation across all CPU cores; the `process` callback runs once per function on the worker.

```python
import json
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.decompiler.parallel import (
    ParallelDecompiler, DecompilerCallback, DecompileConfigurer,
)

class Configurer(DecompileConfigurer):
    def configure(self, decompiler):
        opts = DecompileOptions()
        opts.grabFromProgram(currentProgram)
        decompiler.setOptions(opts)
        decompiler.toggleSyntaxTree(True)
        decompiler.setSimplificationStyle("decompile")

class Stats(DecompilerCallback):
    def __init__(self, prog):
        super().__init__(prog, Configurer())
    def process(self, results, monitor):
        if not results.decompileCompleted(): return None
        hf = results.getHighFunction()
        # Pick anything you want collected — keep it small (returned across processes).
        return {
            "name": results.getFunction().getName(),
            "varnodes": hf.getNumVarnodes(),
            "blocks": hf.getBasicBlocks().size(),
        }

funcs = list(currentProgram.getFunctionManager().getFunctions(True))
cb = Stats(currentProgram)
try:
    results = ParallelDecompiler.decompileFunctions(cb, funcs, monitor)
finally:
    cb.dispose()

# results is a List<Object> in caller order; filter Nones and print
out = [r for r in (results or []) if r is not None]
print(json.dumps(out[:50], indent=2))
print(f"total: {len(out)} successful decompilations")
```

The `process()` return value is collected into a Java `List` you can read after `decompileFunctions` returns. Keep returned values small — they cross the worker boundary.

## Emulate a function to recover an obfuscated string

Ghidra's `EmulatorHelper` runs PCode in-process. The classic use is "this function decrypts a string at runtime; emulate it and read the result out of memory." It's simpler than `JitPcodeEmulator` and right for most one-shot tasks.

```python
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolType

func = getFunction("decrypt_string")
if func is None: raise SystemExit("no decrypt_string")

emu = EmulatorHelper(currentProgram)
try:
    # Pick a return address that doesn't exist in the program — when the
    # emulator's PC lands there, we know the function returned.
    ret_addr = toAddr(0xDEAD0000)

    # x86-64 calling convention example: arg in RDI, stack alignment
    stack_top = 0x70000000
    emu.writeRegister(emu.getStackPointerRegister(), stack_top)
    # Push the fake return address
    emu.writeMemoryValue(toAddr(stack_top - 8), 8, ret_addr.getOffset())
    emu.writeRegister(emu.getStackPointerRegister(), stack_top - 8)

    # Arg 1 in RDI — pointer to a 64-byte buffer in some unused memory
    buf_addr = 0x20000000
    emu.writeRegister("RDI", buf_addr)

    # Set PC and run until we hit the fake return address
    emu.setBreakpoint(ret_addr)
    if not emu.run(func.getEntryPoint(), None, monitor):
        print("emulation stopped early:", emu.getLastError())
    else:
        data = emu.readMemory(toAddr(buf_addr), 64)
        # data is a Java byte[]; convert to Python bytes (signed → unsigned)
        decoded = bytes(b & 0xff for b in data)
        # strip trailing zero bytes
        decoded = decoded.rstrip(b"\x00")
        print(decoded.decode("utf-8", errors="replace"))
finally:
    emu.dispose()
```

Notes:
- `EmulatorHelper` doesn't auto-set up the stack or arguments — that's on you. Calling convention matters: x86-64 SysV puts args in RDI/RSI/RDX/RCX/R8/R9; Windows x64 uses RCX/RDX/R8/R9; ARM64 uses X0–X7.
- Set a breakpoint at an unmapped address you control (e.g. `0xDEAD0000`) and push it as the return address so `emu.run()` stops there cleanly.
- For functions that call external libraries (malloc, printf, …), the emulator will dive into stubs and likely fail. Either hook those addresses with `emu.setBreakpoint(...)` and emulate the effect yourself, or stay within self-contained leaf functions.
- For long emulations, check `monitor.isCancelled()` inside a loop that single-steps with `emu.step(monitor)` instead of using `emu.run()`.

## Recursive xrefs: every string reachable from a function

Walks the call graph forward from a function, collecting every string referenced anywhere in the reachable set. Useful for "what data does this code path touch?"

```python
import json
from ghidra.program.model.listing import CodeUnit

root = getFunction("main")
if root is None: raise SystemExit("no main")

visited = set()
strings = []

def visit(f, depth=0):
    key = f.getEntryPoint()
    if key in visited or monitor.isCancelled(): return
    visited.add(key)
    # Strings referenced from this function's body
    for ins in currentProgram.getListing().getInstructions(f.getBody(), True):
        for ref in ins.getReferencesFrom():
            target = ref.getToAddress()
            data = getDataAt(target)
            if data and data.hasStringValue():
                strings.append({
                    "in_function": f.getName(),
                    "addr": str(target),
                    "value": str(data.getValue()),
                })
    # Recurse into callees
    for callee in f.getCalledFunctions(monitor):
        visit(callee, depth + 1)

visit(root)
print(json.dumps({"reachable_functions": len(visited),
                  "string_refs": strings[:100],
                  "truncated": len(strings) > 100}, indent=2))
```

`Function.getCalledFunctions(monitor)` and `getCallingFunctions(monitor)` are the easy way to traverse the call graph — they handle thunks and indirect resolution that walking xrefs manually wouldn't.

## Define a struct and apply it to memory

Higher-leverage than renaming: once a region of bytes is typed, the listing shows named fields and the decompiler propagates types through every consumer.

```python
from ghidra.program.model.data import (
    StructureDataType, IntegerDataType, PointerDataType, CharDataType,
    DataTypeConflictHandler,
)

dtm = currentProgram.getDataTypeManager()

# Build a struct from scratch (0 = auto-grow as fields are added)
hdr = StructureDataType("WidgetHeader", 0)
hdr.add(IntegerDataType(),                "magic",   "Signature 0xDEADBEEF")
hdr.add(IntegerDataType(),                "version", None)
hdr.add(IntegerDataType(),                "flags",   None)
hdr.add(PointerDataType(CharDataType()),  "name",    "UTF-8, NUL-terminated")

tx = currentProgram.startTransaction("Define + apply WidgetHeader")
try:
    hdr = dtm.addDataType(hdr, DataTypeConflictHandler.DEFAULT_HANDLER)
    # Apply at known addresses
    for addr_int in [0x404000, 0x404100, 0x404200]:
        data = createData(toAddr(addr_int), hdr)
    currentProgram.endTransaction(tx, True)
except Exception:
    currentProgram.endTransaction(tx, False)
    raise

# Walk the fields you just defined
data = getDataAt(toAddr(0x404000))
for i in range(data.getNumComponents()):
    comp = data.getComponent(i)
    print(f"+{comp.getOffset():04x}  {comp.getFieldName()} = {comp.getValue()}")
```

`createData()` clears whatever was at the address first, so this is safe over previously-defined data — but mid-instruction it'll cause disassembly trouble. Apply struct types to data regions, not into code. For an existing type by path, look it up: `dtm.getDataType("/some_header.h/WidgetHeader")`. For a free-form type string from a user, use `DataTypeParserUtil.parseDataTypeObjectFromString(dtm, "WidgetHeader *")` (from ReVa's `reva.util`).

## Set a function signature programmatically

When data-flow analysis tells you a function's signature is wrong — say it's really `int decrypt(char *out, int out_len, const char *in)` — commit the corrected signature so the decompiler propagates the new types everywhere it's called.

```python
from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl, Function
from ghidra.program.model.data import (
    IntegerDataType, PointerDataType, CharDataType, VoidDataType,
)
from ghidra.program.model.symbol import SourceType

func = getFunction("FUN_00401200")
if func is None: raise SystemExit("no such function")

# Build the parameter list
prog = currentProgram
params = [
    ParameterImpl("out",     PointerDataType(CharDataType()),    prog),
    ParameterImpl("out_len", IntegerDataType(),                  prog),
    ParameterImpl("in",      PointerDataType(CharDataType()),    prog),
]
ret = ReturnParameterImpl(IntegerDataType(), prog)

tx = prog.startTransaction("Set decrypt() signature")
try:
    func.updateFunction(
        None,                                       # calling convention (None = unchanged)
        ret,                                        # new return param
        params,                                     # new parameter list
        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
        True,                                       # force=true (override existing)
        SourceType.USER_DEFINED,
    )
    func.setName("decrypt", SourceType.USER_DEFINED)
    prog.endTransaction(tx, True)
except Exception:
    prog.endTransaction(tx, False)
    raise

print(f"signature: {func.getSignature()}")
```

The `FunctionUpdateType` enum controls how Ghidra computes storage:
- `DYNAMIC_STORAGE_ALL_PARAMS` — Ghidra picks registers/stack slots based on calling convention. Almost always what you want.
- `CUSTOM_STORAGE` — you also supply explicit storage per parameter (needed for non-standard ABIs).

Pass `"__stdcall"`, `"__fastcall"`, `"__cdecl"`, etc. as the first argument to change the calling convention. Pass `None` to keep the current one.

For commits driven by the *decompiler's* inferred signature (after data-flow analysis improves things), the related shortcut is `HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.USER_DEFINED)` — it takes whatever the decompiler currently shows and writes it back without you having to spell out each `ParameterImpl`.

## Persist a decompiler-derived rename

When the decompiler shows a local named `iVar3` and you want to commit a better name, that's a `HighSymbol` rename, not a plain symbol rename. Use `HighFunctionDBUtil`:

```python
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

func = getFunctionAt(toAddr(0x401000))
target_name = "iVar3"          # the decompiler name we want to rename
new_name = "loop_counter"

decomp = DecompInterface()
decomp.openProgram(currentProgram)
try:
    res = decomp.decompileFunction(func, 30, monitor)
    if not res.decompileCompleted(): raise SystemExit("decompile failed")
    hf = res.getHighFunction()
    it = hf.getLocalSymbolMap().getSymbols()
    target = None
    while it.hasNext():
        s = it.next()
        if s.getName() == target_name:
            target = s; break
    if target is None: raise SystemExit(f"no {target_name}")
    tx = currentProgram.startTransaction(f"Rename {target_name} -> {new_name}")
    try:
        HighFunctionDBUtil.updateDBVariable(target, new_name, None, SourceType.USER_DEFINED)
        currentProgram.endTransaction(tx, True)
    except Exception:
        currentProgram.endTransaction(tx, False); raise
finally:
    decomp.dispose()
print(f"renamed {target_name} -> {new_name} in {func.getName()}")
```

Pass a `DataType` instead of `None` to retype at the same time. For full signature commits (after data-flow analysis improves parameters), use `HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.USER_DEFINED)`.
