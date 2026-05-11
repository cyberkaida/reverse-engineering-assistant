# Ghidra Flat API cheat-sheet

Reference for the `FlatProgramAPI` + `FlatDecompilerAPI` + `GhidraScript` surface that's pre-bound when `run-script` executes your `code`. Methods listed here are available as bare names (e.g. `toAddr(...)`, `getFunctionAt(...)`) — no import needed.

For the underlying managers (`FunctionManager`, `SymbolTable`, `Listing`, `ReferenceManager`, `Memory`, `DataTypeManager`) reach through `currentProgram.getFunctionManager()` etc. — those have richer APIs when the Flat helpers don't fit.

## Program & memory

| Call | Returns | Notes |
|---|---|---|
| `currentProgram` | `Program` | The program identified by the tool's `programPath` argument. |
| `getMemoryBlock(addr)` / `getMemoryBlock(name)` | `MemoryBlock` or `None` | By address or by section name (`.text`, `.rodata`, …). |
| `currentProgram.getMemory().getBlocks()` | `MemoryBlock[]` | All blocks, in order. |
| `block.getBytes(start, byte[] buf)` | int (count read) | `buf` is a Java `byte[]`; allocate via `jpype.JByte[N]`. |
| `block.getStart()` / `block.getEnd()` / `block.getSize()` | `Address` / long | Bounds. |
| `currentProgram.getImageBase()` | `Address` | For relocatables / address math. |

## Addresses

| Call | Notes |
|---|---|
| `toAddr(0x401000)` / `toAddr("0x401000")` | The primary way to construct an `Address`. |
| `currentAddress` | The current selection's address (often `None` under `run-script`). |
| `addr.add(n)` / `addr.subtract(n)` | Returns a new `Address`. |
| `addr.getOffset()` | `long` (the numeric value). |
| `currentProgram.getAddressFactory().getAddress("0x401000")` | When `toAddr` won't parse. |

## Address sets

When iterating instructions / data / functions, restricting to an `AddressSet` saves a lot of time on large programs and lets you express "only inside this function", "only in `.text`", "only in the .data region between X and Y."

```python
from ghidra.program.model.address import AddressSet

# Whole program (default)
listing.getInstructions(True)

# Restricted to a function body
listing.getInstructions(func.getBody(), True)        # AddressSetView

# Just the .text block
text = currentProgram.getMemory().getBlock(".text")
text_set = AddressSet(text.getStart(), text.getEnd())
listing.getInstructions(text_set, True)

# All executable memory (handy: getExecuteSet picks every block with X permission)
exec_set = currentProgram.getMemory().getExecuteSet()
listing.getInstructions(exec_set, True)
```

Set arithmetic: `set.add(otherSet)`, `set.subtract(otherSet)`, `set.intersect(otherSet)`. `AddressSet(start, end)` builds a single-range set; the union of ranges is built up with `.add()`.

`AddressSetView` is the read-only interface most APIs accept; `AddressSet` is the mutable subclass. `func.getBody()` returns an `AddressSetView` (the function's address ranges, which can be discontiguous for thunks and tail-merged code).

## Functions

| Call | Returns | Notes |
|---|---|---|
| `getFunctionAt(addr)` | `Function` or `None` | Exact entry point. |
| `getFunctionContaining(addr)` | `Function` or `None` | Anywhere inside the body. |
| `getFunctionBefore(addr)` / `getFunctionAfter(addr)` | `Function` | Iteration helpers. |
| `getFirstFunction()` / `getLastFunction()` | `Function` | Start/end. |
| `getFunction("name")` | `Function` or `None` | First match by name; ambiguous in stripped binaries. |
| `getGlobalFunctions("name")` | `List<Function>` | All functions matching name (handles namespaces). |
| `currentProgram.getFunctionManager().getFunctions(True)` | iterable | Forward iteration over all functions. |
| `createFunction(entryAddr, "name")` | `Function` | **Needs transaction.** Won't replace an existing function. |
| `removeFunction(func)` / `removeFunctionAt(addr)` | `bool` | **Needs transaction.** |
| `func.getEntryPoint()` | `Address` | |
| `func.getBody()` | `AddressSetView` | All addresses owned by the function. |
| `func.getParameters()` | `Parameter[]` | |
| `func.getAllVariables()` | `Variable[]` | Locals + params. |
| `func.setName("name", SourceType.USER_DEFINED)` | | **Needs transaction.** Import `SourceType` from `ghidra.program.model.symbol`. |
| `func.setReturnType(dt, SourceType.USER_DEFINED)` | | |

## Symbols & labels

| Call | Returns | Notes |
|---|---|---|
| `getSymbolAt(addr)` | `Symbol` or `None` | Primary symbol. |
| `getSymbolAt(addr, "name")` | `Symbol` | Disambiguates when multiple symbols share an address. |
| `getSymbol("name", namespace)` | `Symbol` or `None` | `None` namespace = global. |
| `getSymbols("name", namespace)` | `List<Symbol>` | All matches. |
| `getSymbolBefore(addr)` / `getSymbolAfter(addr)` | `Symbol` | Linear traversal. |
| `createLabel(addr, "name", makePrimary)` | `Symbol` | **Needs transaction.** |
| `createLabel(addr, "name", namespace, makePrimary)` | `Symbol` | Namespaced. |
| `removeSymbol(addr, "name")` | `bool` | **Needs transaction.** |
| `currentProgram.getSymbolTable().getAllSymbols(True)` | iterable | All symbols, including dynamic. |

`SourceType` import: `from ghidra.program.model.symbol import SourceType` — values: `USER_DEFINED`, `IMPORTED`, `ANALYSIS`, `DEFAULT`.

## Imports, externals & thunks

PE/ELF binaries link to library functions through an indirection: a small "thunk" function in the binary jumps to an external symbol that the loader resolves. So when you look for "callers of `WinExec`", direct xrefs to the external symbol find the thunk, not the real users — you have to walk back through the thunk.

| Call | Returns | Notes |
|---|---|---|
| `currentProgram.getExternalManager()` | `ExternalManager` | Entry point for external libraries / functions. |
| `extMgr.getExternalLibraryNames()` | `String[]` | "KERNEL32.DLL", "ucrtbase.dll", … |
| `extMgr.getExternalLocations(libName)` | `Iterator<ExternalLocation>` | Functions/data imported from one library. |
| `extMgr.getExternalLocation(symbol)` | `ExternalLocation` | The external binding for an external symbol. |
| `currentProgram.getSymbolTable().getExternalSymbols()` | iterable | All external symbols (across libraries). |
| `func.isThunk()` | bool | True if this function is just a jump/trampoline. |
| `func.getThunkedFunction(recurse)` | `Function` | The real underlying function. `recurse=True` chases through chains. |
| `func.getFunctionThunkAddresses()` | `Address[]` | Addresses of thunks pointing at this function (works on both real and external). |
| `func.getCallingFunctions(monitor)` | `Set<Function>` | All functions that call this one — *automatically walks through thunks*. |
| `func.getCalledFunctions(monitor)` | `Set<Function>` | Functions called from this one — likewise transparent to thunks. |

The shortest path to "who calls `WinExec` for real" is: get the `Function` for `WinExec`, call `getCallingFunctions(monitor)`. Ghidra resolves thunks for you. The xrefs-to-symbol approach only works correctly if you then `getThunkedFunction()` and chase callers of each thunk.

## Instructions & data

| Call | Returns | Notes |
|---|---|---|
| `getInstructionAt(addr)` | `Instruction` or `None` | Exact start. |
| `getInstructionContaining(addr)` | `Instruction` or `None` | Anywhere inside. |
| `getInstructionBefore(addr)` / `getInstructionAfter(addr)` | `Instruction` | |
| `getFirstInstruction()` / `getLastInstruction()` | `Instruction` | |
| `getDataAt(addr)` / `getDataContaining(addr)` | `Data` or `None` | |
| `getDataBefore(addr)` / `getDataAfter(addr)` | `Data` | |
| `getUndefinedDataAt(addr)` / `getUndefinedDataBefore(addr)` / `getUndefinedDataAfter(addr)` | `Data` | Find gaps. |
| `createData(addr, dt)` | `Data` | **Needs transaction.** Clears existing. |
| `createByte(addr)` / `createWord(addr)` / `createDWord(addr)` / `createQWord(addr)` | `Data` | Primitive shortcuts. |
| `createAsciiString(addr)` / `createUnicodeString(addr)` | `Data` | |
| `removeData(data)` / `removeDataAt(addr)` | `bool` | **Needs transaction.** |
| `removeInstruction(instr)` / `removeInstructionAt(addr)` | `bool` | **Needs transaction.** |
| `clearListing(addr)` / `clearListing(start, end)` | | **Needs transaction.** Various overloads for code/data/refs/symbols. |
| `disassemble(addr)` | `bool` | Force disassembly. Auto-analysis usually handles this. |
| `instr.getMnemonicString()` / `instr.getOperand(i)` / `instr.getOpObjects(i)` | | Inspect operands. |
| `instr.getFlowType()` | `FlowType` | `isCall()`, `isJump()`, `isFallthrough()`. |
| `data.getValue()` / `data.getBytes()` / `data.getDataType()` | | |

## Data types & structs

Defining a struct and applying it to memory is one of the higher-leverage moves in Ghidra — once a region of bytes is typed, the listing shows fields by name and the decompiler propagates types automatically.

| Call | Returns | Notes |
|---|---|---|
| `currentProgram.getDataTypeManager()` | `DataTypeManager` | Per-program type DB. |
| `dtm.getDataType("/MyCategory/MyStruct")` | `DataType` or `None` | Lookup by path. |
| `dtm.findDataType("MyStruct")` | `DataType` | Lookup without category. |
| `dtm.addDataType(dt, conflictHandler)` | `DataType` | Register a new type. **Needs transaction.** |
| `dtm.getAllDataTypes()` | `Iterator<DataType>` | All types in this program's DB. |
| `BuiltInDataTypeManager.getDataTypeManager()` | `DataTypeManager` | The cross-program built-in types. |
| `DataTypeParserUtil.parseDataTypeObjectFromString(dtm, "char *")` | `DataType` | ReVa's util — handles strings like `int[10]`, `MyStruct *`, `void`. Already in this codebase; import from `reva.util`. |
| `StructureDataType(name, size)` | new `Structure` | Build from code. `size=0` = auto-grow. |
| `struct.add(componentType, "fieldName", "comment")` | | Append a field. **Needs transaction** once the struct is in a DTM. |
| `struct.insertAtOffset(off, type, len, "name", "comment")` | | Place a field at a specific offset. |
| `createData(addr, dt)` | `Data` | Apply a type at an address. **Needs transaction.** Clears existing data. |

Building a struct from scratch:

```python
from ghidra.program.model.data import StructureDataType, IntegerDataType, PointerDataType, CharDataType
from ghidra.program.model.data import DataTypeConflictHandler

dtm = currentProgram.getDataTypeManager()
s = StructureDataType("MyHeader", 0)        # 0 = auto-grow
s.add(IntegerDataType(),  "magic",   "Signature")
s.add(IntegerDataType(),  "version", None)
s.add(PointerDataType(CharDataType()), "name", None)

tx = currentProgram.startTransaction("Define MyHeader")
try:
    s = dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER)
    createData(toAddr(0x404000), s)
    currentProgram.endTransaction(tx, True)
except Exception:
    currentProgram.endTransaction(tx, False)
    raise
```

For composite types: `StructureDataType`, `UnionDataType`, `EnumDataType(name, size)` (then `.add("CONST_NAME", value)`), `ArrayDataType(elementType, count, elementSize)`, `TypedefDataType("Alias", underlying)`, `FunctionDefinitionDataType("name")`.

When you have a type string from the user (`"int"`, `"MyStruct *"`, `"char[16]"`), use `DataTypeParserUtil` — parsing the string into the right `DataType` by hand is fiddly:

```python
from reva.util import DataTypeParserUtil
dt = DataTypeParserUtil.parseDataTypeObjectFromString(dtm, "MyHeader *")
```

`getDataTypeManager()` returns the program's type DB; type IDs and references are stable within that DB but not across programs. Imported headers go into category paths (`/MyHeader.h/MyStruct`); user-defined types default to `/`.

## References / xrefs

| Call | Returns | Notes |
|---|---|---|
| `getReferencesTo(addr)` | `Reference[]` | All xrefs pointing at `addr`. Large on hot functions. |
| `getReferencesFrom(addr)` | `Reference[]` | All refs originating at `addr`. Check `getOperandIndex()` to disambiguate per-operand. |
| `getReference(instr_or_data, toAddr)` | `Reference` or `None` | Specific edge. |
| `createMemoryReference(instr, opIndex, toAddr, refType, sourceType)` | `Reference` | **Needs transaction.** |
| `removeReference(ref)` | | **Needs transaction.** |
| `ref.getFromAddress()` / `ref.getToAddress()` / `ref.getReferenceType()` | | |

`RefType` import: `from ghidra.program.model.symbol import RefType` — `READ`, `WRITE`, `DATA`, `COMPUTED_CALL`, `UNCONDITIONAL_CALL`, `UNCONDITIONAL_JUMP`, `FALL_THROUGH`, …

## Comments

| Call | Notes |
|---|---|
| `setPlateComment(addr, "text")` | Block above the listing item. |
| `setPreComment(addr, "text")` | |
| `setPostComment(addr, "text")` | |
| `setEOLComment(addr, "text")` | End-of-line. |
| `setRepeatableComment(addr, "text")` | Propagates to all xref sites. |
| `getPlateComment(addr)` / `getPreComment(addr)` / `getPostComment(addr)` / `getEOLComment(addr)` / `getRepeatableComment(addr)` | Returns `str` or `None`. |

All setters need a transaction. Pass `None` (or `""`) to clear.

## Bookmarks

| Call | Notes |
|---|---|
| `createBookmark(addr, "Category", "note")` | `Bookmark`. **Needs transaction.** |
| `currentProgram.getBookmarkManager().getBookmarksIterator(category)` | Iterate by category. |
| `removeBookmark(bookmark)` | **Needs transaction.** |

## Search

| Call | Notes |
|---|---|
| `find(startAddr, byteValue)` | First match address, or `None`. |
| `find(startAddr, byte[])` | Sequence search. |
| `findBytes(startAddr, "FF ?? FF", limit, forward)` | Regex-ish wildcards (`??` = any byte). |
| `findBytes(addressSet, "...", limit)` | Restricted to a set. |
| `find("string")` | Substring search in raw bytes. |
| `findStrings(addressSet, minLength, alignment, requireNull, allCharSets)` | Auto-detect strings; returns `FoundString` iterator. |

## Decompiler

`FlatDecompilerAPI` is high-level and convenient; for batch work or fine control, drop to `DecompInterface` directly.

```python
# High-level (one-off, simple)
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
flat = FlatDecompilerAPI()           # uses currentProgram via state
flat.initialize()
try:
    c_source = flat.decompile(func, 30)   # 30-sec timeout per function
finally:
    flat.dispose()

# Low-level (batch, preferred when decompiling many functions)
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
try:
    for func in currentProgram.getFunctionManager().getFunctions(True):
        if monitor.isCancelled(): break
        res = decomp.decompileFunction(func, 30, monitor)
        if res.decompileCompleted():
            c_source = res.getDecompiledFunction().getC()
            high_func = res.getHighFunction()
            # ... process ...
finally:
    decomp.dispose()
```

`dispose()` is mandatory — it tears down a native subprocess. Skipping it leaks.

For variable renames that persist in the database, use `HighFunctionDBUtil.updateDBVariable(highSymbol, name, dt, SourceType.USER_DEFINED)` from inside a transaction (`from ghidra.program.model.pcode import HighFunctionDBUtil`).

## User interaction

`askString`, `askFile`, `askYesNo`, `popup`, `println`, etc. exist as `GhidraScript` globals but are useless under `run-script` (no human at the keyboard — they'll return defaults, throw, or hang). Use `print()` and hard-coded values from the tool's `code` argument instead.

## Monitor (timeout cooperation)

| Call | Notes |
|---|---|
| `monitor.isCancelled()` | Soft check; safe in cleanup paths. |
| `monitor.checkCancelled()` | Throws `CancelledException` if cancelled. Let it propagate. |
| `monitor.setMessage("text")` | UI feedback (visible in GUI mode). |
| `monitor.setProgress(n)` / `monitor.setMaximum(n)` | Progress bar updates. |

Forgetting to check the monitor inside long loops is the #1 reason a `run-script` call ignores its timeout. Add a check at the top of any per-function/per-instruction loop.

## Transaction pattern

```python
tx = currentProgram.startTransaction("Rename trivial wrappers")
try:
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if monitor.isCancelled(): break
        if f.getBody().getNumAddresses() < 8:
            f.setName(f"wrapper_{f.getEntryPoint()}", SourceType.USER_DEFINED)
    currentProgram.endTransaction(tx, True)
except Exception:
    currentProgram.endTransaction(tx, False)
    raise
```

Always pair `start` with `end`. Commit on success (`True`); roll back on failure (`False`). Don't nest transactions on the same program — `pyghidra.analyze()` and some auto-analyzers manage their own and dislike re-entry.
