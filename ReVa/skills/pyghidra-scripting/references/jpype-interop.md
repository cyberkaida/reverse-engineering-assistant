# JPype / Python ↔ Java interop notes

PyGhidra exposes Ghidra's Java API to CPython via JPype. Most of the time it Just Works — Java getters look like Python properties, Java iterables look iterable, `str` ↔ `String` is transparent. The notes below are the edge cases that bite when they bite.

## Importing Ghidra classes inside `run-script`

The JVM is already up when your `run-script` code runs, so you can import Ghidra packages directly at the top of the script:

```python
from ghidra.program.model.symbol import SourceType, RefType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.pcode import HighFunctionDBUtil
from java.util import HashSet, ArrayList
```

No `pyghidra.start()` is needed — that's already happened. Don't include it; it's a no-op at best and noise at worst.

## Getter ↔ property

JPype exposes Java `getFoo()` / `setFoo(v)` as a `foo` property *and* keeps the explicit form. Both work:

```python
func.name              # → calls getName()
func.getName()         # equivalent
func.name = "decoded"  # → calls setName("decoded", SourceType.USER_DEFINED)? NO — see below
```

The property form is only available for single-arg setters. `Function.setName(String, SourceType)` takes two args, so `func.name = "x"` doesn't compile — use `func.setName("x", SourceType.USER_DEFINED)` explicitly. When in doubt, use the explicit form; it never surprises.

## Java arrays

Several Ghidra methods need a Java array — typically a `byte[]` buffer:

```python
import jpype

# Allocate a 16-byte Java byte[]
buf = jpype.JByte[16]

block = currentProgram.getMemory().getBlock(".text")
block.getBytes(block.getStart(), buf)   # fills in-place
```

Going the other way (Python bytes → Java byte[]) is automatic for parameters that won't be mutated. If you hit "no matching overload," wrap explicitly:

```python
my_bytes = jpype.JArray(jpype.JByte)(b"\x00\x01\x02")
```

Other element types: `jpype.JInt[8]`, `jpype.JLong[4]`, `jpype.JChar[16]`. Multi-dimensional: `jpype.JInt[3][3]`.

## Java `byte` is signed

`byte` in Java is `-128..127`. When you read from a `byte[]`, negative values come back:

```python
for b in buf:
    print(hex(b & 0xff))   # mask to 0..255 for display
```

If you want a Python `bytes` object, the safest conversion is:

```python
data = bytes(b & 0xff for b in buf)
```

Don't trust `bytes(buf)` to do the right thing on all JPype versions.

## Iterators

Most Ghidra iterators are Python-iterable thanks to JPype's automatic conversion:

```python
for func in currentProgram.getFunctionManager().getFunctions(True):
    ...

for block in currentProgram.getMemory().getBlocks():
    ...
```

A few aren't — historically the `SymbolIterator` from some accessors and the older `ReferenceIterator` were `Iterator`-only. When `for x in it:` silently yields nothing, fall back:

```python
it = some_call_returning_iterator()
while it.hasNext():
    item = it.next()
    ...
```

When uncertain, `while hasNext()` always works. `Iterable` collections (`getAllVariables()`, `getReferencesTo()`, etc. that return `[]` or `List`) are iterable directly.

## Java collections

`java.util.List`, `Set`, `Map` are iterable and indexable like their Python equivalents thanks to JPype customisations:

```python
from java.util import ArrayList
xs = ArrayList()
xs.add("a"); xs.add("b")
print(xs[0])           # "a"
print(list(xs))        # ['a', 'b']
print(len(xs))         # 2
```

For dict-like access, `Map` supports both `m.get(k)` (Java) and `m[k]` (Python). Iteration yields keys.

## Overload resolution

JPype picks the best matching overload based on Python types. Ambiguous cases (e.g., passing `None` where the parameter is `Object` and there's another `String` overload) can resolve unexpectedly. Force a specific type with a cast:

```python
import jpype
from java.lang import String
flat.something(jpype.JObject(None, String))   # explicit null String
```

For numeric args, `int` may match either `int` or `long` overloads; if you hit "ambiguous," wrap with `jpype.JInt(x)` or `jpype.JLong(x)`.

## Exceptions

Java exceptions surface as Python exceptions inheriting from `jpype.JException`. Catch them by Java class:

```python
from ghidra.util.exception import CancelledException

try:
    monitor.checkCancelled()
    big_work()
except CancelledException:
    print("user cancelled")
```

`Exception` from `java.lang.Exception` doesn't catch *every* Java exception (some inherit `Throwable` directly). For broadest catch, use `jpype.JException` or just `BaseException` — but only for cleanup, never as control flow.

## `print()` and stdout

In `run-script`, `print()` is rerouted to the captured stdout writer. Anything you `print` shows up in the result's `stdout` field, capped at the configured output limit. `sys.stdout.write(...)` works too; `logging` doesn't unless you configure a handler explicitly — usually not worth it.

For binary output back to the caller, base64-encode and print:

```python
import base64
print(base64.b64encode(bytes(b & 0xff for b in buf)).decode())
```

## Package-name collisions

When a Java package name collides with a Python stdlib module (the canonical example: `pdb` is both Python's debugger and Ghidra's PDB importer), the Java side is available with a trailing underscore — `import pdb_` to get Ghidra's. Rare in practice.

## Type stubs for editor autocomplete

When *authoring* scripts in an editor (rather than letting the LLM emit code blind), install Ghidra's type stubs to get full IDE autocomplete:

```
pip install ghidra-stubs==<your-ghidra-version>
```

Then in the script, gate the import so it doesn't run at script execution:

```python
import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *      # currentProgram, toAddr, monitor, ...
    from ghidra.program.model.listing import Program, Function
```

`TYPE_CHECKING` is `False` at runtime so the import is never executed (no JVM bootstrap needed at import time). At type-check time it's `True` and your editor sees all the symbols.

This matters for human-written scripts; for the LLM emitting `run-script` code, skip it — the globals are already bound and you don't get autocomplete benefit from a string.

## `state` and `currentHighlight` etc.

The PyGhidra GhidraScript runtime binds these globals:

| Global | What it is |
|---|---|
| `currentProgram` | `Program` — the program identified by `programPath` |
| `currentAddress` | `Address` or `None` — usually `None` under `run-script` |
| `currentSelection` | `ProgramSelection` or `None` — usually `None` |
| `currentHighlight` | `ProgramSelection` or `None` — usually `None` |
| `monitor` | `TaskMonitor` — your cancellation/timeout signal |
| `state` | `GhidraState` — full script execution context |
| `__this__` / `this` | the underlying `GhidraScript` instance |

Under `run-script`, `currentAddress` / `currentSelection` / `currentHighlight` are almost always `None` because there's no human cursor. Don't write logic that depends on them — take the address you want as a tool argument and use `toAddr(...)` instead. (`run-script` itself doesn't have an `address` arg, so this typically means hard-coding addresses into the inline `code`, or passing them through to a *saved* script via `scriptName` + custom logic.)

## Useful one-liners

```python
# bytes from memory, as a Python bytes
import jpype
buf = jpype.JByte[16]; block.getBytes(addr, buf)
data = bytes(b & 0xff for b in buf)

# Java HashSet of addresses
from java.util import HashSet
seen = HashSet()
seen.add(addr)
if seen.contains(other_addr): ...

# convert a Java List to Python list
py_list = list(java_list)

# format an Address consistently
"0x" + str(addr)        # matches ReVa's AddressUtil.formatAddress() output
```
