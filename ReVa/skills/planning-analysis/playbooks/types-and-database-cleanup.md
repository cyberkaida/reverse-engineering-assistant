# Playbook: types-and-database-cleanup

Copy each Mandatory thread with its five fields.

## Done-when

- Every function the request covers: prototype set, locals typed and named; or, its body read, a `TODO` bookmark category `Types` naming the failed call.
- Every structure repeated field access reveals: defined and applied at each user.
- Every global the typed functions read: typed and labelled.
- The database is the deliverable; the answer cites each type, name and comment.

## Mandatory threads

Type with ReVa's tools: `parse-c-structure`, `apply-structure`, `change-variable-datatypes`, `set-function-prototype`, `rename-variables`, `apply-data-type`, `create-label`. A script comes after a corrected call to one of them fails: Then read `pyghidra-scripting`.

1. `inventory-functions`. Question: which functions does the request cover? "Fix the types" and "clean up the database" cover every function. Start: `get-function-count`, then `get-functions`, paged. Closes when: every address is in `<workspace>/notes/functions.md`. Must exist: a comment at the entry point: `types: <N> functions`.
2. `structures`. Question: which structures do repeated offsets reveal? Start: `search-decompilation` for `\+ 0x`; three or more offsets on one base. Follow Recover a structure in `skill://deep-analysis/strategies.md`. Closes when: no raw offset remains on its base. Must exist: each structure applied at every user.
3. `types-<region>`: one thread per export's call tree (`get-call-tree` from each export or entry point), plus one thread for functions no tree reaches; each thread lists the functions it covers. Question: are their prototypes and locals typed? Per function: `get-decompilation`, paged; `set-function-prototype`, named from the body; `change-variable-datatypes`; `rename-variables`; a comment with its role; re-read. A library function: its documented prototype only. Closes when: each function is written or bookmarked. Must exist: each prototype and locals set, or the `Types` bookmark.
4. `globals`. Question: are the globals typed and named? Start: `DAT_` references in typed functions. Closes when: each is typed. Must exist: a type and a label at each.

## Platform notes

| Platform | Type sources |
|---|---|
| Windows PE | Import prototypes (`get-data-type-archives`); C++ vtables and RTTI `.?AV` names (`analyze-vtable`); `this` in `ECX`/`RCX`. |
| macOS Mach-O | `objc_msgSend` selectors name methods; `self` and `_cmd` come first. |
| Linux ELF | libc prototypes; DWARF when not stripped; `_ZTV` vtables; demangled parameter types. |
| Embedded firmware and raw images | A structure at each peripheral register base (`apply-structure`); SDK headers through `parse-c-header`. |
| Shellcode and position-independent blobs | The resolved API table as a structure of function pointers; `PEB` and `LDR_DATA_TABLE_ENTRY` structures. |
| Managed and bytecode runtimes | .NET metadata types managed code: type the native parts. Go strings `{ptr, len}`; JNI `JNIEnv *` first in `Java_` exports. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "Hundreds of functions: typing all is infeasible." | The request covers every function: work the inventory until done or a harness message says the time or spend is used; then write the open Thread line, the message in quotes. |
| "The typing tools cannot do this. Script it." | Use ReVa's typing tools; script only after a corrected call fails. |
