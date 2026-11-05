# Playbook: detection-and-signatures

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- Each element, in the program's own code or data: its address, why stable across builds, why specific, a false-positive argument.
- The rule, in the form the user asked for (YARA by default), written to `<workspace>/detection/<program-basename>.yar`.
- A `Note` bookmark category `Signature` at each rule element.

## Mandatory threads

1. `own-code`. Question: which functions are the program's own? Start: the Survey's library-versus-own split; statically linked runtimes (CRT, OpenSSL, Go `runtime.`). Closes when: each candidate function is classed own or library. Must exist: a comment at each own function a rule uses.
2. `elements`. Question: which strings, code and features are stable and specific? Start: mutex and pipe names, build paths, command names, decoded strings; decoder and dispatch loops in own code, read with `read-memory`; Platform notes features. Bytes that change per build (addresses, displacements, keys) become `??`. Closes when: each source is checked. Must exist: a `Note` bookmark category `Signature` at each.
3. `false-positives`. Question: will a benign program match each element? Closes when: each has a one-line argument: own code, read; not a library, API or compiler string; not a prologue or compiler idiom; at least 8 bytes. No argument: drop it; comment why. Must exist: the argument in its bookmark comment.
4. `rule`. Question: which rule matches this program and no benign one? Closes when: the file is written; each string has an address comment; the condition requires N of the elements and the row's format check, if any. Must exist: a comment at each element: `rule <name> $<id>`.

## Platform notes

| Platform | Format check and stable elements |
|---|---|
| Windows PE | `uint16(0) == 0x5A4D`; the `pe` module; exports, resource names, PDB path. Exclude MSVC CRT code. |
| macOS Mach-O | `uint32(0) == 0xfeedfacf` or `0xfeedface`; universal `0xbebafeca` (also Java `.class`: add a Mach-O element); the `macho` module; bundle identifier, Objective-C class and selector names. |
| Linux ELF | `uint32(0) == 0x464c457f`; the `elf` module; `/proc` and `/dev/shm` paths, shell commands. Exclude static libc. |
| Embedded firmware and raw images | No header check; vendor banners, hard-coded credentials, own-code MIPS or ARM sequences. |
| Shellcode and position-independent blobs | No header check; the decoder stub with its key as `??`; API hash constants. Pair a PEB walk with a specific element. |
| Managed and bytecode runtimes | .NET `dotnet` module: assembly name, type library GUID, user strings; Java and Dalvik class names; Go main-module package paths, not `runtime.`. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "This string is unique to it." | Read its referencing function. Library, API and compiler strings match benign programs. |
| "Entry point bytes make a good signature." | Entry stubs are compiler runtime. Use own-function bytes, per-build bytes as `??`. |
| "The file hash or imphash is the detection." | Both change each build: one condition at most. |
