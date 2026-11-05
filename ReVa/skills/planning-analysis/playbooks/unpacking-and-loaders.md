# Playbook: unpacking-and-loaders

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- The packer, with the marker that names it, or `custom`.
- The unpacking routine: algorithm, source, destination and size.
- The handoff: the transfer instruction and its target.
- The payload carved, imported as its own program, and surveyed.

## Mandatory threads

The sample and carved code never run: no debugger, sandbox, whole-program emulation or memory dump. Unpack by re-implementing the routine on the packed bytes. A static unpacker that does not run the sample's code (`upx -d` on a copy) is allowed; import the result as its own program with `import-file` and check its entry against the in-binary unpacking routine's hand-off.

1. `packer`. Question: which packer or loader is it? Start: the Survey's packing signs (Platform notes); a writable, executable block in `get-memory-blocks`. Closes when: `candidates: <packer>, custom — separated by: <marker>` (a magic: `UPX!`). Must exist: a `Note` bookmark category `Packer` at the entry point naming the marker.
2. `unpacker`. Question: which routine writes the unpacked bytes, and where? Start: the allocation (`VirtualAlloc`, `mmap`) or section write. Closes when: the routine is read, with source, destination and size: `candidates: LZMA, aPLib, NRV, XOR, custom — separated by: <marker>`. Encrypted: copy the threads of `skill://planning-analysis/playbooks/decoding-and-decryption.md`. Must exist: a function name and comment at the routine.
3. `handoff`. Question: where does control pass to the unpacked code? Start: the end of the unpacking routine. Shapes: a tail jump to a far address; memory written, made executable (`VirtualProtect`, `mprotect`), then called; a decrypted section, then a jump; a manual mapper. Closes when: the target and its bytes are known. Must exist: a `Note` bookmark category `Handoff` at the transfer, naming the target.
4. `carve`. Question: what is the payload as a program? Closes when: your re-implementation or the static unpacker writes `<workspace>/carved/<name>.bin`; its header matches; `import-file` and `analyze-program` load it. Script: Then read `pyghidra-scripting`. Must exist: a comment at the source naming the carved file; a `survey-<name>` thread in the plan.

## Platform notes

| Platform | Packing signs and handoffs |
|---|---|
| Windows PE | `UPX0`/`UPX1`, `.MPRESS1`, `.themida` sections; only `LoadLibraryA` and `GetProcAddress` imported; hollowing (`NtUnmapViewOfSection`, `SetThreadContext`). |
| macOS Mach-O | `UPX!` in the header; `mach_vm_allocate` and `mach_vm_protect`; `NSCreateObjectFileImageFromMemory`. |
| Linux ELF | `UPX!` and no section headers; `memfd_create` then `fexecve`. |
| Embedded firmware and raw images | A boot stub that decompresses to a load address: import the output there. |
| Shellcode and position-independent blobs | A decoder stub, then a reflective loader: a PEB walk (`fs:[0x30]`, `gs:[0x60]`). |
| Managed and bytecode runtimes | .NET `Assembly.Load(byte[])`; Java `defineClass`, Dalvik `DexClassLoader`; PyInstaller `MEI` archives. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "Packed, so the analysis stops at the stub." | The stub is the unpacker: unpack, carve. |
| "The first unpacked code is the final payload." | Look in it for another handoff (allocate, copy, jump): a new stage. |
