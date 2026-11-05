---
name: binary-triage
description: Use when surveying any program, firmware image, shellcode or bytecode in Ghidra before a request is scoped; asked to triage, survey, give an overview or say "what is this"; or sent here by `reverse-engineering`.
---

# Binary Triage

Run the eight steps in order, then hand off. Pass the `programPath` from step 1 to every call. Batch independent calls. Empty result: write "none".

### 1. Identify

1. Call `list-project-files` with `folderPath` `/` and `recursive` true. The file entry is the program path.
   - No program listed and the user named a file: call `import-file` with that path, then `analyze-program`; status `running`: call `analysis-status` with its `jobId` until terminal.
   - Several programs: write each under Leads.
2. Call `get-memory-blocks`. Format from block names: `Headers` and `.rdata` is Windows PE; `.rodata` and `.plt` is Linux ELF; `__TEXT` and `__LINKEDIT` is macOS Mach-O; one block with no header is firmware, a raw image or shellcode.

   Architecture: the processor any tool result names, else the address width (8 hex digits 32-bit, 16 64-bit).
3. Call `list-imports` with `groupByLibrary` true, then `list-exports`. The entry point is the export `entry`, `start` or `_start`; with none, the start of the first executable block. List all exports.
4. Runtime signatures. Call `get-strings` with `regexPattern` `Go build ID|panicked at|Ljava/`, then match:
   - .NET: `mscoree.dll`, `_CorExeMain`.
   - Go: `runtime.` symbols, `Go build ID:`, `.gopclntab`.
   - Rust: `core::` symbols, `panicked at`, `.rs` paths.
   - Java or Dalvik: `classes.dex`, `Ljava/` strings, `JNI_OnLoad`.
   - Script in a dropper: PowerShell, VBScript, JavaScript or shell text.
   - None of these: native.
5. Packing. Count the signs:
   - Entry point outside the first executable block, or in a writable one.
   - Packer block names: `UPX0`, `.aspack`, `.MPRESS1`, `.themida`, `.vmp0`.
   - Under ten imports for a program over 100 KB, or only loaders (`GetProcAddress`, `dlsym`).
   - One large block with few strings and no text from `read-memory` with `length` 64, `format` `ascii`.
   - An executable block of a few KB beside a large data block.

   Two or more signs: record "packing: likely" with the signs; unpacking is candidate thread 1. One sign: write it under Leads. Else: "packing: no".
6. Call `set-bookmark` with `addressOrSymbol` the entry point, `type` `Note`, `category` `Survey`, `comment` the facts so far: format, architecture, runtime, packing.

### 2. Memory layout

Write under Leads, with address: a block both writable and executable; one block far larger than the rest.

### 3. Strings

Call `get-strings-count`, then `get-strings` in pages. Sort, with addresses:
- Network: URLs, IPs, domains, user agents.
- Files and settings: paths, registry keys, `.plist`, `.ini`.
- Commands: `cmd.exe /c`, `/bin/sh -c`, `schtasks`, `launchctl`.
- Crypto: Base64 alphabets, key-like hex.
- Banners: library versions.

### 4. Imports by capability

Group the step 1 imports. Each line gives Windows; POSIX; macOS names:
- Network: `WinHttpSendRequest`; `socket`; `NSURLSession`.
- Execution: `CreateProcessW`; `execve`; `posix_spawn`, `NSTask`.
- Memory: `VirtualAlloc`, `WriteProcessMemory`; `mmap`; `mach_vm_allocate`.
- Crypto: `CryptEncrypt`; `EVP_EncryptInit_ex`; `CCCrypt`.
- Persistence: `RegSetValueExW`, `CreateServiceW`, `CoCreateInstance`; cron or systemd paths; `SMJobBless`, `LaunchAgents` paths.
- Anti-analysis: `IsDebuggerPresent`; `ptrace`; `sysctl`.

### 5. Functions

1. Call `get-function-count` with `filterDefaultNames` false, then true. Mostly `FUN_` names: stripped.
2. Call `get-functions` with `filterDefaultNames` true, in pages.
3. Find main: `main`, `WinMain`, `DllMain`, `ServiceMain`, `main.main`, `JNI_OnLoad`.
4. Library versus own code: runtime or library names (`std::`, `runtime.`, `EVP_`) are library; the rest is own.

### 6. Cross-references for leads

1. Pick five leads: network and execution strings and imports first.
2. String: `find-cross-references` with `location` its address, `direction` `to`, `includeContext` true. Import: `find-import-references` with `importName`.
3. Record the calling function and address. A function in two or more groups is a strong lead.
4. Write the other strings and imports under Leads, unchecked.

### 7. First look at code

Decompile four functions at most:
1. The entry point.
2. Up to three leads: main if the entry point only calls it, then step 6's strongest.

Step 7 is one reply: its `get-decompilation` calls, `limit` 30. The next reply calls step 8.1's `set-bookmark`; any other function goes, undecompiled, into `## Candidate threads`. Each decompiled function gets a line there too.

### 8. Record and hand off

1. Call `set-bookmark` at the entry point, same `type` and `category`; it replaces the step 1 text. `comment`: a one-paragraph summary adding apparent purpose and top leads.
2. Write these sections in your reply:

```
## Survey
- Format:
- Architecture:
- Runtime:
- Packing:
- Entry points and exports:
- Library versus own code:
- Strings and imports landscape:
- Leads:
- Size: <single question | few threads | verdict or deliverable> — <why>

## Candidate threads
1. <question> — start at <address> — <what it seems to do> — <why it matters>
```
3. In that reply, with no other tool call, Size picks:
   - Single question: read `deep-analysis`.
   - Any other size: read `scoping-analysis`.
   - A flag challenge: read the matching `ctf-*` skill.
   - A script request: read `pyghidra-scripting`.
Never answer or finish here.

## Notes

- **Pagination.** Call the count tool first. Fetch pages of 100 (`maxCount` or `maxResults`), with `startIndex`.
- **Anomalies.** Anything no rule above fits goes under Leads with its address.

| Thought | Reality |
|---|---|
| "The answer is already clear." | Write it as candidate thread 1. Finish step 8; read the next skill. |
| "One more function settles it." | A lead is written down, not followed, here. |
