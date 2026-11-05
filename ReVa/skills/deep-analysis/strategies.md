# Question strategies

Each strategy runs inside the loop in `SKILL.md`: the rules there (Improve at once, Paging, Callee, Negative findings) hold at every step. Each gives where to start, what to read, what to write, and what closes the thread.

## What does function X do?

Start:
1. `get-decompilation` with `includeIncomingReferences` true and `includeCallees` true. Page to the last line.
2. `find-cross-references` on the function, `direction` `to`, `includeContext` true: who calls it, and with what.

Read:
- Loops, branches and every call. Decompile each callee whose name is a default name (`FUN_`, `sub_`) before describing what it does.
- Strings and constants it uses: `get-data` or `read-memory` at their addresses.
- Settings and persistence it touches: the registry (`RegSetValueExW`), property lists (`.plist`, `NSUserDefaults`), cron entries, systemd units, launchd jobs (`LaunchAgents`, `LaunchDaemons`).

Write: local names, parameter types, the function name and prototype with `set-function-prototype`, one comment per step of the behaviour.

Closes when: each line of the body is accounted for in one sentence of the answer, and each callee in it is named.

## Does it use cryptography?

Start:
1. `get-strings` with a pattern for algorithm names (`AES`, `RC4`, `ChaCha`, `RSA`, `SHA`, `MD5`).
2. Imports by platform: `CryptEncrypt`, `BCryptEncrypt` (Windows); `EVP_EncryptInit_ex`, `mbedtls_` (POSIX libraries); `CCCrypt`, `SecKeyCreateEncryptedData` (macOS); `javax.crypto.Cipher`, `System.Security.Cryptography` (managed).
3. Constants: `find-constant-uses` or `search-decompilation` for table values (`patterns.md` lists S-boxes and magic numbers).

Read: each function using them, to its end. Find the key, IV and data, and trace each to its producer.

Write: comment the algorithm at the routine and at the table; type the table (`apply-data-type`, for example `uint8_t[256]`); name the key buffer.

Closes when: algorithm, mode, key source and the data it processes are each at an address. No crypto: a negative finding, with the functions read.

## What does it talk to?

Start with the network calls, side by side:

| Platform | Calls |
|---|---|
| Windows | `WSAStartup`, `connect`, `WinHttpSendRequest`, `InternetOpenUrlA`, `URLDownloadToFileW` |
| POSIX | `socket`, `connect`, `getaddrinfo`, `send`, `curl_easy_perform` |
| macOS | `NSURLSession`, `CFStreamCreatePairWithSocketToHost`, `nw_connection_create` |
| Managed | `HttpClient`, `WebClient`, `java.net.URL`, `okhttp3`, Go `net/http` |
| Firmware and shellcode | lwIP `tcp_connect`, `netconn_connect`; raw socket syscalls; API names resolved by hash |

1. `find-import-references` for each call present; `get-strings` for URLs, IPs, domains, user agents.
2. Decompile each caller. Trace each host, port and path argument back to its producer (Callee). A string built by a helper is followed to the bytes.

Write: label the endpoint data (`create-label`); comment each endpoint with its decoded value; name the connect and send routines.

Closes when: every endpoint, the way it is obtained (static, decoded, generated, resolved) and the code that uses it are each at an address.

## Fix the types in this function

1. `get-decompilation`, paged to the end. List each `undefined` variable, each cast and each `param_N + 0xNN`.
2. Type evidence for each: the API it is passed to (its documented signature), the operations on it (pointer dereference, arithmetic, comparison), and the callers' arguments (`get-callers-decompiled`).
3. Offsets on one base: Recover a structure, below.
4. Write: `set-function-prototype` for parameters and return, `change-variable-datatypes` for locals, `rename-variables` for each local whose use you read.
5. Re-read. A new cast: fix that type and re-read.

Closes when: no `undefined` local or cast remains whose use you have read.

## Decode or decrypt a blob

1. Find the blob: a large data block with few strings whose `read-memory` with `length` 64, `format` `ascii` shows no text, an unreadable string table, or a buffer passed to a routine before use. Read it with `read-memory`.
2. Find the routine that reads it: `find-cross-references` `to` on the blob. Apply Callee: the routine that changes the bytes is the decoder, not the one that copies or joins them.
3. Read the decoder to its end. Match its shape against `patterns.md`: single-byte or rolling XOR, an RC4 key schedule (fill 0 to 255, then swap), an AES S-box (`63 7c 77 7b`), a Base64 alphabet, a custom table.
4. Find the key and trace it to its producer.
5. Decode the first bytes by hand from the `read-memory` output. Readable text, or a known header (`MZ`, `\x7fELF`, `\xcf\xfa\xed\xfe`, `PK`), confirms the algorithm.
6. Decode the rest with a re-implementation (a short script on the bytes, or `run-script`). The sample's own code never runs.
7. Write: a comment at each blob with its decoded value, the decoder's name and prototype, a bookmark at the key.

Closes when: the decoded output is readable, and is in the database at the blob's address. The first attempt fails: add an evidence line for the refuted pattern and try the next; every pattern refuted: end the thread Open with that reason.

## Recover a structure

1. In the function, list each access on the base pointer: offset, size from the cast, read or write, and what the value is used for.
2. Add accesses from the other users: `get-callers-decompiled`, and the callees that take the same pointer.
3. Size: the allocation that creates it (`malloc`, `HeapAlloc`, `operator new`, `kmalloc`) or the largest offset plus its field size.
4. Write a C definition with a field at each seen offset and padding between (`uint8_t pad_0x10[8];`). Call `parse-c-structure`.
5. Type the pointer: `set-function-prototype` for a parameter, `change-variable-datatypes` for a local, `apply-structure` for a global instance.
6. Re-read. A field access that still shows a cast or `+ 0xNN` is a wrong offset or size: check `get-structure-info`, correct the definition, call `parse-c-structure` again.
7. Name fields whose use you have read. A field whose role is a guess keeps a neutral name (`field_0x48`) and an `assumption:` comment.

Closes when: no raw offset on that pointer remains in the function and its readers.
