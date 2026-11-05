# Playbook: decoding-and-decryption

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- Each encoded item: address, size, consumer.
- Its decoder (the producer of the decoded bytes) and key, named and commented.
- A re-implementation script; the decoded output in the database and in `<workspace>/decoded/<NN>.bin`.
- What the output is, and the marker confirming it.

## Mandatory threads

Decode by re-implementing the routine. The sample and carved code never run: no debugger, sandbox, or emulating the program. Run only your own script: encoded bytes in; it re-implements the routine, or emulates that one isolated routine.

1. `encoded-<NN>`, one per item. Question: which bytes are encoded, and what consumes them? Start: unreadable strings, a blob with few strings, crypto imports, a Base64 alphabet, key-like hex. Closes when: its bytes, size and consumer are read. Must exist: a `Note` bookmark category `Encoded` at the item.
2. `decoder-<NN>`. Question: which function produces the decoded bytes? Start: the call that uses the plaintext. Follow its argument back (Callee rule, `trace-data-flow-backward`), past each concatenator, copier or formatter. Closes when: the transforming function is read to its end and matched in `skill://deep-analysis/patterns.md`: `candidates: <shape>, custom — separated by: <marker>`. Must exist: its name, prototype and comment `decoder: <algorithm>`. When a reported value is decoded, the perimeter `producers` thread is this thread: give it this Closes when and Must exist.
3. `key-<NN>`. Question: where does the key come from? Closes when: the producer of the decoder's key, IV or table is read. Must exist: a label and comment at the key.
4. `decode-<NN>`. Question: what are the decoded bytes? Steps: decode the first 16 bytes by hand from `read-memory`; write the file `<workspace>/scripts/decode-<NN>.py` (encoded bytes in, `<workspace>/decoded/<NN>.bin` out); run it. Script: Then read `pyghidra-scripting`. Closes when: a marker holds: over 90 % printable; a magic (`MZ`, `\x7fELF`, `\xcf\xfa\xed\xfe`, `PK`); the length the consumer expects. None holds: fix the key, or try the next shape. Must exist: a comment at the item: the decoded value or path.

## Platform notes

| Platform | Decoders and keys |
|---|---|
| Windows PE | `BCryptDecrypt`, `CryptDecrypt`, `CryptStringToBinaryA` (Base64); stack strings. |
| macOS Mach-O | `CCCrypt`, `SecKeyCreateDecryptedData`; `initWithBase64EncodedString:options:`; `__mod_init_func` string decoders. |
| Linux ELF | OpenSSL `EVP_DecryptUpdate`; `.init_array` string decoders. |
| Embedded firmware and raw images | LZMA (`5d 00 00`) or gzip (`1f 8b`) sections; a key at a fixed flash offset. |
| Shellcode and position-independent blobs | A stub at offset 0 looping over the bytes after a `call`/`pop`; an immediate key. |
| Managed and bytecode runtimes | .NET `Convert.FromBase64String`, `Aes.CreateDecryptor`, an indexed string decryptor; Java `Cipher.getInstance`; Go `crypto/aes`; Python `zlib.decompress`. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "This helper builds the strings, so they are plaintext." | A concatenator is not the producer. Follow its callers' inputs back. |
| "Give up on decode; time is short." | It ends on a marker, or Open with every patterns shape refuted. |
