# Playbook: config-extraction

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- The config's location, size, format and encoding, with the decoder.
- The parser, named and typed; a structure applied where it reads.
- Every field: name, value, address, and the decode behind it.

## Mandatory threads

The config is a structure the program parses: find the parser, type the structure, then read the fields.

1. `config-locate`. Question: where are the config bytes? Start: a call that uses a setting (`connect`, `CreateMutexW`), traced back (Callee rule); or a Platform notes location. Closes when: the blob's address and size are read. Must exist: a `Note` bookmark category `Config` at the blob.
2. `config-decode`. Question: which decoder and key produce the config? Encoded: copy the threads of `skill://planning-analysis/playbooks/decoding-and-decryption.md` for this blob. Closes when: a decode marker holds, or the bytes are plain. Must exist: a comment at the blob naming the decoder and key, or `not encoded`.
3. `config-parser`. Question: which function reads fields from the decoded bytes? Start: `trace-data-flow-forward` from the decoder's output. Closes when: each field read is listed: offset or key, size, consumer. Must exist: a function name and prototype at the parser.
4. `config-struct`. Question: what is the layout? Closes when: `parse-c-structure` defines a field per offset; `set-function-prototype` or `change-variable-datatypes` types the parser's pointer; the re-read shows no raw `+ 0xNN`. Text formats: a comment at the parser listing each key. Must exist: the structure applied; fields named after their consumers.
5. `config-field-<NN>`, one per field. Question: what is its value and its consumer? Closes when: both are read. Must exist: a comment where the parser reads it: `<field> = <value> at <blob>+<offset> — decoded by <decoder>`.

## Platform notes

| Platform | Where configs live |
|---|---|
| Windows PE | A `.data` or `.rdata` blob; an `RT_RCDATA` resource (`FindResourceW`); the overlay; a registry value. |
| macOS Mach-O | `__DATA,__const` or a custom section (`getsectiondata`); a plist in `Contents/Resources`; `CFPreferencesCopyAppValue`. |
| Linux ELF | A `.data` or `.rodata` blob; bytes appended to the file, read through `/proc/self/exe`; a file under `/etc`. |
| Embedded firmware and raw images | `nvram_get` keys; a config partition at a fixed flash offset; `/etc/config` UCI files. |
| Shellcode and position-independent blobs | A fixed-size block after the code, found by `call`/`pop` or a RIP-relative `lea`. |
| Managed and bytecode runtimes | .NET `GetManifestResourceStream`, static fields set in `.cctor`; Java `.properties`; Android `SharedPreferences`; Go strings passed to `json.Unmarshal`. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "The URLs in the strings are the config." | The config is what the parser reads: report each parsed field. |
| "The field meanings are obvious from the bytes." | Name a field after reading its consumer. A guess keeps `field_0x<offset>` and an `assumption:` comment. |
| "No config: no encrypted blob." | Literal settings are the config: write `no config blob: settings are literals at <addresses>`. |
