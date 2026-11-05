# Playbook: chains-and-mixed-artifacts

Copy each Mandatory thread, five fields, per stage; an unpacking `handoff` or `carve` is that stage's.

## Done-when

- Each artifact, with format and runtime, surveyed on its own terms.
- Each hand-off (what decodes, drops, loads or maps what), with evidence at both ends.
- Each embedded native payload carved and imported as its own program.
- Each stage's identity and version.
- Each script and bytecode layer read; notes in `<workspace>/notes/<stage>.md`.

## Mandatory threads

1. `inventory`. Question: which artifacts and embedded payloads exist? Start: `list-project-files` with `recursive` true; headers inside data (`MZ`, `\x7fELF`, `\xcf\xfa\xed\xfe`, `PK`, `dex\n`), script text, Base64 runs. Closes when: every program's data blocks are searched. Must exist: a `Note` bookmark category `Stage` at each payload's first byte.
2. `survey-<stage>`, one per artifact. Question: what is it? Start: a program's entry point, with the `binary-triage` survey; a script or bytecode, read whole into its notes file; a blob at offset 0 or the hand-off target. Closes when: its survey slots are filled. Must exist: a `Note` bookmark, category `Survey`, at its entry, or its notes file.
3. `handoff-<NN>`, one per pair of stages. Question: how does stage N reach stage N+1? Start: stage N's decode, drop, load or map call. Closes when: the producer of the next stage's bytes is read and matches its header. Must exist: a `Note` bookmark category `Handoff` at the call; a comment at the next stage's entry naming the source.
4. `carve-<stage>`. Question: what is the embedded payload as a program? Start: its `Stage` bookmark. Closes when: a script writes it to `<workspace>/carved/<stage>.bin` and `import-file`, `analyze-program` load it. Encrypted: re-implement the decoder first. Must exist: the carved program imported; a comment at the source bytes naming it. Script: Then read `pyghidra-scripting`.
5. `identity-<stage>`: the perimeter `identity` thread, per stage.

## Platform notes

| Platform | Stage shapes |
|---|---|
| Windows PE | Resources (`FindResourceW`, `LoadResource`); an overlay; a reflective DLL (`MZ` in memory); Office `vbaProject.bin`; LNK files. |
| macOS Mach-O | Universal binaries, one program per slice; app bundles (`Contents/MacOS`, `Contents/Resources`); PKG `postinstall` scripts; `osascript`; `NSCreateObjectFileImageFromMemory`. |
| Linux ELF | A shell dropper with an appended ELF; `memfd_create` then `fexecve`; `dlopen` of a dropped `.so`. |
| Embedded firmware and raw images | Partitions (uImage `27 05 19 56`, squashfs `hsqs`, TRX `HDR0`): carve each; import at its load address. |
| Shellcode and position-independent blobs | A decoder stub, then the decoded body: carve that. Shellcode in JavaScript `unescape("%u...")` strings. |
| Managed and bytecode runtimes | .NET `Assembly.Load(byte[])` of a resource; JAR in JAR; Dalvik `DexClassLoader`; PyInstaller (`MEI` cookie) holding `.pyc`; PowerShell and JavaScript layers. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "The first native code found is the payload." | Look for a hand-off (allocate, copy, jump; write, execute; load): each is a new stage. |
| "Ghidra cannot disassemble the script; skip it." | Read it as text; write its notes file; bookmark its hand-off. |
