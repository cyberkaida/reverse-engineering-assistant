# Playbook: verdict

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- A verdict: malicious, potentially unwanted, benign or undetermined.
- Each supporting behaviour read in code, with address and annotation.
- Each candidate not chosen, with its excluding marker.
- Each survey capability group: present or absent, with what was read.

## Mandatory threads

1. `capability-<group>`, one per survey capability group (also in `persistence-and-capabilities`). Question: what does the code do with it, or is it absent? Start: its first import's or string's caller. Closes when: each caller is read. Must exist: a function name and comment at each caller, or `no <group>: read <functions>; checked <imports, strings>`.
2. `payload-fate`. Question: what happens to each file or buffer it downloads, drops or decodes? Start: the execute or map call (`ShellExecuteW`, `CreateProcessW`, `execve`, `NSTask`). Closes when: what runs is traced to its producer. Must exist: a comment there naming both.
3. `consent`. Question: can the user see, agree to and remove it? Start: UI calls (`MessageBoxW`, `NSAlert`, `gtk_dialog_run`), uninstall strings. Closes when: each UI call is read. Must exist: a comment at each with its text.
4. `verdict`, last. Question: which verdict does the evidence support? Start: the entry point. Closes when: `candidates: malicious, potentially unwanted, benign, undetermined — separated by:` hidden execution of an unverified payload, or persistence or theft without consent (malicious); visible offers, consent and an uninstall (potentially unwanted); behaviour matching the identity's product (benign); an open thread that decides it (undetermined). Must exist: a `Note` bookmark category `Verdict` at the entry point listing each behaviour's address.

## Platform notes

| Platform | Behaviours that separate the candidates |
|---|---|
| Windows PE | `URLDownloadToFileW` or `WinHttpReadData` then `ShellExecuteW`; `VirtualAlloc` plus `CreateRemoteThread`; Run keys; `WinVerifyTrust` on the download (points to benign). |
| macOS Mach-O | `NSTask` or `posix_spawn` of a file in `/tmp`; removing `com.apple.quarantine`; `~/Library/LaunchAgents` writes; `SecStaticCodeCheckValidity` on the download. |
| Linux ELF | `execve` of a file in `/tmp` or `/dev/shm`; `memfd_create`; `ptrace(PTRACE_TRACEME)`; writes to `/etc/ld.so.preload` or crontab. |
| Embedded firmware and raw images | Hard-coded credentials; `telnetd` in init scripts; unsigned updates; writes to `/dev/mtd`. |
| Shellcode and position-independent blobs | A PEB walk (`fs:[0x30]`, `gs:[0x60]`) or raw `syscall` that fetches and jumps to a next stage. |
| Managed and bytecode runtimes | .NET `Assembly.Load(byte[])`, `Process.Start`; Java `Runtime.exec`, `DexClassLoader`; Python `exec(marshal.loads(...))`; PowerShell `IEX`. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| Malicious explained as benign: "it just downloads and runs an update." | Trace the URL and executed path to their producers; read whether the file is verified. Hidden execution of an unverified remote file is a loader. |
| Benign explained as malicious: "`VirtualAlloc`, `CreateRemoteThread`, crypto: malware." | Read each caller. Installers and updaters import the same; a verdict needs behaviour read in code. |
| "A PUP, not malware: no exploit, no persistence, a dialog." | Read `payload-fate`. A hidden download-and-execute loader is malicious, whatever else is absent. |
