# Playbook: persistence-and-capabilities

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- Each persistence mechanism, with the install code and its exact location (key, task name, path, unit), or `no persistence: read <functions>; checked <imports, strings>`.
- Each privilege path, or its negative line.
- Each survey capability group: present with evidence, or absent with the functions read.

## Mandatory threads

1. `persistence`. Question: how does it survive a reboot or logon? Start: each Platform notes location found in strings or imports. Closes when: the install code, or every candidate, is read. Must exist: a `Note` bookmark category `Finding` at the install code, with the location, or the negative line.
2. `persistence-run-later`. Question: what does each call asking the system to run it later register? Start: COM `CoCreateInstance` callers (Windows); `SMAppService` or `SMJobBless` (macOS); D-Bus `org.freedesktop.systemd1` (Linux); init-script writers (firmware). Closes when: the class or service and each method (vtable offset or message) are read. Must exist: a comment at the call naming the class or service and methods.
3. `privilege`. Question: does it raise its privilege? Start: `AdjustTokenPrivileges`; `runas`; the `Elevation:Administrator!new:` moniker; `setuid`; `AuthorizationExecuteWithPrivileges`; `sudo`, `pkexec`. Closes when: each is read. Must exist: a comment at each, or the negative line.
4. `capability-<group>`, one per survey capability group (also in `verdict`). Question: what does the code do with it, or is it absent? Start: its first import's or string's caller. Closes when: each caller is read. Must exist: a function name and comment at each caller, or `no <group>: read <functions>; checked <imports, strings>`.

## Platform notes

| Platform | Persistence and privilege locations |
|---|---|
| Windows PE | `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`; `CreateServiceW`; scheduled tasks: `schtasks` strings, or the Task Scheduler COM class (`ITaskService` `Connect`, `GetFolder`, `NewTask`; `ITaskFolder` `RegisterTaskDefinition`); COM hijack under `Software\Classes\CLSID\...\InprocServer32`; the Startup folder; WMI `__EventFilter`. |
| macOS Mach-O | `~/Library/LaunchAgents` and `/Library/LaunchDaemons` plists; `launchctl load`; `SMAppService`, `SMJobBless`; login items; `LC_LOAD_WEAK_DYLIB` hijack. |
| Linux ELF | Cron: `/etc/cron.d/`, `/var/spool/cron/`; systemd units in `/etc/systemd/system/` and `~/.config/systemd/user/`, `systemctl enable`; `/etc/rc.local`; `~/.bashrc`; `/etc/ld.so.preload`; `authorized_keys`. |
| Embedded firmware and raw images | Firmware init scripts: `/etc/init.d/rcS`, `/etc/inittab`; `nvram set`; the U-Boot `bootcmd` variable; writes to `/dev/mtd*`. |
| Shellcode and position-independent blobs | Persistence belongs to the stage it drops: trace that write and its path. |
| Managed and bytecode runtimes | .NET `Registry.SetValue`, `Microsoft.Win32.TaskScheduler`; Android `RECEIVE_BOOT_COMPLETED` in `AndroidManifest.xml`, `JobScheduler`; autostart `.desktop` or crontab writes. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "No persistence: no Run key, service or task API imported." | No persistence from the import list alone. Read the `persistence-run-later` calls, run-time loaders and strings (`schtasks`, `launchctl`, `systemctl`); then write the negative line. |
| "This is a license or integrity check." | Name it after its body and callees are read. A role from memory is a `TODO` bookmark category `Assumption`. |
| "It only drops a file." | Read the path: a Startup, `LaunchAgents` or autostart path is persistence. |
