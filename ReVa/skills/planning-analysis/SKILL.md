---
name: planning-analysis
description: Use when a brief for a program in Ghidra is written (`<workspace>/brief.md`) and the work needs an ordered list of threads before analysis starts; or sent here by `scoping-analysis` or `reverse-engineering` after the brief.
---

# Planning Analysis

Input: `<workspace>/brief.md`. Output: `<workspace>/plan.md`, an ordered list of threads. No brief yet: Then read `scoping-analysis`.

Read all of `<workspace>/brief.md`. No analysis calls.

## A thread

One question a reviewer could reject on its own. Five labelled fields:

1. **Question:** one question with a checkable answer. "What key decrypts the blob at `<address>`?"
2. **Start:** an address, symbol, string or import from the Survey.
3. **Closes when:** the evidence you expect to read, and where; then `refuted if:` what would show it false.
4. **Must exist:** each database annotation present at the end: "a `TODO` bookmark category `Assumption` for each open assumption"; "a `Note` bookmark category `Finding` at the C2 parser".
5. **Playbook:** its name, or `none`.

Number threads `01`, `02`, in run order: the brief's goal 1 (unpacking, memory map) if any; `identity`; the playbooks' Mandatory threads; the threads derived from Done-when, in the brief's order; the other perimeter threads. A Done-when item a Mandatory thread covers maps to it in the Done-when map.

The plan marks nothing done.

## Perimeter threads

Every plan holds these five, whatever the request or budget.

| Slug | Question | Start | Closes when | Must exist |
|---|---|---|---|---|
| `identity` | What does it say it is: name, version, build? | The recipe below | each source read | a `Note` bookmark category `Identity` at each identity string |
| `entry-points` | Is every entry point and export body read? | The Survey's entry points and exports | each body read or marked | a comment at each: its role, or `unread — <reason>` |
| `producers` | Is every reported value traced to its producer? | Each value another thread reports | each producer read | a function name and comment at each producer |
| `persistence` | How does it persist: Run keys, services, scheduled tasks, LaunchAgents, cron, systemd, init scripts? | Persistence imports and strings | install code read, or every candidate read | a `Note` bookmark category `Finding` at the install code, or a comment `no persistence: read <functions>; checked <imports, strings>` |
| `no-<capability>` | One per capability the request implies and the Survey lacks: is it absent? | Its imports, loaders (`GetProcAddress`, `dlsym`), strings | each candidate function read | a comment `no <capability>: read <functions>; checked <imports, strings>` |

Identity start: `get-strings` with `regexPattern` `\.pdb|VS_VERSION_INFO|ProductVersion|Go build ID|/rustc/`; then export names, manifests, section names, .NET assembly metadata.

## Alternatives

A thread that names a verdict, a family or an algorithm lists its candidates before naming one.
1. Closes when: `candidates: <A>, <B>, other — separated by: <marker per candidate>` (a constant, table, string or command name).
2. Order it after the thread that decodes its markers.
3. It closes when one marker is read in the database and the others are excluded by theirs.

## Playbooks

For each line that applies, read `skill://planning-analysis/playbooks/<name>.md`. Copy its Mandatory threads, each under its own slug; fill their slots from the brief. Only a thread with the same slug is referenced, not added again.

- `verdict`: malicious or not; how bad; a report.
- `network-and-c2`: C2; what it talks to; a protocol; indicators; a fetched stage.
- `persistence-and-capabilities`: what it does; a report; indicators; persistence imports or strings.
- `config-extraction`: a configuration; a blob that holds settings.
- `decoding-and-decryption`: decode or decrypt; crypto imports; Base64 alphabets; key-like hex.
- `detection-and-signatures`: a detection, rule or signatures.
- `types-and-database-cleanup`: fix types; rename; clean up the database.
- `unpacking-and-loaders`: packing likely; code that maps or loads a payload.
- `chains-and-mixed-artifacts`: more than one thing: several programs, a script with a payload, shellcode in a document, an archive, staged code; added beside the others.

None fits, or one fits part of the job: derive those threads from each Done-when item plus the perimeter threads. Write each playbook consulted and why it did not fit.

## Write the plan

1. Workspace: the directory that holds the brief.
2. Read `skill://planning-analysis/templates/plan.md` and fill every slot.
3. Write the file `<workspace>/plan.md`.

## Self-review

After the write, check:
1. Every brief Done-when item has a thread number in the map. Missing: add a thread.
2. Every thread has a Start, a Closes when, and a Must exist naming an annotation and an address or slot. Missing: write it.
3. Every Question has a checkable answer. "Investigate", "look into", "more": rewrite it as what, which, where or does.
4. Every Mandatory thread of each playbook used has its `###` entry. Missing: add it.

Failed: rewrite and recheck.

Next reply: read `working-threads`, alone, before any other call.
