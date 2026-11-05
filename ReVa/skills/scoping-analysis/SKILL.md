---
name: scoping-analysis
description: Use when the survey of a program in Ghidra is done and the request needs more than one question answered, or is vague (malware or not, what does it do, what does it talk to, fix the types, clean up the database, write a report); deciding what the user means and how big the job is.
---

# Scoping Analysis

Input: the request and the survey reply. Output: `<workspace>/brief.md`. No survey yet: Then read `binary-triage`. `<workspace>/brief.md` (Write the brief, step 1) exists for the same program and Request, or the user asks to resume: Then read `working-threads`.

Scoping decides from the survey; its only analysis calls are the assumption bookmarks.

## Broad reading

Write the matching row's full meaning, in your words, as Reading. Two rows match: take both.

| Request | Means in full |
|---|---|
| "Is this malware", "malware or not" | A verdict; the behaviours that justify it, each with evidence; what was ruled out. |
| "What is the C2", "what does it talk to" | Transport; every address or domain and how it is obtained (static, decoded, generated, resolved); protocol framing; the code that uses it. |
| "Fix the datatypes", "clean up the database" | Every function's prototype and locals; every structure that repeated field access reveals; globals; names where evidence supports them. |
| "Decrypt the payload" | The algorithm; the key and its source; a re-implementation script; the decrypted output in the database or a file; what the payload is. |
| "Extract the config" | The config blob's location and format; the decoder; the decoded fields, each labelled in the database and reported. |
| "Find signaturable elements", "write a detection" | Stable, specific, non-library bytes, strings, constants and structural features, each with address and a false-positive argument; then the rule in the user's format (YARA by default). |
| "What does it do" | Every capability present, with evidence; every absent survey capability group (network, execution, memory, crypto, persistence, anti-analysis), with where you looked. |
| "Write a report" | A verdict-size job: the verdict and "what does it do" rows in full, in the form the user asked for. |

No row fits: take the nearest; write why under Assumptions.

## Scope from the survey

Write each rule that applies under Scope decisions: `<decision> — because <survey fact> at <address>`.

| Survey shows | Scope decision |
|---|---|
| Packing: likely | Unpacking is goal 1; other threads start on the unpacked code. |
| A library with exports (DLL, `.so`, `.dylib`) | Every export is a thread. |
| Firmware or a raw image | Memory map and base address recovery is goal 1. |
| Runtime: .NET, Java or Dalvik, Go, Rust | Matching platform notes; name the runtime. |
| Several programs in the project | Which is the target; what each other one is. |

None applies: write `none — <format>, <runtime>`.

A large program stays whole. Order: candidate threads and own code reached from the entry point, then other own code, then library code by name.

## Ask or assume

Ask only when all three hold:
1. Your tool list has a tool that asks the user, and the session is interactive.
2. The survey is done.
3. A fork remains: two readings that lead to different threads.

Then ask once, with the broad reading as the recommended default. Write the answer under Assumptions. No answer: take Otherwise.

Otherwise:
1. Write the assumption under Assumptions.
2. Call `set-bookmark` once per assumption: `addressOrSymbol` the address it concerns, `type` `TODO`, `category` `Assumption`, `comment` `assumption: <reading chosen> — check: <what would change it>`. No address: the entry point, one bookmark, comments joined by `; `.
3. Proceed on the broad reading.

A file path is not a fork: `list-project-files` in the survey names the target.

## Budget

Copy the stated time and spend into Budget with its source. None stated: write `none stated`. Budget never narrows Reading or Done-when.

## Write the brief

1. Workspace: the directory the user named; otherwise `./reva-analysis/<program-basename>/` (`<program-basename>`: the program path's last part). If `<workspace>/brief.md` exists, use `<workspace>-2` (then -3).
2. Read `skill://scoping-analysis/templates/brief.md` and fill every slot.
3. Write the file `<workspace>/brief.md`. In the same reply, call the assumption bookmarks.

Headings, in order, exactly: `## Request`, `## Reading`, `## Survey`, `## Scope decisions`, `## Assumptions`, `## Non-goals`, `## Budget`, `## Done-when`. Request: the user's words, verbatim. Survey: the survey slots verbatim, then `Candidate threads:` and its lines, with no heading. Non-goals: only what the matched row does not name; library code goes under Scope decisions, by name. Done-when: one observable line per part of the Reading, all of it.

After the write returns, next reply: read `planning-analysis`, alone, before any other call.
