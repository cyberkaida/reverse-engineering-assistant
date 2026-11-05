---
name: reverse-engineering
description: Use when any request about a program in Ghidra arrives; read this first, alone, with no other call. Includes vague asks (malicious or not, what it talks to, what it does, fix types, clean up the database, write a detection, decode or decrypt, extract configuration, write a report, pull indicators). Covers any program, firmware image, shellcode or bytecode loaded in Ghidra; use before the first analysis tool call on a new request.
---

## First reply

1. Reply 1: one tool call, reading this skill.
2. Reply 2: one tool call, reading `binary-triage`.
3. Reply 3 starts its survey.

## Rules that always hold

1. Never execute the sample, directly, by script, debugger or sandbox; emulate one isolated routine only.
2. The evidence is the program in Ghidra, not host files, harness files or the web.
3. Write each finding into the database when made: name, comment, bookmark, type. Every reported address has an annotation.
4. The request's total is not elapsed. Time and spend come only from harness facts or notices; never estimate them. Cut, merge or bulk-do a step only quoting that message.
5. A reply that reads a skill holds no other tool call; read the routed skill alone at hand-off.
6. `skill://<skill>/<file>` is that file in the skill's own directory.

## Size, after the survey

The survey decides, never the wording.

| Size | Looks like | Next skill |
|---|---|---|
| Single question | One named function, address or rename | `deep-analysis` |
| Few threads | 2–5 sub-questions | `scoping-analysis` |
| Verdict or deliverable | What it does; C2; config; detection; all types; report | `scoping-analysis` |

Unnamed types or whole-database cleanup is not single. Size grows: step up.

## Route, after the survey

- Single question. Then read `deep-analysis`.
- Few threads or bigger. Then read `scoping-analysis`.
- Brief written. Then read `planning-analysis`.
- Plan written. Then read `working-threads`.
- Threads closed. Then read `verifying-findings`.
- Findings verified. Then read `finishing-analysis`.
- A flag challenge. Then read the matching `ctf-*` skill.
- The user asked for a script. Then read `pyghidra-scripting`.

| Thought | Reality |
|---|---|
| "Read the skill and list the project together." | The body arrives after this reply. Act next reply. |
| "Time nearly up." "Given budget, be strategic." | Quote the harness message, or run the full step. |
