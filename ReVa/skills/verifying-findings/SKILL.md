---
name: verifying-findings
description: Use when the analysis threads for a program in Ghidra are closed in `<workspace>/ledger.md` and not yet checked against the database; before a family, algorithm, library, COM or Objective-C class, verdict or absence is reported.
---

# Verifying Findings

Input: `<workspace>/ledger.md`, `<workspace>/plan.md`, each `<workspace>/threads/NN-<slug>.md`. Output: a `Verify NN:` line per thread in the ledger; database fixes. No ledger: Then read `working-threads`. Pass the `programPath` to every call.

## Who verifies

Verify each thread with no `Verify NN:` line after its latest `Thread NN:` line.

If you can dispatch a worker that has the same analysis tools you do:
1. Read `skill://verifying-findings/templates/verifier-brief.md`. Fill one per closed thread.
2. Dispatch one worker per brief. It writes `<workspace>/verify/NN-<slug>.md`.
3. Read each verdict file. Append its ledger lines. No file: verify that thread yourself.

Otherwise, verify each closed thread yourself:
1. Read `threads/NN-<slug>.md`. List its claims: answer, confidence, addresses, names, negatives, alternatives, assumptions.
2. Add its Closes when and Must exist from `<workspace>/plan.md`.
3. Run the checklist; write the `Verify NN:` line after its calls return.

An open thread gets `Verify NN: unverifiable — thread open: <reason>`.

## The checklist

Run all five, in order.

| # | Check | Call | Fails when |
|---|---|---|---|
| 1 | Each cited address holds what the claim says | `get-decompilation` for code; `read-memory` for data | the pattern or constant is not there |
| 2 | Each named function, datum and Must exist item has an annotation | `get-symbols` with `filterDefaultNames` true; `get-comments` and `get-bookmarks` at its address | none, or it disagrees |
| 3 | Each negative finding names what was read and where | `get-comments` at it; `get-decompilation` on each function named | imports only, or no function read |
| 4 | Each alternative is excluded by a check | `get-bookmarks` and `read-memory` at each candidate's marker | a candidate in Closes when is dismissed in words or not checked |
| 5 | No open item contradicts the answer | `search-bookmarks` with `types` [`TODO`]; `search-bookmarks` with `categories` [`Assumption`]; `search-comments` with `searchText` `assumption:` | an open item says otherwise |

Each name and comment in Database writes: `get-decompilation`; data: `read-memory`. The read shows what it says, or check 2 fails.

Confidence: High only when check 1's `get-decompilation`, called after this skill was read, showed the producing code for every cited value.

## Naming claims

A claim naming a family, algorithm, library, COM or Objective-C class is confirmed only when:
1. The discriminating marker is in the database at an address, and `read-memory` or `get-decompilation` there shows it.
2. Each listed alternative is excluded by its marker, with its address.

A verdict or class (loader, RAT, stealer, PUP, not malicious) is a naming claim. Its markers are behaviours read at their addresses; its alternatives, the other classes.

## Mismatch is evidence

A noticed mismatch is evidence against the claim until a read resolves it: a GUID, parameter order, offset or import count.
1. Add `mismatch: <expected> vs <read> at <address>` to the claim list.
2. Resolve it by reading: the call it is passed to; `get-structure-info` for the current structure; `analysis-status`, then `list-imports` again.
3. Agrees: continue. Disagrees: check 1 fails. Unresolved: unverifiable.

| Thought | Reality |
|---|---|
| "Not that. … Whatever." | A mismatch or an odd tool result is evidence. Resolve it with a read. |
| "The exact command set of X." … "Note it as the decryption routine." | A name or role with its marker unread is an assumption. |
| "Confident on family." … "But I am confident." "Five checks per thread will blow the budget." | Confidence is not a check; spend comes only from a harness message. Run the five. |

## Verdicts

| Verdict | When | Do | Append to the ledger |
|---|---|---|---|
| confirmed | all five pass | nothing | `Verify NN: confirmed — <answer> — <High\|Medium\|Low> — check 1: <call> at <address>` |
| confirmed-with-fixes | only check 2 fails | write the missing annotation: `set-bookmark`, `set-comment`, `create-label`, `set-function-prototype` or `rename-variables` | `Verify NN: confirmed-with-fixes — <answer> — <High\|Medium\|Low> — wrote <annotation> at <address> — check 1: <call> at <address>` |
| refuted | check 1 fails, or a marker matches another candidate | append `Thread NN: open — refuted: <evidence>`; `set-bookmark` with `type` `TODO`, `category` `Thread`, `comment` the question and evidence | `Verify NN: refuted — <evidence> at <address>` |
| unverifiable | check 3, 4 or 5 fails, or a mismatch is unresolved | `set-bookmark` with `type` `TODO`, `category` `Assumption`, `comment` `assumption: <claim> — check: <next read>` | `Verify NN: unverifiable — <failed check> — next read: <read>` |

First refuted thread: next reply read `working-threads`, alone. Otherwise: next reply read `finishing-analysis`, alone.
