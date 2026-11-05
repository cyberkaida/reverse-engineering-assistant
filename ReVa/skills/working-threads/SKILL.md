---
name: working-threads
description: Use when a plan for a program in Ghidra is written (`<workspace>/plan.md`) and its threads need working; when a workspace holds a ledger from an earlier session; or sent here by `planning-analysis` or `reverse-engineering` after the plan.
---

# Working Threads

Input: `<workspace>/plan.md`. Output: `<workspace>/ledger.md`, one `<workspace>/threads/<NN>-<slug>.md` per thread, and the database writes. No plan yet: Then read `planning-analysis`.

The ledger records evidence; a line is written when the evidence exists, never to clear a list.

## Resume or start

Look for `<workspace>/ledger.md`. A brief names this program when its title is `# Brief: <program-basename>`.

| Found | Do |
|---|---|
| No ledger | Read `skill://working-threads/templates/ledger.md`. Write the ledger; its first line is `# Analysis ledger — plan: <workspace>/plan.md`. Start at thread 01. |
| Its first line names a plan whose brief names this program | Go to Each thread. |
| Any other ledger | Leave that workspace unchanged. Copy your brief and plan into `<workspace>-<N>/` (next free number); work there. |

## Each thread

In plan order, each thread whose last `Thread NN:` line is missing or not `closed`:

1. **Run.** `deep-analysis` not in context: Then read `deep-analysis`. Run its loop on the Question from the Start.
2. **Report.** Fill `skill://working-threads/templates/thread-report.md`. Write `<workspace>/threads/<NN>-<slug>.md`. Not found: write `deep-analysis`'s six Thread report parts, in order.
3. **New threads.** Append each to `<workspace>/plan.md` under `## Threads`, as `### <NN>-<slug> (discovered in <NN>)`, next free number, five fields: Closes when and Must exist from the report's New threads line; Playbook from `planning-analysis`' list, or `none`. Its `set-bookmark` (`TODO`, `Thread`) is in the report's Database writes. Missing: call it now.
4. **Assumptions.** Retire each one the thread settled, now. Its `remove-bookmark` (`TODO`, `Assumption`) or `remove-comment` is in Database writes. Missing: call it now. Append `Assumption: retired — <assumption> — <confirmed | refuted> at <address>`.
5. **Thread line.** Answered or refuted: append `Thread NN: closed — <answer> at <address>`. Open: append `Thread NN: open — <reason> — <next read>`.
6. **Rulings.** Each departure from the plan: append `Ruling: <what> — <why> — <cost if wrong>`. Departures: a thread skipped, merged, split or reordered; a Question changed; a Must exist unwritten; the size stepped up. A time or spend why quotes the harness message in quotation marks; none: do the departed step.

## Closed or open

A `closed` line needs, in the report:
1. Evidence: the Closes when or refuted if evidence, with its address.
2. Database writes: a write for each finding in the Answer.

Writes missing: make them now. Evidence missing: write the `open` line with the reason.

## Tool failure

A call failed or timed out:
1. Retry it once, same arguments.
2. It fails again: write the call and its error text in the report's Answer.
3. Append `Thread NN: open — <call> failed twice: <error text> — <next read>`.

## Dispatch

If you can dispatch a worker that has the same analysis tools you do, choose per thread:
1. Threads sharing a function or data structure run in sequence: start the second after the first one's Thread line.
2. A thread that shares neither with another unclosed thread: dispatch it.
3. Fill `skill://working-threads/templates/thread-brief.md`: the thread's plan entry, the brief's Scope decisions and Assumptions verbatim, the program path, the workspace path, and "Write the report file; dispatch nothing yourself." Not found: send those parts.
4. The worker returns: read its `<workspace>/threads/<NN>-<slug>.md`. No file: dispatch once more. Still none: append `Thread NN: open — worker wrote no report — <next read>`.
5. Do steps 3 to 6 of Each thread. Only you write plan, ledger.

No worker: run inline.

## Common skips

| Thought | Reality |
|---|---|
| "Enough." | Closed needs the Closes when or refuted if evidence at an address. Without it, write the open line. |
| "Possibly a compromised legitimate site." | A doubt is an assumption: `set-bookmark` (`TODO`, `Assumption`), and in the report. The answer carries it. |
| "Come back to that later." | Inside the question: read it now. Outside: a `TODO` bookmark and a discovered thread, now. |
| "It timed out; move on." | Retry once. Fails again: the thread is open with the error text. |
| "I'll annotate at the end." | Write the name, comment or bookmark before the next read. |
| "Mark the remaining ones done." | A `Thread NN:` line comes from that thread's report. Your harness's task list, if it has one, follows the ledger. |
| Thinking never written down | The thread file and its ledger line are the record. Write both before the next thread. |

## After the last thread

Every thread in `<workspace>/plan.md`, discovered ones included, has a `Thread NN:` line. Missing: work that thread.

Next reply: read `verifying-findings`, alone, before any other call.
