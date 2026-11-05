---
name: finishing-analysis
description: Use when the threads for a program in Ghidra are verified (`Verify NN:` lines in `<workspace>/ledger.md`) and the answer is not yet sent; when the closing evidence for the main question is in hand; or sent here by `verifying-findings` or `reverse-engineering`.
---

# Finishing Analysis

Input: `<workspace>/brief.md`, `<workspace>/plan.md`, `<workspace>/ledger.md`, `<workspace>/threads/`, `<workspace>/verify/` if it exists, and the files the threads wrote (`detection/`, `decoded/`, `carved/`, `notes/`, `scripts/`). Output: the database reconciled and checked in, `<workspace>/report.md`, and the answer in your reply. Pass the `programPath` to every call.

## When to finish

Read the brief's Done-when. A line is met when its annotation or value is in the database at its address; the deliverable line is met by Reconcile.

Budget left: no user or harness message says the time or spend is used.

An open thread is a plan thread with fewer than two `refuted` or `unverifiable` `Verify NN:` lines whose latest `Thread NN:` line is `open` or whose latest `Verify NN:` line is `unverifiable`.

| Brief and ledger show | Do |
|---|---|
| Any of `<workspace>/brief.md`, `<workspace>/plan.md` or `<workspace>/ledger.md` missing | Then read `scoping-analysis`. |
| A closed thread with no `Verify NN:` line after its latest `Thread NN:` line | Then read `verifying-findings`. |
| Every Done-when line met | Run Reconcile. |
| An unmet Done-when line; no budget left, or its thread says `failed twice`, or two of its `Verify NN:` lines are `refuted` or `unverifiable` | Write it as `unmet: <line> — <reason>` in Answer and Open threads. Then the next row; no match: Run Reconcile. |
| An open thread Done-when covers; budget left | Work the thread (below). |

To work a thread: Unverifiable: first append `Thread NN: open — unverifiable: <check> — <next read>`. Append it to `<workspace>/plan.md` if it has no entry. Then read `working-threads`.

## Report first, then confirm

Closing evidence is a read at an address.

1. Run the gates above; if they route, stop. Otherwise write `<workspace>/report.md` from the template now, before any further confirming call.
2. Each check you still want: a line under Open threads, `<check> — <next read>`.
3. Then go to When to finish.

## Reconcile

Run all seven, in order.

1. **Retire.** Call `search-bookmarks` with `types` [`TODO`], and `search-comments` with `searchText` `assumption:`. Each item the ledger settles (an `Assumption: retired` line, or its thread's latest `Verify NN:` line is not `unverifiable`): call `remove-bookmark` at its address with `type` `TODO` and its `category`, or `remove-comment` with its `commentType`.
2. **Present.** Each value in the latest `Thread NN: closed` and `Verify NN:` lines, and in `<workspace>/report.md` if written: call `get-comments` and `get-bookmarks` with `addressOrSymbol` its address; for names, `get-symbols` with `filterDefaultNames` true, paging with `startIndex`. Nothing there: write it with `create-label`, `set-comment`, or `set-bookmark` (`type` `Note`, `category` `Finding`). Copy each address from the tool result that shows it, digit for digit.
3. **Read all bookmarks.** Call `get-bookmarks` with no `addressOrSymbol`, `type` or `category`, and `maxResults` 1000. `truncated` true: call again with `maxResults` 5000. Each `Note` and `TODO` bookmark's lead goes into Evidence with addresses or Open threads.
4. **Summary bookmark.** Call `set-bookmark` at the entry point, `type` `Note`, `category` `Survey`, `comment` the conclusion in one paragraph, replacing the survey text.
5. **Check in.** Call `checkin-program` for each program you wrote to, `message` one line: the conclusion. Fails: call again. Fails twice: write the error text under Database state.
6. **Report.** Every Answer thread needs a `Verify NN:` line; missing: Then read `verifying-findings`. Run Budget check. Read `skill://finishing-analysis/templates/report.md` and fill every slot. Confidence: the lowest `High|Medium|Low` in each used thread's latest Verify line. Unverifiable or refuted threads go under Open threads. Write `<workspace>/report.md`.
7. **Answer.** If the user or a harness message states a format, write exactly that format: every heading and line it names, in its order. Otherwise answer in the form the request implies. The answer goes in your reply, from `<workspace>/report.md`. It carries the report's unmet lines and open threads. Every address in your reply is in Evidence with addresses.

## Budget check

If the brief recorded a budget and the ledger shows fewer than half the threads closed, say what is unfinished rather than widening the claim:
1. Answer starts `Partial: <closed> of <total> threads closed.`
2. Each unclosed thread goes under Open threads, with its next read.
3. Confidence covers the closed threads only.

## Common skips

| Thought | Reality |
|---|---|
| "One quick call, then I write the answer." | Write the report now. The call is an Open threads line. |
| "I have plenty." … "But I am confident." | Confidence is not Done-when. Budget left and a covered open thread: work it. |
| "Fix types where it matters most." | Done-when sets the scope. Unmet lines are written as unmet. |
