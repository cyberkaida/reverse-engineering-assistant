---
name: deep-analysis
description: Use when one question about a program in Ghidra needs an answer - what one function does, what is at one address, whether one behaviour is present, where one value comes from, or the types in one function. Used alone for a single question, and by `working-threads` once per thread.
---

# Deep Analysis

One question, one loop. Input: a question and a starting point (address, symbol, string or import). Output: the answer with evidence and the database writes; under `working-threads`, also a `## Thread report`. Pass the `programPath` to every call.

A single question writes no workspace files. The database is the record.

## Start

1. Write the question and its starting point in one line.
2. Write what closes it: the evidence you expect to read, and what would refute it.
3. Starting point is an import: call `find-import-references`. A string: get its address with `get-strings`, then `find-cross-references` with `direction` `to`, `includeContext` true. The referencing function is the start.
4. Single question after a survey: its `## Candidate threads` line gives the start address.
5. The question matches a strategy in `strategies.md` (what X does, crypto, network, types, decode a blob, recover a structure): read it now and follow it inside the loop.

## The loop

Repeat until Thread end holds.

1. **Read.** `get-decompilation` with `limit` 50 and `includeIncomingReferences` true. For data, `get-data` or `read-memory`. Paging applies.
2. **Understand.** One line each: what the code does, what is unclear, what you assume (Hypotheses).
3. **Improve.** Write every decision now (Improve at once).
4. **Verify.** Call `get-decompilation` again. A new cast or a worse line: fix the type, re-read.
5. **Follow.** Choose the next read: the callee that produces the value, the callers' inputs, or the references to a string or constant.
6. **Record.** Add an evidence line: address, then the pattern, constant or code seen there. A lead outside the question: `set-bookmark` with `type` `TODO`, `category` `Thread`, the question as `comment`; add it to new threads; return to the question.

## Rules

### Thread end

A thread ends one of four ways. Under `working-threads`, write the thread report.
- **Answered:** the closing evidence is in hand, with its address.
- **Refuted:** a read showed the expectation false. Write what was read, and where.
- **Open:** write `open — <reason> — <next read>`. The reason is a tool result: every `patterns.md` shape tried on the decoder, a call that failed twice, a program not loaded. Time and spend are a reason only when a harness message states them.
- **Bigger:** a single question needs another first. Say so; Then read `scoping-analysis`.

### Improve at once

Every name, type, comment and bookmark you have decided is written before your next read.
- Names: `rename-variables` for locals; `set-function-prototype` for the function.
- Comments: `set-decompilation-comment` or `set-comment`. Bookmarks: `set-bookmark`.

Name a function after its body was read in this thread. A name or comment states what you read. A guess follows Hypotheses.

### Paging

A page that shows only the signature and local declarations is not a read.
1. Call `get-decompilation` again with `offset` set to the next line number (after `limit` 50 from line 1: `offset` 51, `limit` 50).
2. Write `offset` into the call's arguments.
3. Page until the lines that answer the question are seen.

Lines you skipped are unread. Page them before Thread end.

### Callee

A value you report (string, key, address, URL, size, command) is traced to the code that produces it.
1. Find the call that returns or fills the value.
2. Decompile that callee.
3. It only concatenates, copies, formats or looks up: not the producer. Find where its inputs come from (`get-callers-decompiled`) and decompile that function.
4. The producer computes the bytes: it decodes, decrypts, reads a file or the network, or holds the literal. Name it and comment it at once.

### Negative findings

"Not present" is a finding only after the functions that would do it were read.
1. List the candidates: imports for the capability, run-time loaders (`GetProcAddress`, `dlsym`), related strings, callees of each entry point.
2. Read each candidate function.
3. Write the finding with what was checked: `no <capability>: read <functions>; checked <imports, strings>`.

From the import list alone, write "not imported", and keep reading.

### Tool surprise

A result surprises you (wrong lines, empty, an error, an argument seemingly ignored):
1. Re-read the arguments of your own call. A missing or misspelt argument: fix it and call again.
2. The call failed or timed out: retry it once, same arguments. Retry each failed call of a batch.
3. It fails again: write the call and its error as an open item, and go to the next read.

A tool is at fault only when step 1 shows the argument was in the call.

### Typing tools first

Change types with ReVa's tools, in this order:
1. `parse-c-structure`: define a structure (it replaces one of the same name).
2. `apply-structure` or `apply-data-type`: type data.
3. `change-variable-datatypes`: type locals.
4. `set-function-prototype`: type parameters and return.

A script comes after one of these returns an error that Tool surprise could not fix. A script to write: Then read `pyghidra-scripting`.

### Hypotheses

A guess goes into the database in one of two forms:
- `set-bookmark` with `type` `TODO`, `category` `Assumption`, `comment` `assumption: <guess> — check: <read that settles it>`.
- `set-comment` whose text starts `assumption: `.

A read settles it:
- Confirmed: write the name or fact, then retire it.
- Refuted: retire it; write what is true.

Retire: `remove-bookmark` (`type` `TODO`, `category` `Assumption`) or `remove-comment`.

## Common wrong conclusions

| Jump | Check that settles it |
|---|---|
| "This helper builds the strings, so they are plaintext." | A concatenator is not the decoder. Follow its callers' inputs to the producer (Callee). |
| "Dead code" or "leftover" | Decompile each callee, and call `find-cross-references` `to` on the function. Write what the callee does. |
| "I don't recognise this CLSID, GUID or constant." | Follow what the program does with it: the call it is passed to, and the methods or offsets used on the result. |
| "Only one import." | Call `analysis-status`. When analysis has completed, call `list-imports` again. |
| A family or algorithm named from memory | Match the decoded markers (strings, constants, command names, tables) against each candidate. Write which candidates were excluded, and by which marker. |

## Thread report

Under `working-threads`, when the thread ends, write `## Thread report` with these parts:
1. Answer: one or two sentences.
2. Confidence, with the reason. High: the producing code was read and the bytes match. Medium: one link is a database assumption. Low: a pattern only; the thread is open.
3. Evidence: one line each, an address and the pattern, constant or code seen there.
4. Database writes: each name, type, comment and bookmark, with its address.
5. Assumptions created or retired.
6. New threads: question and starting address, each also a `TODO` bookmark.

A single question ends with the answer in the form the user asked for, followed by the evidence and the database writes.

Examples: `examples.md`. Code and algorithm patterns: `patterns.md`.
