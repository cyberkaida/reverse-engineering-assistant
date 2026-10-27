# CLAUDE.md - Scripts Tool Provider

This package provides MCP tools for writing, reading, editing, and running Ghidra Python scripts via the PyGhidra runtime. Modeled after Claude Code's Read/Write/Edit ergonomics for chunked numbered reads and targeted in-place edits.

## Tools (5)

| Tool | Purpose |
|------|---------|
| `run-script` | Execute Python in current Ghidra/PyGhidra runtime against a program (inline `code` or by `scriptPath` / `scriptName`). |
| `list-scripts` | Enumerate scripts across registered script directories (user + system + bundle). |
| `read-script` | Return `cat -n` style numbered output; supports `offset` / `limit` and `truncated` flag. |
| `write-script` | Create new file or full overwrite (explicit `overwrite: true`); user dir only. |
| `edit-script` | Targeted `old_string` → `new_string` replacement; errors on ambiguity unless `replace_all`. |

## PyGhidra availability gate

`run-script` requires Ghidra to be launched via PyGhidra. The standard `ghidraRun` GUI does **not** wire `PyGhidraScriptProvider.scriptRunner`, so `getScriptInstance()` throws `GhidraScriptLoadException`. We surface this as `PyGhidraNotAvailableException` → MCP error with launch guidance ("use `pyghidra-gui` or `mcp-reva`").

Working configurations:
- `mcp-reva` CLI (headless via PyGhidra)
- `reva_headless_server.py` (headless via PyGhidra)
- `pyghidra-gui` (GUI via PyGhidra)

The other four file-management tools work in every mode.

## Architecture (4 classes + helpers)

| Class | Role |
|-------|------|
| `ScriptToolProvider` | Registers the 5 tools; glues helpers together. |
| `PythonScriptExecutor` | Owns the availability wait, the run's parent transaction, capping + timing + error capture, and leaked-transaction cleanup; delegates Ghidra calls to an injected `ScriptRunner`. Unit-testable without PyGhidra. |
| `PythonTracebacks` | Extracts the final exception line from captured stderr (type + message, continuation lines joined, capped at 200 chars) so a Python failure's `error` says what failed. |
| `TransactionCleanup` | `snapshot(program)` before the run (open `TransactionInfo` or null, plus its open-entry count); `closeLeaked(program, snapshot, analysisRunning)` after: ends the entries the script left open, whose changes follow the run's parent entry (committed on a clean run, rolled back when it failed); returns an `Outcome` (entries ended, terminated-and-unclosable, rolled back, left open for running analysis). |
| `GhidraScriptRunner` | Production `ScriptRunner` — `GhidraScriptUtil.getProvider()` + bundle host refcount + `GhidraState` + `script.execute()`. Boundary class; covered by integration / Python-e2e tests. |
| `ScriptDirectoryManager` | Read/write directory model + path containment guards (`isInsideReadableDirectory` / `isInsideWriteableDirectory`). |
| `ScriptFileEditor` | Pure helpers for `cat -n` rendering and `old_string`/`new_string` editing. |
| `CappedWriter` | `Writer` wrapper that drops bytes past a cap and reports `isTruncated`. |
| `GhidraDirectoryFactory` | Builds `ScriptDirectoryManager` from live Ghidra (defensive: falls back to user dir alone if `bundleHost` is null). |
| `PyGhidraNotAvailableException` | Checked signal that Python is unwired. |
| `reva.tools.ProgramBusyException` (in `reva.tools`) | Result error of a refused run, carrying the reason the program was still busy; `buildRunResult` turns it into `busy: true`, `transaction: "refused"` and wait-then-retry guidance. |

## Execution flow (`run-script`)

1. Resolve source: inline `code` → temp file with `# @runtime PyGhidra` header; or `scriptPath`/`scriptName`.
2. `GhidraScriptUtil.acquireBundleHostReference()` (defensive bracket; refcounted, idempotent).
3. `GhidraScriptUtil.getProvider(scriptFile)` → expect `PyGhidraScriptProvider`. `UnsupportedScriptProvider` or `null` → `PyGhidraNotAvailableException`.
4. Build `GhidraState` via copy-constructor — prevents plugin events firing while the script mutates state.
5. `TimeoutTaskMonitor.timeoutIn(timeoutSeconds, SECONDS)`.
6. `script.execute(scriptState, new ScriptControls(stdoutPw, stderrPw, monitor))`.
7. Capture stdout/stderr via `CappedWriter`-backed `PrintWriter` (default cap 64K chars per stream).
8. Always `releaseBundleHostReference()`; always delete temp file if any.
9. `PythonScriptExecutor` waits up to 30 s (`DatabaseAvailability.awaitModifiable`) for an open transaction or running auto-analysis to clear, and refuses only when it does not — the refusal is a `ProgramBusyException`, rendered by `buildRunResult` as `busy: true` / `transaction: "refused"`. Otherwise it records `TransactionCleanup.snapshot`, opens one parent transaction (`run-script: <file>`), runs the runner, samples `getCurrentTransactionInfo().getStatus()` for `NOT_DONE_BUT_ABORTED` (a script that ended an entry with `commit=false`), flushes the error writer, treats a Python traceback there as a failure (PyGhidra catches Python exceptions and returns normally), and ends the parent entry with `commit = (no Java exception && no Python traceback && !monitor.isCancelled() && !aborted)`, and only then calls `TransactionCleanup.closeLeaked` — all in a `finally`, so a thrown `Error` cannot leave the entry open. An observed abort becomes a synthetic `executionError` (unless a `forceLock` termination already explains it) and `transactionRolledBack: true`, so an aborted run reports `success: false` even when the script left no entry open. The parent entry commits as a single undo entry; `commit=false` aborts the whole transaction, so everything the script did rolls back. The count of closed leaked entries lands in `Result.leakedTransactions`; when positive, `buildRunResult` adds `transactionLeaked: true` and appends a note to `stderr` ("changes were committed", or "changes were rolled back" when `Result.transactionRolledBack`: the transaction's status was `NOT_DONE_BUT_ABORTED` because the run failed or an entry had been ended with `commit=false`). The `transaction` field reports the outcome, not the parent's flag alone: `open` when a transaction was left to auto-analysis, else `committed` only when `Result.parentCommitted` and not `Result.transactionRolledBack`, else `rolled back` (the executor never commits the parent entry of an aborted run, and an abort is detected before that commit). When a run rolled back without leaking an entry, `buildRunResult` appends the aborted-run note instead of the leak note. A terminated transaction it could not close lands in `Result.transactionTerminated` and becomes `transactionTerminated: true` plus its own stderr note. A transaction left alone because auto-analysis is running lands in `Result.transactionLeftOpen` and becomes `transactionOpen: true` plus the stderr line "A transaction is still open while auto-analysis runs; ReVa did not close it." `success` is unchanged.

## Key design decisions

- **One parent transaction per run, all-or-nothing.** `GhidraScript.execute()` does not open a transaction, so the executor opens one itself (`run-script: <file>`) after the availability wait and after the cleanup snapshot. It is ended *before* `closeLeaked` runs, so cleanup never ends the parent entry. A clean, non-cancelled exit ends it with `commit=true`: every edit the script made is one undo entry. An exception, a Python traceback PyGhidra swallowed into stderr, or a timeout ends it with `commit=false`, which aborts the whole transaction (Ghidra: any entry ended with `commit=false` aborts all entries), so nothing the script did survives — the failed run is not half-applied. Scripts may still open their own transaction; their entries join the same unit and a script's own `endTransaction(false)` aborts the run's unit as well. Because the transaction status is sampled (`NOT_DONE_BUT_ABORTED`) before the parent entry is ended, that case is reported as a failure — synthetic `executionError`, `success: false`, `transactionRolledBack: true`, `transaction: "rolled back"`, plus a stderr note — even when the script leaves no entry open and `closeLeaked` sees nothing to do. `forceLock` also reads as aborted but is reported through `transactionTerminated` instead, since its outcome is not necessarily a rollback.
- **Busy program: wait, then refuse — never stack.** When a transaction is already open (a sibling `run-script` call, a direct-write tool, a background `analyze-program` job, an unfinished script from an earlier call) or auto-analysis is running, `execute` polls `DatabaseAvailability.awaitModifiable(program, analysisRunning, awaitMs, pollMs)` for up to 30 s (200 ms polls; both injectable for tests) before giving up. Trial 3 showed the instant refusal was wrong: all 27 busy refusals were sibling `run-script` calls that finished seconds later, and the model answered every one with an immediate retry. Only a program still busy at the deadline — or a save lock, which is only observable by attempting `startTransaction` — yields the `ProgramBusyException` result, which `buildRunResult` marks `busy: true`, `transaction: "refused"` (not "rolled back": no transaction was started) and an `error` naming the reason plus "wait for the in-flight operation to finish, then call run-script again … do not retry in a tight loop". Joining someone else's transaction would still make this run's undo entry and rollback depend on theirs, so a transaction that appears between the wait and the start is refused the same way, as is one that our own entry joined (detected by open-entry count). A `TerminatedTransactionException` (read-only or force-terminated program) is *not* busy — retrying cannot help — and keeps a plain `IllegalStateException` result. This is why `closeLeaked`'s pre-open-transaction counting cannot be reached through `execute`; `TransactionCleanupTest` exercises it against `closeLeaked` directly.
- **Failures say what failed.** PyGhidra's only failure signal is the traceback it prints to stderr, so for a traceback-carrying run `buildRunResult`'s `error` is `Python exception: <line>`, where `PythonTracebacks.summary` reduces the text to the final exception line: type and message, continuation lines (Jython's "options are:" overload list) joined with spaces, whitespace collapsed, capped at 200 chars, and the last traceback of a chain wins. A traceback with no recognizable exception line falls back to the last non-empty stderr line. Other errors keep `SimpleName: message`, with a null message rendered as `SimpleName: (no message; see stderr)` — `PyExceptionProxy: null` must never reach the model again.
- **Leaked entries are closed and reported.** A script that throws between `startTransaction` and `endTransaction` used to leave the program locked: every later `checkin-program` failed with "Unable to lock due to active transaction" and the final save lost the session. The executor therefore still ends any entry the script left open after the parent entry is done, and the result carries `transactionLeaked: true` so the model learns to use try/finally. Which changes survive follows from the parent entry: a clean run's leaks are committed with it, a failed or timed-out run's are rolled back with the aborted transaction (`transactionRolledBack: true`).
- **How the leak is closed (Ghidra internal dependency).** `TransactionInfo.getID()` is the *database* transaction id (a `long`), not the per-call id `endTransaction(int, boolean)` takes, and Ghidra has no public way to list open per-call ids. `closeLeaked` opens and ends one probe entry of its own, then walks down from `probe - 1` calling `endTransaction(id, true)` until no transaction is open or 64 attempts; `IllegalStateException` (already ended / not found) means "keep walking". This relies on per-call ids within one transaction being consecutive (`DomainObjectDBTransaction.addEntry`), identical in Ghidra 12.1.3 and 12.2. `TransactionCleanupTest.nestedLeakIsClosed` pins it. Hitting the 64-attempt bound with the transaction still open logs a warning.
- **Entry counting when a transaction was already open.** When the same `TransactionInfo` (identity) is still open after the run with more open entries (`getOpenSubTransactions().size()`) than the snapshot, exactly the extra N entries are ended, walking down from the probe and stopping after N ends: the walk ends the newest first, so the entries that were open before stay untouched. Fewer or equal entries: nothing is touched. When no transaction was open before (or the one that was has since ended), every open entry was opened during the run and the walk ends them all — the case `execute` always takes, since it refuses to start while a transaction is open; the counted branch stays for a transaction another writer opens mid-run and is covered against `closeLeaked` directly.
- **Running auto-analysis is not walked.** In the GUI a script that creates functions sets off background auto-analysis, whose command holds a transaction entry for its whole run. When nothing was open before the script, a transaction is open after it, and `AutoAnalysisManager.hasAutoAnalysisManager(program) && getAnalysisManager(program).isAnalyzing()` (both present in 12.1.3 and 12.2), the walk is skipped and the result reports `transactionOpen: true` instead (a leak by the script in that window stays open too). The check is not made when a transaction was open before: the `analyze-program` job is itself auto-analysis, and its entry is protected by the count instead. Tests inject the check through the package-private `PythonScriptExecutor(runner, analysisRunning, awaitMs, pollMs)` constructor.
- **Known limitation.** Ghidra records no owner (thread or caller) for a transaction entry, so entries another thread opened during the run (a concurrent MCP tool call) look like the script's and may be ended and reported as its leak; concurrent writers to the program during a script run are not supported.
- **Terminated transactions.** If the script terminated its transaction (`forceLock`), Ghidra refuses the probe, so the transaction cannot be closed: the result carries `transactionTerminated: true` and a stderr note instead.
- **`GhidraState` copy-constructor.** Suppresses plugin event broadcast during script execution; matches `PyGhidraPlugin` behavior at `script.set(new GhidraState(state), ScriptControls.NONE)`.
- **Inline `code` → temp file**, never written to the user scripts dir. `# @runtime PyGhidra` header pins the provider.
- **Output cap.** Default 64K chars per stream; per-call override unsupported (use `Script Output Char Limit` config). Synchronous capture only; no progress streaming.
- **Argument errors name the fix.** `run-script` validates `code`/`scriptName`/`scriptPath` (exactly one) before resolving the program, and the message lists which were given. `resolveWriteTarget` / `resolveReadTarget` and `run-script` (before `validateRunSources`) all go through `mergeBareName`: a `scriptPath` with no `/` or `\` is a `scriptName` (default write directory for writes, the script directories for reads and runs, never the JVM cwd); equal name and bare path are accepted, a different name and bare path are reported as two sources. A missing name says where files go; an outside-directory refusal lists the writeable directories and suggests `scriptName: "<basename>"`. `write-script` returns `run` (`tool`, `scriptName`, optional `programPath` echoed from an optional `programPath` arg) and `note` so the model can call `run-script` directly. Tests in `ScriptToolProviderTest` call the registered handlers through a captured `SyncToolSpecification`.
- **Write safety.** `write-script` and `edit-script` refuse any path outside a registered writeable directory. System script directories (under Ghidra install root) are read-only.
- **PluginTool.** Pulled from `McpServerManager.getActiveTool()` (null in headless). The injection point is a `Supplier<PluginTool>` so tests can mock.

## Configuration

Two `ConfigManager` keys back the executor:

| Key | Default | Effect |
|-----|---------|--------|
| `SCRIPT_TIMEOUT_SECONDS` | 60 | Default per-call timeout (overridable via `timeoutSeconds` arg). |
| `SCRIPT_OUTPUT_CHAR_LIMIT` | 65536 | Per-stream truncation cap (stdout and stderr independent). |

The provider holds `Supplier<Integer>` references rather than cached ints so live config edits take effect on the next call.

## Testing strategy

| Layer | What it tests |
|-------|---------------|
| Java unit (`src/test/java/reva/tools/scripts/`) | Capping, exception types, directory containment, render/edit logic, executor wrapper behavior (mocked `ScriptRunner`), tool registration / schema; `TransactionCleanupTest` runs stub runners against a real headless `ProgramDB` to check the parent transaction (a failed run rolls its edits back), leak cleanup (including inside an outer transaction, rollback status, and a stubbed running analysis), and the `transactionLeaked` / `transactionOpen` / `transaction` results. The bounded availability wait (writer clears / deadline expires), the raise rendering (`busy`, `transaction: "refused"`, parsed `Python exception:` line, `(no message; see stderr)`) and the parent open/commit/abort calls are pinned with a mocked `Program` in `PythonScriptExecutorTest`, `PythonTracebacksTest` and `ScriptToolProviderTest` |
| Java integration (`src/test.slow/java/reva/tools/scripts/`) | `list-scripts` / `read-script` / `write-script` / `edit-script` end-to-end via MCP client + real filesystem; `run-script` error path (gradle JVM has no PyGhidra, so this confirms the friendly-error guidance is correct) |
| Python e2e (`tests/test_run_script_e2e.py`, marked `@pytest.mark.e2e`) | Real Python execution via `mcp-reva` subprocess: stdout capture, `currentProgram` binding, exception capture, `timeoutSeconds` cutoff, write→run round-trip |

Real Python execution cannot be tested in the gradle integration JVM because it is not launched via PyGhidra; the e2e harness is the only place this path is exercised.

## Gotchas

- **`GhidraScriptUtil.bundleHost == null`** in some contexts (gradle test JVM, some headless flows). `GhidraDirectoryFactory.build()` falls back to just user + system dirs when bundleHost is unset.
- **Tests must clean up `~/ghidra_scripts/`** — the integration tests use the live user scripts directory. Use unique fixture prefixes and delete in `@After`. (See `ScriptToolProviderIntegrationTest.FIXTURE_PREFIX`.)
- **`PyGhidraScriptProvider.setScriptRunner()` throws if called twice.** A test cannot install a fake runner in a JVM where the real one is already installed. We rely on forkEvery=1 to isolate JVMs.
- **`InterpreterConsole.getStdin()` is not viable** for injecting code; `IPStdin` is package-private. Temp-file + provider is the only public path.
