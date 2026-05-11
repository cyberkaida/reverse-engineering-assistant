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
| `PythonScriptExecutor` | Owns capping + timing + error capture; delegates Ghidra calls to an injected `ScriptRunner`. Unit-testable without PyGhidra. |
| `GhidraScriptRunner` | Production `ScriptRunner` — `GhidraScriptUtil.getProvider()` + bundle host refcount + `GhidraState` + `script.execute()`. Boundary class; covered by integration / Python-e2e tests. |
| `ScriptDirectoryManager` | Read/write directory model + path containment guards (`isInsideReadableDirectory` / `isInsideWriteableDirectory`). |
| `ScriptFileEditor` | Pure helpers for `cat -n` rendering and `old_string`/`new_string` editing. |
| `CappedWriter` | `Writer` wrapper that drops bytes past a cap and reports `isTruncated`. |
| `GhidraDirectoryFactory` | Builds `ScriptDirectoryManager` from live Ghidra (defensive: falls back to user dir alone if `bundleHost` is null). |
| `PyGhidraNotAvailableException` | Checked signal that Python is unwired. |

## Execution flow (`run-script`)

1. Resolve source: inline `code` → temp file with `# @runtime PyGhidra` header; or `scriptPath`/`scriptName`.
2. `GhidraScriptUtil.acquireBundleHostReference()` (defensive bracket; refcounted, idempotent).
3. `GhidraScriptUtil.getProvider(scriptFile)` → expect `PyGhidraScriptProvider`. `UnsupportedScriptProvider` or `null` → `PyGhidraNotAvailableException`.
4. Build `GhidraState` via copy-constructor — prevents plugin events firing while the script mutates state.
5. `TimeoutTaskMonitor.timeoutIn(timeoutSeconds, SECONDS)`.
6. `script.execute(scriptState, new ScriptControls(stdoutPw, stderrPw, monitor))`.
7. Capture stdout/stderr via `CappedWriter`-backed `PrintWriter` (default cap 64K chars per stream).
8. Always `releaseBundleHostReference()`; always delete temp file if any.

## Key design decisions

- **Scripts manage their own transactions.** `GhidraScript.execute()` does not open a transaction; this tool deliberately does not wrap one (avoids nested-tx footgun). Document the requirement in the `run-script` description.
- **`GhidraState` copy-constructor.** Suppresses plugin event broadcast during script execution; matches `PyGhidraPlugin` behavior at `script.set(new GhidraState(state), ScriptControls.NONE)`.
- **Inline `code` → temp file**, never written to the user scripts dir. `# @runtime PyGhidra` header pins the provider.
- **Output cap.** Default 64K chars per stream; per-call override unsupported (use `Script Output Char Limit` config). Synchronous capture only; no progress streaming.
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
| Java unit (`src/test/java/reva/tools/scripts/`) | Capping, exception types, directory containment, render/edit logic, executor wrapper behavior (mocked `ScriptRunner`), tool registration / schema |
| Java integration (`src/test.slow/java/reva/tools/scripts/`) | `list-scripts` / `read-script` / `write-script` / `edit-script` end-to-end via MCP client + real filesystem; `run-script` error path (gradle JVM has no PyGhidra, so this confirms the friendly-error guidance is correct) |
| Python e2e (`tests/test_run_script_e2e.py`, marked `@pytest.mark.e2e`) | Real Python execution via `mcp-reva` subprocess: stdout capture, `currentProgram` binding, exception capture, `timeoutSeconds` cutoff, write→run round-trip |

Real Python execution cannot be tested in the gradle integration JVM because it is not launched via PyGhidra; the e2e harness is the only place this path is exercised.

## Gotchas

- **`GhidraScriptUtil.bundleHost == null`** in some contexts (gradle test JVM, some headless flows). `GhidraDirectoryFactory.build()` falls back to just user + system dirs when bundleHost is unset.
- **Tests must clean up `~/ghidra_scripts/`** — the integration tests use the live user scripts directory. Use unique fixture prefixes and delete in `@After`. (See `ScriptToolProviderIntegrationTest.FIXTURE_PREFIX`.)
- **`PyGhidraScriptProvider.setScriptRunner()` throws if called twice.** A test cannot install a fake runner in a JVM where the real one is already installed. We rely on forkEvery=1 to isolate JVMs.
- **`InterpreterConsole.getStdin()` is not viable** for injecting code; `IPStdin` is package-private. Temp-file + provider is the only public path.
