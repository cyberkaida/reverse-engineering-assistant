# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the binary diff tools package.

## Package Overview

The `reva.tools.diff` package provides MCP tools for diffing two programs by wrapping Ghidra's **Version Tracking (VT)** engine. It correlates a source program against a destination program, surfaces the function/string/data differences, and (on request) transfers analysis markup — names, prototypes, datatypes, comments — from one program to the other. The heavy lifting lives in `reva.util.VersionTrackingUtil`; this package is the MCP surface plus a DomainFile-backed session store (with an in-memory cache over it).

All VT orchestration is funneled through `VersionTrackingUtil` so the tools stay thin: building correlator sequences, running them, collecting deduped function matches, computing unmatched functions, and accepting/applying markup all live there.

## Source vs Destination Orientation

The single most important rule in this package:

- **source** = the analyzed/reference program (the one you trust: named functions, good prototypes, comments).
- **destination** = the variant being analyzed (the stripped/patched/newer build you want to understand).
- **Markup transfers source → destination.** "Changes" are always described relative to source (added = present only in destination, removed = present only in source).

`putPairProperties()` encodes this in every tool's schema: `sourceProgramPath` is "the trusted/analyzed/old program (markup flows FROM here)" and `destinationProgramPath` is "the variant/new/patched program (markup flows TO here)." Getting orientation backwards silently writes the wrong names into the wrong program, so the descriptions are deliberately blunt.

## The Thirteen Tools and the Funnel

`DiffToolProvider.registerTools()` registers thirteen tools. They form a read-then-write funnel:

**Setup**
- `diff-create-session` — Correlate the two programs with VT and persist the result. Expensive (minutes on large binaries); idempotent reuse if the correlator selection matches the persisted session, unless `force=true`. Runs a **scoped-staged** correlator sequence: each correlator in the sequence runs only over the **still-unmatched residual** (source/dest function bodies not yet matched) and the DomainFile is saved after each stage. This makes large-image correlation tractable (tens of thousands of functions) — running every correlator over the full loaded address set generates a combinatorial match-object graph that OOM-stalls the heap; scoping to the residual avoids that blow-up. Optional `correlators` array picks/orders the VT correlators (omit for the default sequence; drop `symbol-name` to diff by structure/bytes when names are stripped or untrusted). Optional `sourceScope`/`destinationScope` (arrays of function names or addresses; omitted ⇒ all functions, then per-stage residual scoping) let the agent choose WHERE to correlate up front (independent per side, since names/addresses shift across versions); an unresolved identifier errors naming it. Returns summary counts. *Runs as a background job — see Async Model below.*
- `diff-add-correlator` — Run one more VT correlator over the existing session's still-unmatched residual (or an agent-chosen scope) and persist. Enables a refine workflow: correlate broadly with `diff-create-session`, read the residual (`diff-list-functions category=removed/added`), then aim a sharper correlator at a chosen subset. Params: `correlator` (REQUIRED — one key from `CORRELATOR_KEYS_AVAILABLE`), optional `sourceScope`/`destinationScope` (arrays of function names or addresses; omitted ⇒ current residual), `waitSeconds` (default 10). *Runs as a background job (`DiffJobKind.ADD_CORRELATOR`) — see Async Model below.*

**Read / orient**
- `diff-summary` — Counts plus a ranked teaser of the most-changed matched functions (lowest similarity first), each tagged with a `changeTypes` profile (see *Typed Change Profile* below). The "what changed?" entry point. `includeBodyByteChanges` (default false) adds the body-bytes recall lens. When `matched.changed == 0` **and** the body-bytes knob is off, the result carries a `hint` string pointing the agent at `includeBodyByteChanges=true` — so "0 changed under the precision lenses" isn't mistaken for "no changes" (operand/control-flow tweaks VT scores identical are caught only by the recall knob). The hint is omitted when the knob is on or when `changed > 0`. Separately, if most matched functions have **1-address bodies** (the program was imported without disassembly), the result carries an `analysisWarning` — the `size`/`body-bytes` lenses are blind on un-disassembled bodies, so "0 changed" there means "run `analyze-program` first," not "no changes" (the body-bytes hint is suppressed in that case).
- `diff-list-functions` — Paginated list of function diff rows for one `category` (`changed` / `added` / `removed` / `identical`). Each matched row carries the `changeTypes` profile (`sizeDelta`, `calleeChanges`) plus similarity and correlator — no bodies. Honors `includeBodyByteChanges`.
- `diff-function` — Side-by-side decompiler diff for one matched function pair: changed-line snippets, similarity, matching correlator, both signatures, and the full `changeProfile` (body-bytes always included — cheap for one function).

**Signals**
- `diff-strings` — Added/removed defined strings between source and destination (signal for signature updates and C2/protocol changes).
- `diff-data` — Added/removed defined non-string data (by representation + address).

**Write (mutate destination)**
- `diff-transfer-markup` — Auto-apply VT markup from source to destination for every match at/above a confidence floor, in a transaction. Returns applied matches and below-floor proposals for selective review. *Runs as a background job — see Async Model below.*
- `diff-apply-match` — Apply VT markup for exactly one matched function pair (a proposal the agent chose), by source/destination address.

**Background jobs / polling**
- `diff-status` — Long-poll a running diff job by `jobId` (or by the source+destination pair). Returns new log lines since a `sinceLogSeq` cursor. When the job reaches a terminal state, also returns the job's full result: the session summary for a `create-session` or `add-correlator` job, or the applied/proposed markup for a `transfer-markup` job.
- `diff-cancel` — Request async cancellation of a running diff job by `jobId`. Poll `diff-status` until the status is `cancelled`. A cancelled `transfer-markup` job rolls back all changes (all-or-nothing).

**Housekeeping**
- `diff-list-sessions` — List persisted sessions (pairs + correlators run). Sessions are kept durably until explicitly deleted.
- `diff-delete-session` — Permanently delete a persisted session. This is the **only** thing that removes a session — sessions are never auto-deleted.

The intended flow: `create-session` → `summary` → `list-functions` → `function` (drill in); `strings` / `data` for orthogonal signals; `transfer-markup` / `apply-match` to write findings back; `diff-add-correlator` to refine unmatched residual with additional correlators; `list-sessions` / `delete-session` to manage the session store. For large binaries: poll `diff-status` after `create-session`, `add-correlator`, or `transfer-markup`, and use `diff-cancel` to abort if needed.

## Async Model

`diff-create-session`, `diff-add-correlator`, and `diff-transfer-markup` submit their work as cancellable background jobs rather than blocking the request thread. All three accept a `waitSeconds` parameter (default 10): they wait inline up to that many seconds before returning. Small binaries finish within the window and return the same result shape as before (backward-compatible). Large binaries return `{status: "running", jobId, log, logCursor}` when the inline wait expires.

**Polling**: call `diff-status` with the returned `jobId` (or equivalently with the source+destination pair) and pass `sinceLogSeq` from the previous response to receive only new log lines. When the job terminates the response includes the full result (summary or markup). **Cancellation**: call `diff-cancel` with the `jobId`, then poll `diff-status` until `status == "cancelled"`. A cancelled `transfer-markup` rolls back atomically — all-or-nothing.

Key behavioral notes:
- **Serialized worker**: all correlation, add-correlator, and markup-transfer jobs run on a single shared daemon worker (these are memory-heavy operations), so jobs queue rather than run concurrently.
- **Survives client disconnect**: the work runs on the worker thread, not the request thread, so dropping the connection does not abort the job.
- **Real cancellation**: the worker uses a live `TaskMonitor` (the old synchronous path used `TaskMonitor.DUMMY` — no progress reporting, no cancel). The new path supports both.
- **Progress notifications during long-poll**: the inline waits (`diff-create-session`/`diff-add-correlator`/`diff-transfer-markup`) **and** `diff-status` emit an MCP `ProgressNotification` per ~250 ms tick when the caller supplied a `progressToken` (shared `AbstractToolProvider.awaitWithProgress`). This both renders client-side progress and resets the client's tool-call idle timer, so a long `waitSeconds` doesn't spuriously time out. Without this, a bare-sleep long-poll would hold the request open silently and the client would abort it.
- **Single-flight attach**: if a job of the same kind (`CORRELATE`, `ADD_CORRELATOR`, or `TRANSFER_MARKUP`) for the same source+destination pair is already running, a second call attaches to it rather than starting a new one. The `force`/`correlators` overrides on the attached call are ignored until the in-flight job finishes.
- **`cancelled` can still leave a usable session**: cancellation is checked after the work returns, so a cancel landing *after* correlation finished but before the terminal-status check marks the job `cancelled` even though a valid `DiffSession` was already persisted. A subsequent read tool against that pair may legitimately succeed — treat "cancelled" as "the job stopped," not "nothing was produced."
- **Program close cancels jobs but does not delete the session**: closing a program requests cancellation of its in-flight diff jobs, but the persisted `DiffSession` (and its `VTSession` + `Program` handles) is *not* removed on close — it survives on disk until `diff-delete-session`/`clearAll`. Sessions can be reopened from their DomainFile at any time (including after a server restart).
- **Coarse session lock**: `DiffSessionManager`'s methods are `static synchronized` (one class monitor), and `createStaged` holds it across the whole multi-minute staged correlation. So while a large correlation runs, read tools (`diff-summary`/`diff-list-functions`/`diff-list-sessions`) on *other* pairs block until it finishes. Not a deadlock (the worker awaits no caller-held lock) and `diff-status`/`diff-cancel` stay responsive (separate lock); per-pair lock striping is a deferred follow-up.

## Session Persistence

`DiffSessionManager` is a DomainFile-backed store with an in-memory cache over it, keyed by `(sourcePath, destinationPath)`. Each session is a persisted `VTSessionDB` DomainFile under the project folder `DiffSessionManager.FOLDER` (`"ReVaDiffSessions"`), one file per pair (filename derived deterministically from the pair). Because correlation can run for minutes, the session — the live `VTSession` plus both `Program` handles, paths, and the list of correlators that ran — is cached so a single correlation serves every subsequent read/write tool for that pair.

- **`get(srcPath, dstPath)`** — the read path used by `requireSession()` (which every tool except `create-session`/`add-correlator`/`list-sessions` calls to resolve its pair, and errors with a "Run diff-create-session first" message if absent). Returns the cached open session; if the cache is cold (e.g. after a server restart), reopens the session from its DomainFile (auto-opening the source/dest programs from the project); returns null if no DomainFile exists.
- **`createStaged(source, dest, factories, initialSrc, initialDst, force, monitor)`** — staged loop: runs each factory over the still-unmatched residual in sequence, saves the DomainFile after each stage. Idempotent reuse if the correlator selection matches the persisted session's `correlatorsRun`; `force=true` deletes first, then re-correlates.
- **`addCorrelator(ds, factory, scopeSrc, scopeDst, monitor)`** — runs one scoped correlator stage (null scope ⇒ current residual); saves the DomainFile after the stage.
- **`list()`** — returns `List<SessionSummary>` (`record SessionSummary(String sourcePath, String destinationPath, List<String> correlatorsRun)`); lightweight (releases any sessions it had to reopen — does not pin them).
- **`delete(srcPath, dstPath)`** and **`clearAll()`** — close + delete the DomainFile. These are the **only** removal paths; nothing prunes sessions automatically. Integration tests call `clearAll()` in teardown because the store is static and shared across the test JVM.

**Durable persistence**: sessions survive server restart. On restart the in-memory cache is empty; the first tool call for a pair reopens the session from its DomainFile. Sessions are also openable in Ghidra's native Version Tracking GUI.

**Save granularity and resumability**: the DomainFile is saved after each staged correlator, so a crash or cancel mid-sequence keeps all stages that completed. A failed or cancelled stage rolls back its own transaction; previously-saved stages survive. The agent can inspect the partial result and continue via `diff-add-correlator`.

`DiffSession` is an immutable holder: `sourceProgram`, `destinationProgram`, `sourcePath`, `destinationPath`, `vtSession`, `correlatorsRun`, and `domainFile`.

## Read / Write Split

The read tools (`summary`, `list-functions`, `function`, `strings`, `data`, `list-sessions`) never mutate program state. The write tools (`transfer-markup`, `apply-match`, and `delete-session` for the session store) do. Both write tools open **two** transactions — one on the `VTSession` and one on the destination `Program` — and end both together in a `finally`, committing only when the work completed without error. `VersionTrackingUtil.acceptAndApplyMarkup()` accepts the association and runs an `ApplyMarkupItemTask`; the caller must already hold those transactions.

## Typed Change Profile (how changed/identical is decided)

A single VT similarity verdict is not enough: VT's `SymbolName` correlator scores any name-matched pair `1.0` regardless of body, so a relocation-only patch (identical instruction bytes, one swapped call target) hides in the *identical* bucket and the agent sees "0 changed" and misses the patch. So classification is **profile-driven, not similarity-driven**.

`DiffToolProvider.changeProfile(ds, mi, includeBodyBytes)` evaluates orthogonal lenses and returns a `changeTypes` list naming which fired. A matched pair is **changed iff `changeTypes` is non-empty** (`isChanged()`); that drives the `matched.changed`/`matched.identical` counts and the `changed`/`identical` categories — `MatchInfo.isIdentical()` (similarity) is now just *one* of the lenses, not the verdict.

The lenses:
- **`similarity`** — VT structural similarity below `IDENTICAL_THRESHOLD`.
- **`callees`** — the resolved callee *symbol-name* set differs (`VersionTrackingUtil.calleeNames`, address-independent via `getCalledFunctions`). Catches call-target swaps VT scores identical; emits `calleeChanges: {added, removed}`. This is the call-target-swap fix. **Only non-default callee names are compared** — `calleeNames` skips Ghidra placeholders (`FUN_<addr>`, etc.) via `SymbolUtil.isDefaultSymbolName`, because on a fully-linked image an *unnamed* callee's address-derived name shifts between builds and would fire this lens on pure relocation noise. Named call-target swaps are still caught.
- **`size`** — the function body grew/shrank (`getBody().getNumAddresses()`); emits `sizeDelta`. Catches added/removed basic blocks (e.g. an added bounds check).
- **`body-bytes`** — raw instruction bytes differ. **Opt-in** recall knob (`includeBodyByteChanges`, default false), because it is address-*dependent*: precise on relocatable objects (functions at the same address) but noisy on fully-linked images where unchanged functions shift. Catches operand/control-flow tweaks VT scores identical (e.g. one retargeted jmp). A body that can't be fully read (`functionBytes` returns `null` — e.g. an unreadable/uninitialized range) is treated as **changed**, not silently equal (the prior empty-array compare reported "no change" for a pair it couldn't read).

**Both `size` and `body-bytes` read `getBody()`, so they depend on the program being DISASSEMBLED.** A program imported with symbols but no disassembly has 1-address function bodies, blinding these two lenses (every body looks like a single entry byte). `summarize` detects this — when most matched functions have ≤1-address bodies it emits an `analysisWarning` telling the agent to run `analyze-program` first — see *diff-summary* above. (`callees`/`similarity` and the decompiler-based `diff-function` are unaffected; the decompiler disassembles on-demand.)

**Design rule (advisor-validated): precision by default, agent-controlled recall.** `similarity`/`callees`/`size` are address-independent and scale-safe, so they are always on. `body-bytes` is the deliberate recall knob the agent enables when the precise lenses come up empty, then filters the residual itself — rather than ReVa guessing the right correlator/settings up front. Surface typed signals; let the agent interpret.

## Confidence and the IDENTICAL_THRESHOLD

`VersionTrackingUtil.IDENTICAL_THRESHOLD` is `0.9999`. It is the `similarity` lens boundary above and the default `confidence` floor for `diff-transfer-markup` (matches below the floor are returned as `proposed` rather than auto-applied). It no longer single-handedly decides changed/identical — see *Typed Change Profile*.

The default correlator sequence is intentionally conservative and precision-favoring: `SymbolName` → `ExactMatchBytes` → `ExactMatchInstructions` → `ExactMatchMnemonics` → `DuplicateFunction` → `FunctionReference`, minimum function size lowered to 1 (`VersionTrackingUtil.CORRELATOR_KEYS`). The agent can override it per-session via the `correlators` param; the **selectable** keys are `VersionTrackingUtil.CORRELATOR_KEYS_AVAILABLE` (the default sequence plus opt-in correlators), and `correlatorSequence()` builds the factory list. Changing the selection re-correlates — `DiffSessionManager.createStaged` compares the requested correlator names against the persisted session's `correlatorsRun`. Similarity-weighted narrowing and smarter auto-apply thresholds remain a deferred tuning round.

**Opt-in `combined-reference` correlator.** The default correlators are exact-match only, so a function whose *body* changed can only be matched by trusting its symbol name. `combined-reference` (Ghidra's `CombinedFunctionAndDataReferenceProgramCorrelatorFactory`, display name "Combined Function and Data Reference Match") is reference-based: it pairs functions by the data/function references they have in common, so it **can** match across body changes when call/data references are stable — useful on stripped binaries. It is **not** in `CORRELATOR_KEYS` (the default) and must be requested explicitly via `correlators` (or via `diff-add-correlator`). Honest caveat: it is reference-based, so **leaf functions with no references still won't match** — Ghidra VT has no body-similarity correlator, so a changed leaf with no refs falls into unmatched regardless.

## Scale behavior: 1:1 assignment collapses the fan-out

`collectFunctionMatches` returns a **1:1 assignment** — each source address and each destination address is used at most once. Without this, the exact correlators (minimum function size lowered to 1) pair tiny byte-identical functions **many-to-many**: one source address matches several destinations (observed live: a single `FUN_*` matched 7 destinations in a 1438-function image), inflating counts and double-counting functions (`matched.identical = 3191` against `sourceFunctions = 1438`).

The assignment is **greedy by correlator priority, then by similarity** (honestly: greedy, *not* an optimal assignment):
- Match sets are iterated in correlator-run order, so earlier sets are higher priority (`symbol-name` before `exact-bytes` etc.). This preserves correct named matches — `symbol-name` claims its addresses first.
- Within a set, FUNCTION matches are taken best-similarity-first.
- A candidate `(sa, da)` is accepted only if neither `sa` nor `da` is already taken; both are then marked taken and one `MatchInfo` is emitted. When several candidates tie at the same similarity the choice among them is arbitrary (the greedy caveat).

Consequences for the rest of the package: counts are now over **distinct functions** (a function appears in at most one matched row), so `matched.identical`/`matched.changed` no longer exceed the function count, and the `callees` lens no longer fires spuriously on arbitrarily-paired byte-identical duplicates. `summarize`/`buildRows`/`resolveMatch` all consume the deduped list, so they inherit the 1:1 guarantee for free. (Note: `diff-transfer-markup` and `diff-apply-match` keep their own `(src,dst)` dedup over raw `VTMatch` objects — they apply markup per association and are intentionally not routed through `collectFunctionMatches`.)

## Precondition: Both Programs Must Be Analyzed

VT correlates *functions*. `requireAnalyzed()` rejects any program whose function count is zero, with an explicit error: ReVa does **not** auto-analyze. `diff-create-session` checks both source and destination before correlating. If a caller hands in an unanalyzed binary, the tool errors rather than silently producing an empty diff.

## Per-Function Drill-Down Reuses DecompilationDiffUtil

`diff-function` resolves the matched pair (by name or address on either side, normalizing mid-function addresses to entry points), decompiles both sides with a decompiler configured to match ReVa's `get-decompilation` behavior (preserves unreachable code; mirrors `DecompilerToolProvider`), and feeds the two C texts to `reva.util.DecompilationDiffUtil.createDiff(...)`. The result is the same changed-line snippet structure used elsewhere in ReVa, so a function diff reads identically to a before/after decompilation diff. Always dispose the `DecompInterface` (the helpers do this in `finally`).

## Key APIs

- `VersionTrackingUtil.defaultCorrelatorSequence()` — the conservative correlator list (`= correlatorSequence(CORRELATOR_KEYS)`).
- `VersionTrackingUtil.CORRELATOR_KEYS` (default sequence) / `CORRELATOR_KEYS_AVAILABLE` (selectable: default + opt-in `combined-reference`) / `correlatorSequence(keys)` — the factory list builder for an agent-chosen selection. The schema `enum` for the `correlators` param uses `CORRELATOR_KEYS_AVAILABLE`.
- `VersionTrackingUtil.calleeNames(program, entry, monitor)` — resolved **non-default** callee symbol-name `SortedSet` (address-independent; `FUN_*`/placeholder names filtered via `SymbolUtil.isDefaultSymbolName`), the basis of the `callees` lens.
- `VersionTrackingUtil.collectFunctionMatches(session)` — **1:1** `MatchInfo` list: greedy assignment by correlator priority then similarity, each src/dst address used at most once (collapses fan-out; not an optimal assignment).
- `VersionTrackingUtil.unmatchedFunctions(program, matchedSet)` — non-external functions whose entry point isn't matched.
- `VersionTrackingUtil.unmatchedFunctionBodies(program, matchedEntries)` — `AddressSet` of bodies of functions whose entry isn't yet matched; the residual address set fed to each staged correlator.
- `VersionTrackingUtil.resolveScope(program, identifiers)` — union of named/addressed functions' bodies; throws `IllegalArgumentException` naming an unresolved identifier. Basis of `sourceScope`/`destinationScope` params.
- `VersionTrackingUtil.runOneCorrelator(session, source, srcSet, dest, dstSet, factory, monitor)` — runs one correlator scoped to the given address sets in its own transaction (min function size 1); called per stage by `createStaged` and `addCorrelator`.
- `VersionTrackingUtil.matchedSourceEntries(session)` / `VersionTrackingUtil.matchedDestEntries(session)` — matched entry points per side; used to compute the residual for the next stage.
- `VersionTrackingUtil.defaultApplyOptions()` — `ToolOptions` seeded with Ghidra VT defaults so markup actually applies.
- `VersionTrackingUtil.acceptAndApplyMarkup(session, assoc, opts, monitor)` — accept + apply; returns false if nothing applied or errors occurred.
- `AddressUtil.formatAddress()` — **REQUIRED** for all address output, as everywhere in ReVa.

## Important Notes

- **Orientation matters**: source = trusted/reference, destination = variant; markup and "changes" are always source-relative.
- **Correlation is expensive and persisted**: one `create-session` per pair; reuse via the DomainFile-backed `DiffSessionManager`. `force=true` deletes and re-correlates.
- **Sessions are durable on disk**: persisted under `ReVaDiffSessions/` in the Ghidra project; survive server restart and are reopenable in Ghidra's native Version Tracking GUI. Only `diff-delete-session` (or `clearAll()` in tests) removes a session — nothing auto-deletes.
- **Both programs must be analyzed** — tools error on zero-function programs.
- **Write tools use dual transactions** (VT session + destination program) and commit only on success.
- **Classification is profile-driven**: changed iff `changeTypes` (similarity/callees/size, plus opt-in body-bytes) is non-empty — not VT similarity alone. `body-bytes` is the agent's recall knob (`includeBodyByteChanges`); precise on `.ko`, noisy on linked images.
- **`IDENTICAL_THRESHOLD = 0.9999`** is the `similarity` lens boundary and the default transfer floor; richer ranking is deferred.
- **Correlators are selectable** per session via the `correlators` param (`CORRELATOR_KEYS_AVAILABLE`); changing the selection re-correlates. The default sequence is exact-match only; `combined-reference` is opt-in and can match functions across body changes (reference-based; leaf functions with no refs still won't match). Use `diff-add-correlator` to run additional correlators over the residual after the initial session is established.
- **Scoped-staged correlation** runs each correlator over the still-unmatched residual and saves after each stage — fixes large-image OOM on exact-match correlators; a crash/cancel mid-sequence preserves completed stages. Agent can scope via `sourceScope`/`destinationScope` or refine post-session via `diff-add-correlator`.
- **`diff-create-session`, `diff-add-correlator`, and `diff-transfer-markup` are async background jobs**: accept `waitSeconds` (default 10); small binaries finish inline, large ones return `{status:"running", jobId}` to poll via `diff-status`. Cancel with `diff-cancel` (transfer rolls back atomically). Jobs are serialized on a single worker; a second call for the same pair+kind attaches to the in-flight job.
- **Reuse, don't reinvent**: function diffs go through `DecompilationDiffUtil`; VT orchestration goes through `VersionTrackingUtil`.
