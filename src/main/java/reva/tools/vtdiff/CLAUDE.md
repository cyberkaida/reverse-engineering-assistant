# VT Diff & Migration Tools

Tier 2 (VT-backed diff) and Tier 3 (analysis migration) tools. Operates on persistent
`VTSession` domain objects stored in the project at `/VTSessions/`.

## Tools
| Tool | Tier | Purpose |
|---|---|---|
| `compare-programs` | 2 | Create or reuse a session, run AutoVT correlators (and auto-apply markup for accepted matches). Returns `sessionPath`. |
| `list-changed-functions` | 2 | Paginated function-level matches by category: `matched`, `unmatched-source`, `unmatched-destination`, `all`. |
| `list-changed-data` | 2 | Same shape for data associations. |
| `get-function-diff` | 2 | Single matched-pair diff. **Default returns SHAPE only** (BB/instruction counts, callee-set delta, scores). Decompilation opt-in via `includeDecompilation=true`. |
| `list-migration-candidates` | 3 | AVAILABLE associations (lower-confidence matches AutoVT didn't auto-accept). |
| `migrate-function-analysis` | 3 | Accept one association (if AVAILABLE) and apply its markup. |
| `migrate-analysis` | 3 | Bulk markup re-apply across the session. `acceptAvailable=true` extends to AVAILABLE associations. |
| `list-vt-sessions` | mgmt | Enumerate all sessions in the project. |
| `delete-vt-session` | mgmt | Remove a session file (requires `confirm=true`). |

## Parameter naming
- `compare-programs` and migration tools use `sourceProgramPath` / `destinationProgramPath` —
  direction is meaningful (markup flows source → destination).
- Tier 1 cheap diff tools use `programA` / `programB` (no implied direction).

## Session lifecycle
Per-call open/close via `BinaryDiffService.openSession` + `closeSession` in finally. Keeping
the session open across calls would hold a synchronized write-lock on the destination program
(VTSession constructor calls `addSynchronizedDomainObject(destinationProgram)`).

## get-function-diff response design
Mirrors `get-decompilation`: small structured response by default so the LLM can navigate
without filling context. Decompilation is opt-in with per-side `sourceOffset/Limit` and
`destinationOffset/Limit`. The LLM should usually call `get-decompilation` on each program
directly — `includeDecompilation` exists for one-shot side-by-side comparisons.

## Common ergonomic flow (LLM-facing)
```
1. diff-program-metadata     # are the binaries comparable at all?
2. diff-imports/strings      # cheap delta survey across modalities
3. compare-programs          # creates session, auto-applies markup for matched pairs
4. list-changed-functions    # filter category=unmatched-destination → focus list
5. get-function-diff (shape) # for a candidate, see structural delta cheaply
6. get-decompilation x 2     # use the existing per-program tools to drill in
```

## ApplyMarkupItemTask headlessness
`ApplyMarkupItemTask` lives in `feature.vt.gui.task` package but has no AWT/Swing imports —
verified safe in headless mode.
