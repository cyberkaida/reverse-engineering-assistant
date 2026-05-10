# Cheap Diff Tools

Tier 1 binary-diff tools — compare two programs without a Version Tracking session.
All tools take symmetric `programA`/`programB` parameters (no implied direction).

## Tools
- `diff-program-metadata` — architecture, compiler, image base, format, sizes; flags fields whose values differ
- `diff-sections` — memory blocks by name; permissions, sizes
- `diff-symbols` — user-defined named symbols (default Ghidra names like `FUN_*`/`DAT_*` filtered out)
- `diff-exports` — external entry points
- `diff-strings` — defined string literals by value
- `diff-imports` — external functions by `library!name`

## Response shape (uniform across all six)
```
{ "programA", "programB",
  "onlyInA": [...], "onlyInB": [...], "inBoth": [...],
  "countOnlyInA", "countOnlyInB", "countInBoth" }
```
For `inBoth` entries with addresses on both sides, the address is split into `addressA` / `addressB`.

## When to use vs Tier 2 (compare-programs)
Use Tier 1 first to spot delta categories that don't need correlation: new imports/strings/exports,
section-layout changes, architecture differences. Use `compare-programs` when you need
function-level pairing (e.g., "which function in B implements the same logic as `decrypt` in A").
