# Saved scripts: list / read / write / edit

This file covers the workflow for scripts that live as `.py` files on disk under Ghidra's registered script directories, rather than as inline `code` to `run-script`. The four file-management tools (`list-scripts`, `read-script`, `write-script`, `edit-script`) work in every ReVa mode, even when PyGhidra isn't wired up — only `run-script` itself needs the PyGhidra runtime.

## When to save vs. one-shot

Inline `code` is right when the work is exploratory, one-off, or you're still iterating. Save with `write-script` when:

- The same logic will be re-run (different binaries, different days).
- The user explicitly asks for "a script that does X."
- The script crossed ~50 lines or has comments worth keeping.
- You want it to appear in Ghidra's Script Manager (GUI mode).

Don't save partial drafts — get it working inline first, then save the finished version.

## Where scripts live

Scripts live in registered directories. `list-scripts` enumerates all of them. Common ones:

- `~/ghidra_scripts/` — the **user dir**. Writeable. This is where `write-script` puts new files when you pass `scriptName` instead of an absolute `scriptPath`.
- `<Ghidra install>/Ghidra/Features/.../ghidra_scripts/` — bundled system scripts. **Read-only.** `write-script` / `edit-script` will refuse paths here.
- Bundle script dirs configured in the Ghidra Bundle Manager — usually read-only.
- ReVa's own `ghidra_scripts/` directory (shipped with the extension) — sample scripts; read-only.

`list-scripts` returns each entry with a `writeable` boolean so you can tell at a glance which directory it's in.

## Naming conventions

- End in `.py`. The tool doesn't enforce it but Ghidra discovery does.
- CamelCase or snake_case both work; the existing Ghidra examples use CamelCase (`AnalyzeStuff.py`, `FindCryptoConsts.py`).
- Avoid generic names like `script.py` or `test.py` — they collide and they don't tell `list-scripts` consumers anything.
- Prefix with the analysis target if appropriate: `wallaby_dump_strings.py`, `loader_decrypt_strings.py`.

## GhidraScript headers

Saved scripts can carry headers Ghidra reads for the Script Manager UI:

```python
# Some short one-line description here.
# @category Analysis.MyCategory
# @runtime PyGhidra
# @menupath Tools.Reverse.MyAnalysis
# @keybinding ctrl shift M
# @toolbar
```

| Header | What it does |
|---|---|
| `# @runtime PyGhidra` | **Required** for CPython 3 execution. Without it, Ghidra tries Jython and you get import errors. |
| `# @category Foo.Bar` | Where it shows up in the GUI Script Manager tree. Dots → submenus. |
| `# @menupath Tools.X.Y` | Top-menu placement. |
| `# @keybinding ctrl shift M` | Hotkey. |
| `# @toolbar` | Toolbar icon (with a matching `.gif`/`.png`). |
| The first comment line | One-line description shown in the Script Manager. |

`run-script` honours `# @runtime PyGhidra` and ignores the rest. When you `write-script` something you intend to use *only* via `run-script` from the LLM, the other headers are optional.

ReVa's `run-script(code=...)` mode adds `# @runtime PyGhidra` to inline temp files automatically — but it does **not** when you `write-script` a saved file. If you save a script and later it fails to run because Ghidra tries Jython, the missing header is the cause.

## The typical workflow

### First time

```
1. list-scripts(nameFilter="String")                # see if something exists
2. run-script(programPath="/bin", code="""...""")   # prototype inline
3. iterate inline until it works
4. write-script(scriptName="DumpStringsWithXrefs.py", code="""
   # Dump all defined strings with their callers.
   # @runtime PyGhidra
   # @category Analysis
   ...final code...
   """)
5. run-script(programPath="/bin", scriptName="DumpStringsWithXrefs.py")
```

### Iterating on a saved script

```
1. read-script(scriptName="DumpStringsWithXrefs.py")
   # Note the cat -n line numbers around what you want to change.
2. edit-script(
     scriptName="DumpStringsWithXrefs.py",
     old_string="    if not refs: continue",
     new_string="    # require at least 2 referencers\n    if len(refs) < 2: continue",
   )
3. run-script(scriptName="DumpStringsWithXrefs.py")
```

Why not `write-script(overwrite=true)`? Because `edit-script` produces a clean diff and only touches the lines you changed; full overwrites obscure intent and risk losing concurrent edits.

## Picking a good `old_string` for `edit-script`

`edit-script` errors when `old_string` matches zero or multiple locations (unless `replace_all: true`). To make a match unique, include surrounding context:

**Bad** (likely matches several places):
```python
old_string="    if not refs: continue"
```

**Good** (anchored by the comment two lines above):
```python
old_string="""    refs = [r for r in getReferencesTo(addr) if getFunctionContaining(r.getFromAddress())]
    if not refs: continue"""
```

Read the file with `read-script` first, find a chunk that's clearly unique (often the line plus 1-2 above and below), and use that.

`replace_all: true` is right when you're doing a name change that *should* hit every occurrence — renaming a variable throughout, changing a constant, swapping an import. Don't use it as a shortcut around picking a unique `old_string`.

## What gets shipped with ReVa

ReVa's repo has a `ghidra_scripts/` directory (`reverse-engineering-assistant/ghidra_scripts/`) with a `sample_script.py`. Those ship with the extension and end up in Ghidra's script search path — they're read-only via `read-script`/`run-script` (you can't `write-script` to them). Drop new public-facing scripts there in the repo (not via the MCP tool) if you're a contributor; the MCP tool is for user-authored, runtime scripts.

## Discoverability tips

When the user asks for a script that "probably already exists":

1. `list-scripts(nameFilter="...")` — search by file name.
2. `list-scripts(pathFilter="...")` — search by directory (e.g. only the user dir).
3. `read-script(scriptName="...")` on any hit that looks close to confirm.

Don't re-implement a script that already exists in the user's `~/ghidra_scripts/` — read it, suggest running it, or `edit-script` it to fit the new requirement.
