# CLAUDE.md - Ghidra Help System

Guidance for editing the JavaHelp content shipped with the ReVa extension. The whole module fails to build if help validation fails — `gradle install` is gated on `:buildModuleHelp`.

## Layout

```
src/main/help/help/
  TOC_Source.xml                 # Table of contents (referenced by tocdef IDs)
  topics/ReVa/
    ReVa_overview.html           # Landing page (target of top tocdef)
    ReVa_installation.html       # Setup, config, troubleshooting
    ReVa_skills.html             # Claude Code workflow notes
    map.xml                      # Maps help IDs → topic files (must match TOC ids)

src/main/resources/help/shared/  # Module-owned shared assets (NOT under src/main/help/)
  note.png  tip.png  warning.png
```

Pages reference shared assets as `help/shared/foo.png` in HTML — JavaHelp resolves that across all modules at runtime. Anything *the page uses* but Ghidra's core help doesn't already provide must live under `src/main/resources/help/shared/`. Stylesheet (`DefaultStyle.css`) and `arrow.gif` come from Ghidra core; note/tip/warning PNGs do not, which is why they ship here.

## Hard rules

1. **Anchor names must be globally unique across every HTML file in this module.** JavaHelpValidator treats the module as one namespace. Common collision risks: `RelatedTopics`, `Tips`, `Troubleshooting`, `Configuration`, `ProgramPath`. Prefer prefixed names: `Troubleshoot<Specific>`, `Config<Section>`.
2. **Every `<A name="X">` referenced from `TOC_Source.xml` or another page must exist** with that exact case. Validator catches dangling targets.
3. **Every `<IMG src="...">` and `<LINK href="...">` must resolve.** Either the asset is in `src/main/resources/help/shared/` (this module) or it's a known Ghidra core shared asset (`DefaultStyle.css`, `arrow.gif`, `close16.gif`, `note.yellow.png` — see `Ghidra/Framework/Help/src/main/resources/help/shared/`).
4. **`tocdef id` and `map.xml` entries must agree.** TOC ids are the contract for help-button targets in plugin UI code.
5. **`<TITLE>` must be set** on every HTML file; missing titles fail validation.

## Authoring conventions

- Write for humans, not for LLMs. Keep example prompts and capability tables; remove tool-by-tool parameter docs (commit 722d519 deleted ~7000 lines of those — they belong in the MCP tool descriptions, not help).
- Use `<H1><A name="PageAnchor">` for the page title, `<H2><A name="...">`/`<H3>` for sections.
- Wrap section bodies in `<BLOCKQUOTE>` to match Ghidra's house style.
- For callouts: `<P><IMG border="0" src="help/shared/note.png" alt=""> ...</P>` (also `tip.png`, `warning.png`).
- Use `<CODE>` for command names and paths; `<I>` for example prompts.
- Cross-reference other pages with `<A href="ReVa_installation.html#Anchor">`.

## Verifying before commit

- `GHIDRA_INSTALL_DIR=$HOME/.local/opt/ghidra_12.0.4_PUBLIC gradle buildModuleHelp` runs the validator standalone (faster than full `install`).
- A green `BUILD SUCCESSFUL` is not enough on its own — scan stdout for `JavaHelp.*errors? = [1-9]` or `Duplicate anchor` / `Broken link` warnings before assuming the build is clean.
- After fixing anchors, also re-grep across all module HTML to confirm uniqueness:
  `grep -rEho 'name="[^"]+"' src/main/help/help/topics | sort | uniq -d`
