---
name: commit
description: Use when writing a git commit message in ReVa, committing staged changes, squashing or rewording commits during a rebase, or cleaning up a branch's history before it lands on main.
---

# Committing in ReVa

ReVa commit messages follow the maintainer's own style, taken from the
hand-written history (`git log --until=2025-05-01 --author=カイダ`). Commits
read like short notes from a person, not like a changelog generator.

## The message

A message is a subject line, and for anything not obvious from the subject,
a blank line and a short prose body.

**Subject**

- Imperative, sentence case, no trailing period: `Add cross reference tool`
- Starts with a plain verb: Add, Fix, Remove, Refactor, Move, Allow, Make,
  Clean, Update, Switch, Improve, Bump, Rewrite, Let, Handle, Ignore
- Says what changed for the user of ReVa or the code, in everyday words
- Usually 30 to 60 characters; never over 72
- One idea. Two closely related changes may share a subject with a comma
  (`Refactor options, add auto analysis`); three or more means split the commit

**Body** (optional)

- One to four sentences of plain prose, wrapped at about 70 columns
- Explains why, or what was wrong before, or what now works:
  "We returned updated addresses when we should not have."
  "Now you can just run Ghidra, then open a terminal and run `reva-chat`"
- Speaks as "we" about the code and "now" for the new behaviour
- An issue reference goes on its own line: `Fixes #80`

## Examples from the history

```
Fix bug where comments are always at the top of functions

We returned updated addresses when we should not have.
```

```
Move the connection files to the home directory

The tempfile in java and python was different.
```

```
Remove BinaryNinja support

BinaryNinja support will be rewritten. Remove it for now as it is
broken.
```

```
Add CI for Windows and macOS

Fixes #80
```

Subjects with no body: `Add data type tool`, `Ignore .worktrees directory`,
`Fix template for 12.1.3 support`, `Pin langgraph to version 0.2.3`.

## Rewriting generated-style messages

| Generated style | ReVa style |
|---|---|
| `feat(decompiler): decompilation cache keyed on program modification number` | `Cache decompilations per program modification number` |
| `fix: retain programs after checkin` | `Keep programs open after check-in` |
| `tools: a missing programPath means the only open program; check-in with no changes succeeds` | split into `Make programPath optional when one program is open` and `Allow check-in with no changes` |
| `fix: roll back missing bookmark removal transactions` | `Fix bookmark removal leaving a transaction open` |
| 20 `fix(decompiler):`/`test(decompiler):` commits on one feature branch | one `Cache decompilations ...` commit |

The left column's habits, each replaced by the right column's:

- `type(scope):` prefixes become a leading verb
- Semicolon-joined change lists become separate commits
- Present-tense descriptions ("cache put is state-checked") become imperatives
- Internal work names (trial3, plan5, workflow-skills, superpowers, "the
  contract", "ruling") become what the change does
- Bullet-point bodies become a sentence or two of prose

## Commit content

- One commit is one feature or one fix a reviewer would read on its own.
  A branch of dozens of small commits lands as a handful. A test, doc,
  review fix or follow-up for code in the same unpushed series is
  squashed into the commit that introduced that code.
- Docs say how the code works now. Notes about earlier designs, review
  rulings, dates or "no longer" wording are rewritten or dropped.
- A feature that went through several designs on a branch lands as its
  final design. Intermediate designs that were later replaced are folded
  away, not kept as history.
- Every commit compiles so bisect works.
- Planning notes, scratch files, and local IDE files (`.classpath`,
  `.project`, `.settings/`, `docs/superpowers/`) are not committed.
- Binary fixtures under `tests/fixtures/` go through git-lfs (see the
  root CLAUDE.md).
- No `Co-Authored-By` or "Generated with" trailers.

## Cleaning up a branch before it lands

1. Back up first: `git branch backup/<name>-$(date +%Y%m%d)`.
2. Rebase onto the latest `origin/main`, flattening merges.
3. Read the whole branch diff (`git diff origin/main HEAD --stat`, then
   per file) and list the features it adds. Assign every commit to one
   feature; split a commit that serves two (`edit`, `git reset HEAD^`,
   stage each half). When one feature's later fixes build on another
   feature's code, merge the two groups rather than fight the conflicts.
4. Write a todo where each group is one `pick` followed by `fixup`s, in
   order of the group's first commit, and an `exec git commit --amend
   -F <message file>` after each group. Set `GIT_SEQUENCE_EDITOR` to a
   command that writes it, since `-i` prompts are not available to agents.
5. Check the result: `git diff <backup> HEAD` shows only the upstream
   changes plus any deliberate cleanups, every commit compiles
   (`git rebase -x 'gradle -q compileJava compileTestJava compileIntegrationTestJava' origin/main`),
   and the full test suite passes at the tip.
6. Never force-push `main` without the maintainer saying so.
