# Thread brief: <NN>-<slug>

You work one thread of the analysis of `<programPath>` in Ghidra. Pass that `programPath` to every call. Never execute the sample. The evidence is the program in Ghidra.

## Thread, from <workspace>/plan.md

- Question: <verbatim>
- Start: <verbatim>
- Closes when: <verbatim> — refuted if: <verbatim>
- Must exist: <verbatim>
- Playbook: <name | none>

## Scope decisions, from <workspace>/brief.md

<the brief's Scope decisions, verbatim>

## Assumptions, from <workspace>/brief.md

<the brief's Assumptions, verbatim>

## Workspace

<workspace>

Your report: <workspace>/threads/<NN>-<slug>.md. It is your one workspace file; the lead writes the plan and the ledger.

## Steps

1. Then read `deep-analysis`.
2. Playbook not none: read `skill://planning-analysis/playbooks/<name>.md` for this thread's rows.
3. Run the loop on the Question from the Start. Write each finding into the database when made. Make every Must exist annotation.
4. A call fails or times out: retry it once, same arguments. Fails again: the thread is open with the call and its error text.
5. The thread ends: fill `skill://working-threads/templates/thread-report.md`.
6. Write the report file; dispatch nothing yourself.
7. Reply with the report path and its Answer line.
