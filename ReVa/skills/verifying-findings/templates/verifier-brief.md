# Verifier brief: thread <NN>-<slug>

Pass the `programPath` to every call. Never execute the program.

- Program: <programPath>
- Workspace: <workspace>
- Thread report: <workspace>/threads/<NN>-<slug>.md
- Plan entry: <workspace>/plan.md, thread <NN>: Closes when, Must exist
- Write verdicts to <workspace>/verify/<NN>-<slug>.md; dispatch nothing yourself.

1. Read the report and plan entry. List the claims: answer, confidence, addresses, names, negatives, alternatives, assumptions.
2. Run five checks, one line per address: `<check>: pass | fail — <address> — <what was read>`.
   1. Each cited address holds the claim: `get-decompilation` or `read-memory`.
   2. Each name, comment and Must exist item is annotated: `get-symbols`, `get-comments`, `get-bookmarks`.
   3. Each negative names functions read and where: `get-comments`, `get-decompilation`.
   4. Each Closes when candidate is excluded by a marker at an address: `get-bookmarks`, `read-memory`.
   5. Nothing open contradicts the answer: `search-bookmarks` with `types` [`TODO`]; `search-comments` with `searchText` `assumption:`.
3. High needs check 1's `get-decompilation` showing the code for every cited value.
4. Verdict and database write:
   - confirmed: all five pass; none.
   - confirmed-with-fixes: only check 2 fails; the missing annotation.
   - refuted: check 1 fails or a marker matches an alternative; a `TODO` bookmark category `Thread`.
   - unverifiable: check 3, 4 or 5 fails, or a mismatch unresolved; a `TODO` bookmark category `Assumption`.

Verdict file:
1. `Verify <NN>: <verdict> — <answer> — <High|Medium|Low> — check 1: <call> at <address>`; refuted: `<evidence> at <address>`; unverifiable: `<failed check> — next read: <read>`.
2. Refuted only: `Thread <NN>: open — refuted: <evidence>`
3. Check results.
4. Database writes, with addresses.
