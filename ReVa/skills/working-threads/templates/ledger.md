# Analysis ledger — plan: <workspace>/plan.md

Append one line per event, below Lines, in the order it happens. A line is written when its evidence exists, never to clear a list. Fill every slot; one line each.

Line forms:
- `Thread <NN>: closed — <answer> at <address>`: answered or refuted; the evidence is in `threads/<NN>-<slug>.md`.
- `Thread <NN>: open — <reason: a tool result, or the harness message in "quotes"> — <next read>`
- `Thread <NN>: open — <call> failed twice: <error text> — <next read>`
- `Assumption: retired — <assumption> — <confirmed | refuted> at <address>`
- `Ruling: <what departed from the plan> — <why; time or spend: the harness message in "quotes"> — <cost if wrong>`

Later skills append lines in the same style, a label, a colon, then parts joined by ` — `:
- `verifying-findings`: `Verify <NN>: <verdict> — <one line>`.
- Any later step: `<Label>: <what> — <one line>`.

A thread's state is its last `Thread <NN>:` line: `verifying-findings` may append `Thread <NN>: open — refuted: <evidence>` after a `closed` one. A resumed session reads this file first and starts at the first thread whose last `Thread <NN>:` line is missing or not `closed`.

## Lines

(none yet)
