# Thread <NN>-<slug>: <the Question, verbatim from the plan>

## Thread report

1. Answer: <one or two sentences>, or `open — <reason> — <next read>`
2. Confidence: <High | Medium | Low> — <reason>
   - High: the producing code was read and the bytes match.
   - Medium: one link is a database assumption.
   - Low: a pattern only; the thread is open.
3. Evidence:
   - <address> — <pattern, constant or code seen there>
   - <address> — <pattern, constant or code seen there>
4. Database writes:
   - <address> — <name | type | comment | bookmark | bookmark removed | comment removed> — <what was written>
   - <address> — <name | type | comment | bookmark | bookmark removed | comment removed> — <what was written>
5. Assumptions created or retired:
   - created: <assumption> — at <address> — <`TODO` bookmark category `Assumption` | `assumption:` comment>
   - retired: <assumption> — <confirmed | refuted> by <address>
6. New threads:
   - <question> — start at <address> — closes when: <evidence expected, and where> — must exist: <annotation> at <address> — `TODO` bookmark category `Thread` at <address>

A part with nothing to list: write `none`. Every Evidence line has an address. Every finding in the Answer has a line under Database writes. A failed call goes in the Answer: `open — <call> failed twice: <error text> — <next read>`.
