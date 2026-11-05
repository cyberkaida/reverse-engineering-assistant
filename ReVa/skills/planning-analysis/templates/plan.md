# Plan: <program-basename>

Brief: <workspace>/brief.md

## Playbooks consulted

- <name> — <used | did not fit: why>

## Threads

### <NN>-<slug>
- Question: <one question with a checkable answer>
- Start: <address, symbol, string or import>
- Closes when: <evidence expected, and where> — refuted if: <what would show it false>
- Must exist: <annotation> at <address>; <annotation> at <address>
- Playbook: <name | none>

### <NN>-identity
- Question: What does the program say it is: name, version, build?
- Start: `get-strings` with `regexPattern` `\.pdb|VS_VERSION_INFO|ProductVersion|Go build ID|/rustc/`; <export names, manifests, section names, assembly metadata>
- Closes when: <identity strings, with addresses> — refuted if: <every source checked, none present>
- Must exist: a `Note` bookmark category `Identity` at each identity string
- Playbook: none

### <NN>-persistence
- Question: How does it persist?
- Start: <persistence imports and strings>
- Closes when: <install code read> — refuted if: <every candidate read, none installs>
- Must exist: a `Note` bookmark category `Finding` at the install code, or a comment `no persistence: read <functions>; checked <imports, strings>`
- Playbook: persistence-and-capabilities

### <NN>-entry-points
- Question: Is every entry point and export body read?

### <NN>-producers
- Question: Is every reported value traced to its producer?

### <NN>-no-<capability>
- Question: Is <capability> absent?

Fill all five fields for these three, from the skill's perimeter table.

## Done-when map

- <Done-when item, from the brief> — threads <NN, NN>
