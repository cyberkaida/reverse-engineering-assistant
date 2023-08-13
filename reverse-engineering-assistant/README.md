# Reverse Engineering Assistant

This package contains the core of the reverse engineering assistant.
This module is independent of any particular disassembler, and is mostly
code to interface with the large language model and structure common concepts
from disassemblers such as decompilation, note taking, etc.

This package can be used on its own for reverse engineering tasks, but
it works best when paired with a plugin for your reverse engineering tool.
Plugins are provided for:
- [Ghidra](/ghidra-assistant)
- [Binary Ninja](/binary-ninja-assistant)

## Design

In general the tool plugin will lay out a directory of JSON files
containing details about the data to be embedded into the model.
Once this initial analysis is done the reverse-engineering-assistant
core takes over and performs the embedding. Once embedding is complete
the embeddings are serialised to disk and a prompt API is provided to
the tool.

The user can either the core to talk to the model, or use the RE tool
for greater integration (current selection, real time updates, etc).

This allows for both an interactive experience during analysis and a
post analysis option (for automated analysis pipelines).
