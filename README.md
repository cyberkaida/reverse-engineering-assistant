# ReVA - Reverse Engineering Assistant

> Updated demo coming soon!

The reverse engineering assistant (ReVA) is a project to build a disassembler agnostic AI assistant for
reverse engineering tasks. This includes both _offline_ and online inference and a simple architecture.

ReVa is different from other efforts at building AI assistants for RE tasks because it uses a _tool driven approach_.
ReVa aims to provide a variety of small tools to the LLM, just as your RE environment provides a set of small tools
to you. ReVa combines this approach with chain-of-reasoning techniques to empower the LLM to complete complex tasks.

Each of the tools given to the LLM are constructed to be easy for the LLM to use and to tolerate a variety of inputs
and to reduce hallucination by the LLM. We do this by providing the LLM with a schema but tolerating other input,
including descriptions that guide the LLM,and redirecting correctable mistakes back to the LLM, and including extra
output to guide the next decision by the LLM.

For example, when the LLM requests decompilation from your RE tool, we will accept a raw address in hex, a raw address
in base 10, a symbol name with a namespace, or a symbol. If the LLM gives us bad input we report this to the LLM along
with instructions to correct the input (maybe encouraging it to use the function list for example). To encourage exploration
as a human would, we report additional context like the namespace and cross references along with the decompilation, this
is a small nudge to make the LLM explore the binary in the same way a human would.

Using this technique you can ask general questions and get relevant answers. The model prioritises
information from the tools, but when there is no information it can still respond to generic
questions from its training.

You can ask questions like:
- What are the interesting strings in this program?
- Does this program use encryption? Write a markdown report on the encryption and where it is used.
- Draw a class diagram using plantuml syntax.
- Start from main, examine the program in detail. Rename variables as you go and provide a summary of the program.
- Explain the purpose of the `__mod_init` segment.
- What does `mmap` return?
- What does the function at address 0x80000 do?
- This is a CTF problem. Write a pwntools script to get the flag.

An important part of reverse engineering is the process. Many other tools simply ask a single question of the LLM,
this means it is difficult to determine _why_ a thing happened. In ReVa we break all actions down into small parts
and include the LLMs thoughts in the output. This allows the analyst to monitor the LLMs actions and reasoning, aborting
and changing the prompt if required.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
