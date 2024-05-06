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
- Does this program use encryption? Write a markdown report on the encryption and where it is used.
- Draw a class diagram using plantuml syntax.
- Start from main, examine the program in detail. Rename variables as you go and provide a summary of the program.
- Explain the purpose of the `__mod_init` segment.
- What does `mmap` return?
- What does the function at address 0x80000 do?
- This is a CTF problem. Start at main, examine the program in detail and write a pwntools script to get the flag.

An important part of reverse engineering is the process. Many other tools simply ask a single question of the LLM,
this means it is difficult to determine _why_ a thing happened. In ReVa we break all actions down into small parts
and include the LLMs thoughts in the output. This allows the analyst to monitor the LLMs actions and reasoning, aborting
and changing the prompt if required.

## Large Language Model Support

RevA is based on [langchain](https://langchain.com),
which supports a number of models.

Built in support is provided for:
- [OpenAI](https://platform.openai.com/overview) for online inference and easy setup (Needs an OpenAI API key)
- [Ollama](https://ollama.ai) and any model it supports for local on-device inference or connecting to a self hosted remote inference server.

Adding additional inference servers is easy if it is supported by langchain.

## Configuration

> This is currently being moved to the Ghidra GUI
> See Edit -> Tool Options -> ReVa in the Codebrowser Tool

Configuration for the reverse engineering assistant is stored at
`~/.config/reverse-engineering-assistant/config.yaml`. If this
is not present on first start, a default configuration using
OpenAI for inference and the `OPENAI_API_TOKEN` environment
variable will be used.

The most important setting is the `type` top level setting.
This controls what inference service you use. These are the
same as the configuration keys, for example to use Ollama,
set type to `ollama` and configure the settings in the `ollama:`
section.

The configuration also contains the prompts used for the models.
If you use Ollama or OpenAI these will be processed to fit the
model specific prompt pattern (placing the system prompt in the
correct tags, etc).

For `llama-cpp` and `text-generation-webui` these may need to be
configured for your specific model. For this reason Ollama is
preferred for self hosting.

## Workflow

RevA has a two step workflow.
1. Open your RE tool and the program you want to examine
2. Open the chat session.

ReVa uses an extension for your RE tool to perform analysis.
See [Ghidra Support](#ghidra-support) below.

To ask questions and run the inference a command line tool is provided. Run `reva-chat` to begin the chat session. This command will find your open Ghidra
and connect to it. To open a new chat, run the command again in another terminal.

If you have more than one Ghidra open, you can select the right one with
`reva-chat --project ${project-name}`, if it is not set, `reva-chat` will
ask you which project you want to connect to.

## Installation

First install the python component, I like to use `pipx`. It is best to make
sure that `reva-server` and `reva-chat` are on your path.
The Ghidra extension will need to start `reva-server`, and you will need to
run `reva-chat`.

To install the particular extension for your disassembler see:
- [Ghidra Support](#ghidra-support)

The chat can be started with:

```sh
reva-chat
```

> You can also configure the path to `reva-server` in `Edit -> Tool Options -> ReVa`
> if it is not on your path. But you really should put it on your path!

# Ghidra Support

## Usage

> The Python package must be installed for the Ghidra extension to work!

Follow the instructions in the [ghidra-assistant](ghidra-assistant/README.md) plugin.

After installation, enable the `ReVaPlugin` extension in the CodeBrowser tool (Open a file and click: File -> Configure -> Miscellaneous).

If you want ReVa enabled by default, click File -> Save Tool to save the configuration.

If everything is working correctly you will see a ReVa menu on your menu bar.

## Undo

Whenever ReVa performs an action it will create an undo point for each action. If ReVa renames 5 variables, this will be
one undo.

## Menus

> These are being added in the next release

ReVa adds some elements to the Ghidra UI. You can either ask ReVa to do something in the chat window,
"Examine the variable usage in `main` in detail, rename the variables with more descriptive names.",
or use the menu system.

For example you can right click a variable in the decompilation, select Reva -> Rename variable and ReVa
will perform the action.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
