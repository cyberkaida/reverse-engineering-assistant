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

See [Configuration](#configuration) for more information about settings for the providers.

Adding additional inference servers is easy if it is supported by langchain.

## Configuration

Configuration for ReVa is in the CodeBrowser Tool options.
Open a program and go to Edit -> Tool Options -> ReVa.

There are options for:
- Selecting a provider (OpenAI or Ollama, others coming soon!)
- Enabling "Follow", this will move the Ghidra view to the location of
things ReVa is examining or changing.
- Enabling "Auto-allow", ReVa will log her actions for the user to accept
in the "ReVa Actions Log" window.

There are sections for the providers.

### OpenAI

By default, the OpenAI key is loaded from the environment variable `OPENAI_API_KEY`. You can also set your key inside Ghidra. Setting the key back to the `OPENAI_API_KEY` value will clear the key from the Ghidra configuration and load it from the environment.

You can also select the model. By default `gpt-4o` is selected. This model works best with the tools and the prompt provided by ReVa.

`gpt-4` also works well, but is slow and needs more prompting by the user to explore a binary.

### Ollama

Ollama is a local inference server. The default server is set to localhost, with the default Ollama port. You can change this to a remote server if you want to perform inference on a remote machine. This is useful for organisations that self host.

You can also select a model. The model must alread be loaded on the server. Good performance has been seen with:
- `mixtral`
- `llama3`
- `phi`

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

## Protocol Build

To facilitate communication between `reva-server` and RE tools' plugins, a protocol has been defined. You can read more about that (here)[./DEVELOPER.md]. Building the source files from those protocol definitions is driven from the [Makefile](./Makefile). To build the protocol source code files, run this command in the project's root:

```
make all
```

## Python Project (reva-server and reva-chat) Installation

First install the python component, I like to use `pipx`. Install it with something like: 

```
pip install pipx
```

In the `reverse-engineering-assistant` folder, run:

```
pipx install .
```

After installing the python project, pipx may warn you that you need to add a folder to your PATH environment variable. Make sure that the folder (now containing `reva-server` and `reva-chat`) are in your PATH variable. You can add it to the PATH variable by editing that variable (via some .rc file or the Windows GUI) or pipx can do it for you with this command: 

```
pipx ensurepath
```

Your chosen RE tool's extension will need to start `reva-server`, and you will need to run `reva-chat`. In case you very much do not want to add them to your PATH, your tool's ReVA extension should expose configuration to set the path to `reva-server`.

Once the `reva-server` has been started (ideally by your tool's ReVA plugin/extension) the chat can be started with:

```sh
reva-chat
```

# Ghidra Support

## Usage

> The Python package must be installed for the Ghidra extension to work!

Follow the instructions in the [ghidra-assistant](ghidra-assistant/README.md) plugin.

After installation, enable the `ReVa Plugin` extension in the CodeBrowser tool (Open a file and click: File -> Configure -> Miscellaneous).

If you want ReVa enabled by default, click File -> Save Tool to save the configuration.

If everything is working correctly you will see a ReVa menu on your menu bar.

## Configuration

You can modify the plugin configuration in `Edit -> Tool Options -> ReVa`.

## Undo

Whenever ReVa performs an action it will create an undo point for each action. If ReVa renames 5 variables, this will be
one undo.

## Menus

ReVa adds an option to the CodeBrowser Tool's Window menu.
Select Window -> ReVa Action Log to open the ReVa Action Log window.

This window shows actions ReVa has performed and would like to perform.
You can accept or reject a change by double clicking the ✅ or ❌ icon. You can also go to the location the action will be performed by double clicking the address.

If you reject an action, ReVa will be told and she will move on.

You can also enable "Auto-allow" in the ReVa options. This will automatically accept all actions ReVa wants to perform.

ReVa also adds some elements to the Ghidra UI. You can either ask ReVa to do something in the chat window,
"Examine the variable usage in `main` in detail, rename the variables with more descriptive names.",
or use the menu system.

For example you can right click a variable in the decompilation, select Reva -> Rename variable and ReVa
will perform the action.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
