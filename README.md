# ReVA - Reverse Engineering Assistant

[✨ An (old) quick demo! ✨](https://asciinema.org/a/626197)

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

Limited support is provided for:
- [llama-cpp](https://llama-cpp-python.readthedocs.io/en/latest/) and any model it supports for local on-device inference
- [text-generation-webui](https://github.com/oobabooga/text-generation-webui) and any model it supports for self-hosted remote inference

Adding additional inference servers is easy if it is supported by langchain.

See the configuration section for more information about setting the model.

## Configuration

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
See [Ghidra Support](#ghidra-support) and [BinaryNinja Support](#binary-ninja-support) below.

Once open the RE tool will try to connect to ReVa's REST API on localhost.

A project cache is created in `~/.cache/reverse-engineering-assistant/projects`. This contains your chat log and other
cache data. This can be deleted at any time and ReVa will re-generate the data as needed.

To ask questions and run the inference a command line tool is provided. Run `revassistant --project ${NAME_OF_YOUR_FILE}` to begin the chat session.

> Note: In the future `--project` will refer to a _project_ in Ghidra and allow inference across multiple files.
> I am waiting for BinaryNinja's project feature to make this change, if this takes too long I will rework this argument.

`revassistant` provides a chat window and runs the command API to talk with the RE tool.

> Note: Right now only one `revassistant` can run at a time (as we start a server on a well known port)
> In the future we will share the server between chat clients and RE tool connections.

## Installation

To install the particular extension for your disassembler see:
- [Ghidra Support](#ghidra-support)
- [Binary Ninja Support](#binary-ninja-support)

To install the chat component you can do the following:

```sh
python3 -m pip install ./reverse-engineering-assistant
```

The chat can be started with:

```sh
revassistant --project ${NAME_OF_YOUR_PROJECT}
```

# Ghidra Support

## Usage

After installation, enable the `ReVaPlugin` extension in the CodeBrowser tool (Open a file and click: File -> Configure -> Miscellaneous).

If you want ReVa enabled by default, click File -> Save Tool to save the configuration.

To start the inference side, open Help -> About ${program name}. In this popup you will see details about your open file.
The `Program Name:` field is the name you need to pass to `revassistant --project` to start the inference server. In some
cases this is different to the name in the project view.

## Undo

Whenever ReVa performs an action it will create an undo point for each action. If ReVa renames 5 variables, this will be
one undo.

## Menus

ReVa adds some elements to the Ghidra UI. You can either ask ReVa to do something in the chat window,
"Examine the variable usage in `main` in detail, rename the variables with more descriptive names.",
or use the menu system.

For example you can right click a variable in the decompilation, select Reva -> Rename variable and ReVa
will perform the action.

Note this uses the same system as chatting with ReVa, this means you can monitor ReVas thoughts in the chat
window while the action is performed.

# Binary Ninja Support

> Note: Binary Ninja support is currently on hold while the basic functions are implemented in the Ghidra plugin.
> This is because plugin development for Binary Ninja is easier as we have Python3. I will resume development soon!

Install the ReVA BinaryNinja plugin by opening your BinaryNinja plugin directory (Plugins -> Open Plugin Folder)
and copying or symbolic linking the [binary-ninja-assistant](./binary-ninja-assistant) directory into the plugin
directory.

Restart Binary Ninja and "ReVA Push" will be available in the Plugin menu.
Press this to push data from BinaryNinja to ReVA, then follow the instructions in the [Workflow section](#workflow).
The project name will be the name of the current open file.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
