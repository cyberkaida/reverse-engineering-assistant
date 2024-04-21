# Developer notes

These are some notes documenting annoying or complex parts of developing for ReVa and
the general architecture of ReVa. It is assumed you read the [README.md](/README.md) before
reading this.

## Design

ReVa is two components:
- An extension/plugin (Ghidra, Binary Ninja, etc.)
- The inference component (LLM)

These two components talk to each other using gRPC.
The extension launches the inference when it starts.

The inference component is written in Python and can use
Ollama and OpenAI for inference. The Ollama server can be
local or remote.

The [protocol](./protocol/) directory contains the protobuf
definitions for each message type and a definition for the
functions provided. Services are small and can be hosten on
either the extension or the inference side. This allows the LLM
to ask the extension for information, or the extension to ask
the LLM for analysis.

## Building the Ghidra extension

You will need:
- Ghidra installed, with the `GHIDRA_INSTALL_DIR` environment variable set to the path to your install
- The [gradle and JDK required by Ghidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/README.md#build)

The [Ghidra extension](./ghidra-assistant) is built like any other
Ghidra extension. Running `gradle` will generate a `dist/` directory
and you can install the extension from there.

If you are running a UNIX system, there is a helper script
[gext-build](./ghidra-assistant/gext-build) that will build
and install the extestion (replacing older versions) in one step.

## ReVa -> RE Tool

These tools allow ReVa to interact with an RE tool and the binary/project
it has open.

These include:
- Getting decompilation for a function
- Renamaing variables or symbols
- Getting a list of functions

## RE -> Reva Tool

These tools allow the RE tool to make queries to the LLM.

These include:
- Asking for a better variable name
- Explaining some code that is highlighted
- Setting a comment

These typically just forward some context information to ReVa, and
ReVa will format a prompt and send it to the LLM. Usually the LLM
will then use ReVa -> RE Tools to perform any actions required.

## Adding a new Tool

We use the gRPC library to talk between the RE Tool and ReVa.

https://grpc.io/docs/languages/java/quickstart/


1. Add a protocol entry to the [protocol](./protocol/) directory.

### Handlers - Python

Handlers in python can provide a function to the LLM, or receive a message from the RE Tool.
These are handled in the [api_server_tools package](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools)

In the [re_tools module](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools/re_tools.py)
tools that perform actions on the RE tool side are defined. In other words, these are the
ReVa -> RE Tools. These classes subclass `RevaRemoteTool` and are registered with the `@register_tool`
decorator.

In the [llm_tools module](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools/re_tools.py)
tools that make requests of the LLM are defined. In other words, these are the
RE -> ReVa Tools. These classes subclass `RevaMessageHandler` and are registered with the
`@register_message_handler` decorator.
