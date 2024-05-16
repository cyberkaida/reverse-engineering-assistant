# Developer notes

These are some notes documenting annoying or complex parts of developing for ReVa and
the general architecture of ReVa. It is assumed you read the [README.md](/README.md) before
reading this.

## Design

ReVa is three components:
- An extension/plugin (Ghidra, Binary Ninja, etc.)
- `reva-server` - The LLM interface
- `reva-chat` - The chat UI

These three components talk to each other using gRPC.
The extension launches `reva-server` when it starts and manages its lifetime. `reva-chat` communicates with the extension and `reva-server`.

There is a one to one relationship between the extension and `reva-server` instances. There is a many to one relationship of `reva-chat` to the extension and server.

`reva-server` is written in Python and can use
Ollama and OpenAI for inference. The Ollama server can be
local or remote.

The [protocol](./protocol/) directory contains the protobuf
definitions for each message type and a definition for the
functions provided. Services are small and can be hosted on
either the extension or the inference side. This allows the LLM
to ask the extension for information, or the extension to ask
the LLM for analysis.

The `reva-chat` client first locates the running extension, and then gets details of the `reva-server` started by that extension. The `/tmp/.reva` (or, on Windows, the `%TEMP%/.reva`) directory is used to find running extensions.

## Building the Ghidra extension

You will need:
- Ghidra installed, with the `GHIDRA_INSTALL_DIR` environment variable set to the path to your install
- The [gradle and JDK required by Ghidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/README.md#build)
> Note: This means Gradle 7 for Ghidra and gRPC support!

The [Ghidra extension](./ghidra-assistant) is built like any other
Ghidra extension. Running `gradle` will generate a `dist/` directory
and you can install the extension from there.

If you are running a UNIX system, there is a helper script
[gext-build](./ghidra-assistant/gext-build) that will build
and install the extestion (replacing older versions) in one step.

## reva-server -> Extension

These tools allow ReVa to interact with an RE tool and the binary/project
it has open.

These include:
- Getting decompilation for a function
- Renamaing variables or symbols
- Getting a list of functions

The implementation for these are in the [Ghidra extension's Handlers directory](./ghidra-assistant/src/main/java/reva/Handlers/).

The client code is in the `reva-server`'s [api\_server\_tools](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools/re_tools.py).

## Extension -> reva-server

These tools allow the RE tool to make queries to the LLM.

These include:
- Asking for a better variable name
- Explaining some code that is highlighted
- Setting a comment

These typically just forward some context information to ReVa, and
ReVa will format a prompt and send it to the LLM. Usually the LLM
will then use ReVa -> Extension tools to perform any actions required.

These are [implemented in reva-server](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools/llm_tools.py).

The client code is mostly in the UI code of the Ghidra extenstion.

## Adding a new Tool

We use the gRPC library to talk between the RE Tool and ReVa.

https://grpc.io/docs/languages/java/quickstart/


1. Add a protocol entry to the [protocol](./protocol/) directory.
1. Add a server implementation to the correct location
  1. For a reva-server -> Extension tool, [Handlers in the Ghidra extension](./ghidra-assistant/src/main/java/reva/Handlers/)
  1. For an Extension -> reva-server tool, [api\_server\_tools](./reverse-engineering-assistant/reverse_engineering_assistant/api_server_tools/)
1. Add a stub to call the server.
