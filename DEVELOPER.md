# Developer notes

These are some notes documenting annoying or complex parts of developing for ReVa and
the general architecture of ReVa. It is assumed you read the [README.md](/README.md) before
reading this.

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

To add one of these there are a few steps to make sure the messaging
between ReVa and the RE tool works correctly.

We implement a message and a response in python, this is used by the inference
and BinaryNinja plugin. Special handling is required for Ghidra.

1. Add a protocol entry to [tool_protocol.py](./reverse_engineering_assistant/reverse_engineering_assistant/tool_protocol.py)
2. Add matching protocol entries to the Ghidra plugin [RevaProtocol package](./ghidra-assistant/src/main/java/reva/RevaProtocol/)
3. Add new Java protocol entries to the [message parser](./ghidra-assistant/src/main/java/reva/RevaProtocol/RevaMessage.java)
4. Add a handler to the Java [message handlers](./ghidra-assistant/src/main/java/reva/RevaMessageHandlers)
5. Add your new handler to the [message handler dispatch](./ghidra-assistant/src/main/java/reva/RevaMessageHandlers/RevaMessageHandler.java)
6. Add a tool to the python side.

### Protocol entries - Python

A protocol entry is a python class that subclasses either `RevaMessageToReva` or `RevaMessageToTool`
(depending on the direction of the message).

These must always have a matching response message that also subclasses
`RevaMessageResponse`.

To be used in the communication it must be decorated with the `@register_message` decorator.

### Protocol entries - Java

We can't use reflection to capture the types easily like with python. This means there is more
manual setup on the Java side.

To do the same thing `@register_message` does in python, you must add your class to the list
in the [message parser](./ghidra-assistant/src/main/java/reva/RevaProtocol/RevaMessage.java).

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
