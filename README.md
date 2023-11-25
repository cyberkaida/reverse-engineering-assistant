# ReVA - Reverse Engineering Assistant

[✨ A quick demo! ✨](https://asciinema.org/a/622155)

The reverse engineering assistant (ReVA) is a project to build a disassembler agnostic AI assistant for
reverse engineering tasks. This includes both _offline_ and online inference and a simple architecture.

RevA is different to other efforts at building AI assistants for RE tasks because it uses a technique
called [embedding](https://openai.com/blog/introducing-text-and-code-embeddings)
to give the AI assistant a sort of "long term memory". The model also is given access to a number of tools
that are tweaked to perform well with queries provided by the LLM. This allows the model to reason about the whole
program, rather than just a single function. The tools are tweaked to lead the AI to examine deeper.

Using this technique you can ask general questions and get relevant answers. The model prioritises
information from the embeddings and tools, but when there is no information it can still respond to generic
questions from its training.

You can ask questions like:
- Does this program use encryption?
- Draw a class diagram using plantuml syntax.
- Rename all the variables in main with descriptive names.
- Explain the purpose of the `__mod_init` segment.
- What does `mmap` return?
- What does the function at address 0x80000 do?

## Large Language Model Support

RevA is based on [llama-index](https://github.com/jerryjliu/llama_index),
which supports a number of models.

Built in support is provided for:
- [OpenAI](https://platform.openai.com/overview) for online inference and easy setup (Needs an OpenAI API key)
- [Ollama](https://ollama.ai) and any model it supports for local on-device inference or connecting to a self hosted remote inference server.

Limited support is provided for:
- [llama-cpp](https://llama-cpp-python.readthedocs.io/en/latest/) and any model it supports for local on-device inference
- [text-generation-webui](https://github.com/oobabooga/text-generation-webui) and any model it supports for self-hosted remote inference

Adding additional inference servers is easy if it is supported by llama-index or langchain (on which llama-index is based).

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
1. Generate knowledge base
2. Perform inference

To generate the knowledge base, use the plugin for your disassembler and run the Assistant script.
See [Ghidra Support](#ghidra-support) and [BinaryNinja Support](#binary-ninja-support) below.

First your disassembler extracts the information required for the knowledge base and embeddings.
This involes extracting each function, it's decompilation and some metadata. These are written to a "project". This allows
multiple programs and data sources to be combined into one set of knowledge for the assistant. For example multiple malware
samples, or a program and its libraries could be included along with previous RE notes.

Projects are stored in `~/.cache/reverse-engineering-assistant/projects`. If you make significant changes to your
annotations or analysis in your disassembler, you should delete and regenerate your project directory. This cache
is a _snapshot_ of the state of your disassembler.

To ask questions and run the inference a command line tool is provided. Run `revassistant --project ${NAME_OF_YOUR_PROJECT}` to begin the chat session.

`revassistant` will hash the knowledge base and generate and combine the embeddings into a searchable
index. Once this is complete the index is saved to disk and the chat session begins.

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

## Prerequisites
- [Ghidrathon](https://github.com/mandiant/Ghidrathon) >= 2.2.0 installed into Ghidra

## Usage

After installation, enable the [Ghidrathon extension](https://github.com/mandiant/Ghidrathon#installing-ghidrathon)
and the Ghidra Assistant Extension.

You can generate the knowledge base by running the Ghidra Assistant analysis from the Analysis menu in the Code Browser.

# Binary Ninja Support

Install the ReVA BinaryNinja plugin by opening your BinaryNinja plugin directory (Plugins -> Open Plugin Folder)
and copying or symbolic linking the [binary-ninja-assistant](./binary-ninja-assistant) directory into the plugin
directory.

Restart Binary Ninja and "ReVA Push" will be available in the Plugin menu.
Press this to push data from BinaryNinja to ReVA, then follow the instructions in the [Workflow section](#workflow).
The project name will be the name of the current open file.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
