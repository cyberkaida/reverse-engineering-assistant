# Reverse Engineering Assistant

The reverse engineering assistant (RevA) is a project to build a disassembler agnostic AI assistant for
reverse engineering tasks. This includes both _offline_ and online inference and a simple architecture.

RevA is different to other efforts at building AI assistants for RE tasks because it uses a technique
called [embedding](https://openai.com/blog/introducing-text-and-code-embeddings)
to give the AI assistant a sort of "long term memory". This allows the model to reason about the whole
program, rather than just a single function.

This technique uses a kind of "semantic hash" to look up relevant information to your query and pass
it to the large language model (LLM) when you ask a question. RevA provides a variety of information
sources to the model and the model can look up information from these sources.

Using this technique you can ask general questions and get relevant answers. The model prioritises
information from the embeddings, but when there is no information it can still respond to generic
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
- [llama-cpp](https://llama-cpp-python.readthedocs.io/en/latest/) and any model it supports for local on-device inference
- [text-generation-webui](https://github.com/oobabooga/text-generation-webui) and any model it supports for self-hosted remote inference
- [OpenAI](https://platform.openai.com/overview) for online inference and easy setup (Needs an OpenAI API key)

Adding additional models is easy if it is supported by llama-index or langchain (on which llama-index is based).

See the configuration section for more information about setting the model.

## Configuration

Configuration for the reverse engineering assistant is stored at
`~/.config/reverse-engineering-assistant/config.yaml`. If this
is not present on first start, a default configuration using
OpenAI for inference and the `OPENAI_API_TOKEN` environment
variable will be used.

```yaml
local_llama_cpp:
  # At least pone of `model_path` or `model_url` must be specified
  # If you have the model locally, you can put the path here
  model_path: null
  # Otherwise if you have the URL here it will be cached on first launch
  model_url: https://huggingface.co/TheBloke/Llama-2-13B-chat-GGML/resolve/main/llama-2-13b-chat.ggmlv3.q6_K.bin
  number_gpu_layers: 1

openai:
  # If you have an API token you can put it here, or you can leave this as `null`
  # and RevA will check the `OPENAI_API_TOKEN` environment variable.
  openai_api_token: null

text_gen_web_ui:
  # Set this to the base URL of your text_gen_web_ui instance
  text_gen_web_ui_url: http://text-gen-web-ui.local:5000

# Set this to the model type you would like to use
type: local_llama_cpp
# type: openai
# type: text_gen_web_ui
```

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
revassistant
```

## Workflow

RevA has a two step workflow.
1. Generate knowledge base
2. Perform inference

To generate the knowledge base, use the plugin for your disassembler and run the Assistant script.
See [Ghidra Support](#ghidra-support) below.

First your disassembler extracts the information required for the knowledge base and embeddings.
This involes extracting each function, it's decompilation and some metadata. These are written to a "project". This allows
multiple programs and data sources to be combined into one set of knowledge for the assistant. For example multiple malware
samples, or a program and its libraries could be included along with previous RE notes.

To ask questions and run the inference a command line tool is provided. Run `revassistant` to begin the chat session.

`revassistant` will hash the knowledge base and generate and combine the embeddings into a searchable
index. Once this is complete the index is saved to disk and the chat session begins.

Generating the knowledge base is the longest step and may take a few minutes on an Apple M1 laptop with 16GB of RAM. Once the
embedding and indexing is complete, this data is saved and can be reused.

# Ghidra Support

## Prerequisites
- [Ghidrathon](https://github.com/mandiant/Ghidrathon) >= 2.2.0 installed into Ghidra

## Usage

After installation, enable the [Ghidrathon extension](https://github.com/mandiant/Ghidrathon#installing-ghidrathon)
and the Ghidra Assistant Extension.

You can generate the knowledge base by running the Ghidra Assistant analysis from the Analysis menu in the Code Browser.

# Binary Ninja Support

Coming soon!

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
