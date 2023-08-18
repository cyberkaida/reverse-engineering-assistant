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

## Workflow

RevA has a two step workflow.
1. Generate knowledge base
2. Perform inference

First your disassembler extracts the information required for the knowledge base and embeddings.
This involes extracting each function, it's decompilation and some metadata. These are written to a "project". This allows
multiple programs and data sources to be combined into one set of knowledge for the assistant. For example multiple malware
samples, or a program and its libraries could be included along with previous RE notes.

The second step is to run the inference. The knowledge base is hashed and embeddings are generated and combined into a searchable
index. Once this is complete the index is saved to disk and the chat session begins.

Generating the knowledge base is the longest step and may take a few minutes on an Apple M1 laptop with 16GB of RAM. Once the
emebedding and indexing is complete, this data is saved and can be reused.

## Models

```sh
python3 -m pip install transformers accelerate
python3 -m pip install --pre torch torchvision torchaudio --extra-index-url https://download.pytorch.org/whl/nightly/cpu
GIT_LFS_SKIP_SMUDGE=1 git clone https://huggingface.co/TheBloke/Llama-2-7B-GGML

# Or with WizardLM
GIT_LFS_SKIP_SMUDGE=1 git clone https://huggingface.co/TheBloke/TheBloke/WizardLM-13B-V1.2-GGML

# Pull just the 4bit quantized version. If you have the compute and know what you're doing
# you can use anything compatible with llama-cpp
git lfs pull -I *.ggmlv3.q4_0.bin
```

# Ghidra Support

## Prerequisites
- [Ghidrathon](https://github.com/mandiant/Ghidrathon) >= 2.2.0 installed into Ghidra

## Usage

After installation, enable the [Ghidrathon extension](https://github.com/mandiant/Ghidrathon#installing-ghidrathon)
and the Ghidra Assistant Extension.

You can generate the knowledge base by running the Ghidra Assistant analysis from the Analysis menu in the Code Browser.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at https://twitch.tv/cyberkaida !
