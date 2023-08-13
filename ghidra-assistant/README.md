# Ghidra Assistant

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

## Prerequisites
- [llama-cpp configured in langchain](https://python.langchain.com/docs/integrations/llms/llamacpp) or OpenAI API access
- [Ghidrathon](https://github.com/mandiant/Ghidrathon) >= 2.2.0 installed into Ghidra

## Usage

After installation, enable the [Ghidrathon extension](https://github.com/mandiant/Ghidrathon#installing-ghidrathon)
and the Ghidra Assistant Extension.

Once enabled you can access the Assistant through the Window menu. On first launch for a binary the assistant will
query Ghidra's program APIs for information about your program and then generate an
[embedding](https://developers.google.com/machine-learning/crash-course/embeddings/obtaining-embeddings). This
embedding allows _the entire_ program, and other sources such as additional related programs, your notes and your
annotations to be incorporated into the models responses without sacrificing input token space.
