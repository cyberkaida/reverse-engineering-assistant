# ReVa - Ghidra MCP Server for AI-Powered Reverse Engineering

> A Ghidra extension that provides a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/faqs) server for AI-assisted reverse engineering

ReVa (Reverse Engineering Assistant) is a **Ghidra MCP server** that enables AI language models to interact with Ghidra's powerful reverse engineering capabilities. ReVa uses
state of the art techniques to limit [context rot](https://github.com/chroma-core/context-rot) and enable
long form reverse engineering tasks.

ReVa is different from other efforts at building AI assistants for RE tasks because it uses a _tool driven approach_ with a focus
on designing tools for effective LLM use.
ReVa aims to provide a variety of small tools to the LLM, just as your RE environment provides a set of small tools
to you.

Each of the tools given to the LLM are constructed to be easy for the LLM to use and to tolerate a variety of inputs
and to reduce hallucination by the LLM. We do this by providing the LLM with a schema but tolerating other input,
including descriptions that guide the LLM,and redirecting correctable mistakes back to the LLM, and including extra
output to guide the next decision by the LLM.

ReVa's tools differ to other solutions, they provide smaller,
critical fragments with reinforcement and links to other
relevant information to reduce context usage and hallucination.
This greatly improves performance, especially on long form
reverse engineering tasks. This allows ReVa to handle large
binaries and even entire firmware images.

To encourage exploration as a human would, we report additional context like the namespace and cross references along with the decompilation, this
is a small nudge to make the LLM explore the binary in the same way a human would.

Using this technique you can ask general questions and get relevant answers. The model prioritises
information from the tools, but when there is no information it can still respond to generic
questions from its training.

As an MCP server, ReVa can be used alongside other MCP servers to enrich its analysis.
For example you can use the [GitHub MCP Server](https://github.com/github/github-mcp-server)
to allow ReVa access to source code on GitHub, or the
[Kagi MCP Server](https://github.com/kagisearch/kagimcp) to allow ReVa to search the web.

You can ask questions like:

- Examine the programs in this project and explain the relationship between the main binary and the shared libraries.
- What are the interesting strings in this program?
- Does this program use encryption? Write a markdown report on the encryption and where it is used.
- Draw a class diagram using plantuml syntax.
- Start from main, examine the program in detail. Rename variables as you go and provide a summary of the program.
- Explain the purpose of the `__mod_init` segment.
- What does `mmap` return?
- What does the function at address 0x80000 do?
- This is a CTF problem. Write a pwntools script to get the flag.

# Installation

> NOTE: ReVa only supports Ghidra 11.3 and above!

ReVa is a Ghidra extension. To install it, you can download the release for your
version of Ghidra from the releases page and install it using the Ghidra extension manager.

Alternatively, you can build it from source. To do this, clone the repository and run the following command:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle
```

Then install the extension (in `dist/`) using the Ghidra extension manager. You can also extract the release zip to
the Ghidra extensions directory globally at `${GHIDRA_INSTALL_DIR}/Ghidra/Extensions`.

After installing the extension you need to activate it in two places:

1. In the Project view, open the File menu and select "Configure". Click the "Configure all plugins" button on the top right of the menu (it looks like a plug). Check the "ReVa Application Plugin"
2. In the Code Browser tool (Click the Dragon icon or open a File), open the File menu and select "Configure". Click the "Configure all plugins" button on the top right of the menu (it looks like a plug). Check the "ReVa Plugin". Then Press File and select "Save Tool". This will enable ReVa by default.

## MCP configuration

ReVa uses the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/faqs) to communicate with the LLM.

ReVa uses the [streamable MCP transport](https://modelcontextprotocol.io/docs/concepts/transports#server-sent-events-sse)
and will listen on port `8080` by default, you can change this in the Ghidra settings from the project view.

You will need to configure your MCP client to connect to ReVa, this depends on the client you are using.

### Claude Code

Claude Code is the recommended client for ReVa, performance is excellent and Claude Code
handles large binaries and projects well.

```sh
claude mcp add --scope user --transport sse ReVa -- http://localhost:8080/mcp/sse
```

When you use the `claude` command with Ghidra open it will connect to the ReVa MCP server.
You can check with `/mcp` in the Claude Code chat to see if it is connected.

To enable all ReVa commands by default, and avoid prompts for tool use, you can use
the `/permissions` command in Claude Code and add a rule for `mcp__ReVa`. This will
allow ReVa to use all of its tools without prompting you for permission.

### Claude

With Claude you can open your MCP configuration file by opening the Claude
app, opening the settings and then the Developer tab. You can click `Edit Config` to
locate the configuration file.

Add a block to the `mcpServers` section of the configuration file:

```json
{
  "mcpServers": {
    "ReVa": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://localhost:8080/mcp/sse"
      ]
    }
  }
}

```

### VSCode

> If you use Claude Desktop, there is an [automatic discovery feature in VSCode](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_automatic-discovery-of-mcp-servers)
> that will automatically configure the MCP server for you.

VSCode has a built in MCP client, instructions to configure it can be found
in the [GitHub Copilot documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_add-an-mcp-server-to-your-user-settings).

Note that VSCode supports `sse` natively, so you do not need to use `mcp-remote`.

```json
{
  "mcp": {
    "servers": {
      "ReVa": {
        "type": "sse",
        "url": "http://localhost:8080/mcp/sse"
      }
    }
  }
}
```

### oterm - Ollama

[oterm](https://ggozad.github.io/oterm/) is a TUI interface for [Ollama](https://ollama.com) and works well locally with ReVa.

For best results, use a reasoning model like `Qwen3`.

See the [oterm documentation](https://ggozad.github.io/oterm/mcp/#sse-transport) for instructions on how to configure
oterm to use ReVa.

```json
{
  "mcpServers": {
    "ReVa": {
      "url": "http://localhost:8080/mcp/sse"
    }
  }
}
```

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at <https://twitch.tv/cyberkaida> !
