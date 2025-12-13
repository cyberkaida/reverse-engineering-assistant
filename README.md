# ReVa - Ghidra MCP Server for AI-Powered Reverse Engineering

[![Run in Smithery](https://smithery.ai/badge/skills/cyberkaida)](https://smithery.ai/skills?ns=cyberkaida&utm_source=github&utm_medium=badge)


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

> NOTE: ReVa only supports Ghidra 11.4 and above!

ReVa is a Ghidra extension. To install it, you can download the release for your
version of Ghidra from the releases page and install it using the Ghidra extension manager.

Alternatively, you can build it from source. To do this, clone the repository and run the following command:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle install
```

After installing the extension you need to activate it in two places:

1. In the Project view, open the File menu and select "Configure". Click the "Configure all plugins" button on the top right of the menu (it looks like a plug). Check the "ReVa Application Plugin"
2. In the Code Browser tool (Click the Dragon icon or open a File), open the File menu and select "Configure". Click the "Configure all plugins" button on the top right of the menu (it looks like a plug). Check the "ReVa Plugin". Then Press File and select "Save Tool". This will enable ReVa by default.

# Usage

There are two ways to use ReVa, with the Ghidra UI in assistant mode or in headless mode. Headless mode is ideal for automation and CI/CD pipelines, while the assistant mode is great for interactive analysis.

In assistant mode, ReVa connects to your running Ghidra and can work with you on your project. It can work in real time on the same file or on other files in your project. This is useful for deep analysis, ReVa can help identify algorithms, rename variables, fix datatypes, and many other parts of analysis.

In headless mode, ReVa runs without the Ghidra UI. This is useful for automation, CI/CD pipelines, or when you want to run ReVa in a pipeline. ReVa manages starting Ghidra
and projects for you. Projects in headless mode are ephemeral (session-scoped) and automatically cleaned up. This is useful when you do not need the Ghidra UI and want ReVa
to work on its own.

You select which mode with the MCP configuration in your MCP client.

### Assistant Mode

In assistant mode, you run Ghidra with ReVa installed and connect your MCP client to the ReVa MCP server running in Ghidra. You must first start Ghidra and open a project.

ReVa uses the [streamable MCP transport](https://modelcontextprotocol.io/docs/concepts/transports#streamable-http)
and will listen on port `8080` by default, you can change this in the Ghidra settings from the project view. This allows many clients to connect to the same UI for interactive use.

#### Claude Code

Claude Code is the recommended client for ReVa, performance is excellent and Claude Code
handles large binaries and projects well.

```sh
claude mcp add --scope user --transport http ReVa -- http://localhost:8080/mcp/message
```

When you use the `claude` command with Ghidra open it will connect to the ReVa MCP server.
You can check with `/mcp` in the Claude Code chat to see if it is connected.

To enable all ReVa commands by default, and avoid prompts for tool use, you can use
the `/permissions` command in Claude Code and add a rule for `mcp__ReVa`. This will
allow ReVa to use all of its tools without prompting you for permission.

#### VSCode

VSCode has a built in MCP client, instructions to configure it can be found
in the [GitHub Copilot documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers#_add-an-mcp-server-to-your-user-settings).

```json
{
  "mcp": {
    "servers": {
      "ReVa Assistant": {
        "type": "http",
        "url": "http://localhost:8080/mcp/message"
      }
    }
  }
}
```

### Headless Mode

ReVa can run in headless Ghidra mode without the GUI, making it ideal for:

- **Automation** - CI/CD pipelines and automated analysis
- **Docker** - Containerized reverse engineering workflows
- **PyGhidra** - Python-based automation

#### Claude Code

```bash
# Set Ghidra installation directory, this must always be in your environment
export GHIDRA_INSTALL_DIR=/path/to/ghidra
uv tool install reverse-engineering-assistant
claude mcp add --scope user ReVa -- mcp-reva

claude -p "Import /bin/ls with ReVa and tell me how it works"
```

A project will be created in the current working directory in `.reva/projects/`.
If you run claude from the same directory, you can import many files into the same project. Just ask ReVa to work on the new file.

#### PyGhidra Integration

You can also use ReVa directly from PyGhidra scripts:

```python
import pyghidra
pyghidra.start()

from reva.headless import RevaHeadlessLauncher

# Start server
launcher = RevaHeadlessLauncher()
launcher.start()

if launcher.waitForServer(30000):
    print(f"Server ready on port {launcher.getPort()}")
    # ... your analysis code with your agent ...

launcher.stop()
```

# Claude Code Marketplace

The ReVa repo includes a [Claude Code marketplace and plugins](https://claude.com/blog/claude-code-plugins)
to make using ReVa easier. These include skills and scripts to help ReVa work better with Claude Code.

You can install with:

```bash
claude plugin marketplace add cyberkaida/reverse-engineering-assistant
```

This will add the [ReVa skills](/ReVa/skills/) to your Claude Code installation.

- Binary Triage
- Deep Analysis
- Cryptography Analysis
- CTF guides

I will be adding more skills over time to help with reverse engineering tasks.

# Support

Do you like my work? Want to support this project and others? Interested in how this project was designed and built?
This project and many others are built live on my stream at <https://twitch.tv/cyberkaida> !
