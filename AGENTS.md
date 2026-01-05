# AGENTS.md

## Project Overview

ReVa (Reverse Engineering Assistant) is a Ghidra extension that provides a Model Context Protocol (MCP) server for AI‑assisted reverse engineering. It offers a collection of tool providers that expose Ghidra functionality (decompiler, strings, symbols, etc.) via a JSON‑based MCP interface.

---

## Build & Test Commands

### Building the extension
```bash
# Set the Ghidra installation directory first
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle            # no wrapper – use the system `gradle` command
```

### Testing
- **Unit tests**: `gradle test --info`
- **Integration tests** (require a headed GUI environment): `gradle integrationTest --info`
- **Run a single unit test**: `gradle test --tests "*MyTestClass.testMethod" --info`
- **Run a single integration test**: `gradle integrationTest --tests "*MyIntegrationTest" --info`
- **Check** (includes lint & both test suites): `gradle check`

---

## Project Structure

- `src/main/java/reva/` – Core source code
  - `util/` – Foundational utilities (`AddressUtil`, `ProgramLookupUtil`, etc.)
  - `plugin/` – Ghidra plugin infrastructure and configuration
  - `server/` – Embedded Jetty server and MCP transport
  - `tools/` – Tool providers (decompiler, functions, strings, symbols, …)
  - `resources/` – Read‑only MCP resources
  - `services/` – Service‑layer abstractions
  - `ui/` – Optional UI components
- `src/test/` – Unit tests (no Ghidra runtime required)
- `src/test.slow/` – Integration tests (require Ghidra environment)

---

## Development Guidelines

### Code Style
- **Java version**: Target **Java 21**.
- **Formatting**: 4‑space indentation, no trailing whitespace. Imports sorted alphabetically, static imports after regular imports.
- **Naming**: Classes & enums `PascalCase`; methods & variables `camelCase`; constants `UPPER_SNAKE_CASE`.
- **Types**: Prefer concrete generic types (`List<>`, `Map<>`) over raw collections; use `Optional` for nullable returns.
- **Documentation**: Every public class and method must have a Javadoc comment describing purpose, parameters, and return values.

### Error Handling
- Convert runtime exceptions (e.g., `IllegalArgumentException`) to structured JSON responses:
  ```json
  {"success":false,"error":"<message>","details":{}}
  ```
- Always log the stack trace via `DebugLogger`.

### Utilities (must‑use)
- `AddressUtil.formatAddress()` – consistent address formatting.
- `ProgramLookupUtil.getValidatedProgram()` – safe program resolution.
- `AbstractToolProvider` helper methods (`getString`, `getInt`, `getOptional*`).
- `HighFunctionDBUtil.updateDBVariable()` – persist changes inside a transaction.

---

## Testing Practices
- **Unit tests**: Use JUnit 4 only (no JUnit 5 annotations).
- **Integration tests**: Set `java.awt.headless=false` and fork each test (`forkEvery 1`).
- Validate program state changes with Ghidra APIs (`Function.getParameters()`, `DataType.isEquivalent()`).
- Ensure all tests pass before committing; the CI pipeline runs `gradle check`.

---

## Copilot / Cursor Rules

- Follow the guidance in **.github/copilot-instructions.md** for using the MCP SDK, Gradle (no wrapper), and Java 21.
- No `.cursor` rules are present in this repository; adhere to the style conventions outlined above for all contributions.

---

## Additional Resources

- [MCP Java SDK](https://modelcontextprotocol.io/sdk/java/mcp-server)
- Ghidra documentation: start from `FlatProgramAPI` or `ProgramPlugin`.
- Project README for high‑level overview and installation steps.
