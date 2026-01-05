# CLAUDE.md - Source Directory Overview

This file provides guidance for Claude Code when working with the ReVa source code. This is the top-level documentation for the `src/` directory structure.

## Quick Reference

| Item | Value |
|------|-------|
| **MCP SDK Version** | v0.17.0 |
| **Jackson Version** | 2.20.x |
| **Jetty Version** | 11.0.26 |
| **PyGhidra Version** | 3.0.0+ |
| **JUnit Version** | JUnit 4 (NOT JUnit 5) |
| **Build Command** | `gradle` (NOT `./gradlew`) |
| **Unit Tests** | `gradle test` |
| **Integration Tests** | `gradle integrationTest` |
| **Python Tests** | `uv run pytest` |

## Directory Structure

| Directory | Purpose | Documentation |
|-----------|---------|---------------|
| `main/java/reva/` | Java extension code | See package-level CLAUDE.md files |
| `test/` | Java unit tests (no Ghidra env) | Fast tests for utilities/logic |
| `test.slow/` | Java integration tests (GUI required) | [test.slow/CLAUDE.md](test.slow/CLAUDE.md) |
| `reva_cli/` | Python CLI for stdio transport | Python package for `mcp-reva` |

## Testing Guidelines

### Test Types and Locations

| Test Type | Location | Requirements | Command |
|-----------|----------|--------------|---------|
| Java Unit | `test/` | No Ghidra environment | `gradle test` |
| Java Integration | `test.slow/` | GUI environment, fork=1 | `gradle integrationTest` |
| Python Unit | `tests/` (marker: `unit`) | Mocked PyGhidra | `uv run pytest -m unit` |
| Python Integration | `tests/` (marker: `integration`) | PyGhidra available | `uv run pytest -m integration` |
| Python E2E | `tests/` (marker: `e2e`) | Full CLI subprocess | `uv run pytest -m e2e` |

### Critical Integration Test Requirements

- **ALWAYS validate actual Ghidra program state changes**, not just MCP responses
- Use `Function.getParameters()` and `Function.getAllVariables()` to verify variable changes
- Use `DataType.isEquivalent()` to compare datatypes before/after modifications
- Tests require `java.awt.headless=false` and `forkEvery=1`
- **You are not finished until all tests pass!**

### JUnit Version

Use JUnit 4 for all Java tests:
```java
// CORRECT - JUnit 4
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

// WRONG - JUnit 5 (causes compilation errors)
import org.junit.jupiter.api.Test;           // DO NOT USE
import org.junit.jupiter.params.ParameterizedTest; // DO NOT USE
```

## Address Formatting

**ALWAYS use `AddressUtil.formatAddress(address)`** for consistent address formatting in JSON output:

```java
import reva.util.AddressUtil;

// CORRECT - Consistent "0x" prefix
String formatted = AddressUtil.formatAddress(address);
// Returns: "0x404000"

// WRONG - Inconsistent format
String wrong = address.toString(); // May not have "0x" prefix
```

## Decompiler Tool Implementation

### Adding New Tools to DecompilerToolProvider

| Step | Action |
|------|--------|
| 1 | Create `register[ToolName]Tool()` method following existing patterns |
| 2 | Call it from `registerTools()` method |
| 3 | Use `HighFunctionDBUtil.updateDBVariable()` for persisting variable changes |
| 4 | Follow the `rename-variables` pattern for consistency |
| 5 | Handle decompilation with proper error handling and transaction management |

### Key Decompiler APIs

| API | Usage |
|-----|-------|
| `DataTypeParserUtil.parseDataTypeObjectFromString()` | Parse datatype strings ("char*", "int[10]") |
| `HighFunctionDBUtil.updateDBVariable()` | Persist variable changes to database |
| `DecompInterface` | Get decompiled function (ALWAYS dispose!) |
| `LocalSymbolMap.getSymbols()` | Returns Iterator (use while loop, not for-each) |

### Common Patterns

```java
// Transaction management for all program modifications
int txId = program.startTransaction("Tool operation");
try {
    // Perform modifications
    program.endTransaction(txId, true);
} catch (Exception e) {
    program.endTransaction(txId, false);
    throw e;
}

// Decompiler disposal pattern
DecompInterface decompiler = new DecompInterface();
try {
    decompiler.openProgram(program);
    DecompileResults results = decompiler.decompileFunction(function, 30, null);
    if (!results.decompileCompleted()) {
        return createErrorResult("Decompilation failed: " + results.getErrorMessage());
    }
    // Process results...
} finally {
    decompiler.dispose(); // ALWAYS dispose to prevent memory leaks
}

// LocalSymbolMap iteration (NOT Iterable!)
Iterator<HighSymbol> symbolIter = localSymMap.getSymbols();
while (symbolIter.hasNext()) {
    HighSymbol symbol = symbolIter.next();
    // Process symbol
}
```

### Parameter Handling

**Use AbstractToolProvider helper methods** for type conversion and validation:

```java
// Required parameters (auto-converts types)
String programPath = getString(request, "programPath");
int count = getInt(request, "maxCount");

// Optional parameters with defaults
int startIndex = getOptionalInt(request, "startIndex", 0);
boolean verbose = getOptionalBoolean(request, "verbose", false);

// Exception handling is automatic - registerTool() wraps handlers
// to catch IllegalArgumentException and ProgramValidationException
```

## Critical Utility Usage

**ALWAYS use ReVa utilities instead of direct Ghidra APIs**:

| Utility | Method | Purpose |
|---------|--------|---------|
| `AddressUtil` | `formatAddress()` | **REQUIRED** for all address formatting in JSON |
| `ProgramLookupUtil` | `getValidatedProgram()` | **REQUIRED** for program resolution with helpful errors |
| `AbstractToolProvider` | `getProgramFromArgs()` | **REQUIRED** for tool parameter extraction |
| `DataTypeParserUtil` | `parseDataTypeObjectFromString()` | Parse datatype strings |
| `HighFunctionDBUtil` | `updateDBVariable()` | **REQUIRED** for persisting variable changes |
| `SymbolUtil` | `isDefaultSymbolName()` | Filter Ghidra-generated names |

## Troubleshooting

### Common Build Issues

| Problem | Solution |
|---------|----------|
| Jackson conflicts | Run `rm lib/*.jar` and rebuild |
| JUnit 5 compilation errors | Replace with JUnit 4 annotations |
| Integration tests fail | Ensure `java.awt.headless=false` |
| Tests interfere with each other | Ensure `forkEvery=1` in build.gradle |
| Gradle wrapper not found | Use `gradle` directly, not `./gradlew` |

### Common Runtime Issues

| Problem | Solution |
|---------|----------|
| Memory leaks | Always dispose `DecompInterface` instances |
| Program not found | Use `ProgramLookupUtil.getValidatedProgram()` for helpful errors |
| Transaction errors | Always use try-finally for `startTransaction`/`endTransaction` |
| Iterator exceptions | Check API - `LocalSymbolMap.getSymbols()` returns Iterator, not Iterable |

## Related Documentation

### Essential Infrastructure
- [util/CLAUDE.md](main/java/reva/util/CLAUDE.md) - Foundational utilities (AddressUtil, ProgramLookupUtil, etc.)
- [plugin/CLAUDE.md](main/java/reva/plugin/CLAUDE.md) - ConfigManager, plugin lifecycle
- [server/CLAUDE.md](main/java/reva/server/CLAUDE.md) - MCP server architecture

### Tool Providers
- [tools/CLAUDE.md](main/java/reva/tools/CLAUDE.md) - Tool provider patterns and base classes
- [tools/decompiler/CLAUDE.md](main/java/reva/tools/decompiler/CLAUDE.md) - Decompiler tools
- [tools/functions/CLAUDE.md](main/java/reva/tools/functions/CLAUDE.md) - Function analysis tools

### Testing
- [test.slow/CLAUDE.md](test.slow/CLAUDE.md) - Integration test base class and patterns

### Supporting Systems
- [resources/CLAUDE.md](main/java/reva/resources/CLAUDE.md) - MCP resource providers
- [services/CLAUDE.md](main/java/reva/services/CLAUDE.md) - Service interfaces
- [headless/CLAUDE.md](main/java/reva/headless/CLAUDE.md) - Headless mode support
