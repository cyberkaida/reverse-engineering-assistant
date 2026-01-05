# CLAUDE.md - Constants Tool Provider

This file provides guidance to Claude Code when working with the constants tool provider in ReVa.

## Package Overview

The `reva.tools.constants` package provides MCP tools for searching and analyzing constant values (immediate operands) used in program instructions. This helps identify magic numbers, error codes, buffer sizes, and other significant values across the codebase.

## Key Tools

### Constant Search Tools
- `find-constant-uses` - Find all locations where a specific constant value appears
- `find-constants-in-range` - Find constants within a specified numeric range
- `list-common-constants` - Identify the most frequently used constants in the program

## Tool Details

### find-constant-uses
Searches for all instruction operands matching a specific constant value.

**Parameters:**
- `programPath` (required) - Path to the program
- `value` (required) - Constant to search for (supports decimal, hex with 0x prefix, or negative)
- `maxResults` (optional) - Maximum results to return (default: 500, max: 10000)

**Use cases:**
- Finding all uses of a magic number (e.g., `0xdeadbeef`)
- Locating error code references
- Identifying buffer size constants

### find-constants-in-range
Finds all constant values within a numeric range.

**Parameters:**
- `programPath` (required) - Path to the program
- `minValue` (required) - Minimum value (inclusive, supports decimal/hex)
- `maxValue` (required) - Maximum value (inclusive, supports decimal/hex)
- `maxResults` (optional) - Maximum results to return (default: 500, max: 10000)

**Use cases:**
- Finding HTTP status codes (400-599)
- Locating enum values within expected bounds
- Identifying constants in a specific numeric range

**Response includes:**
- `uniqueValues` - List of unique values found with occurrence counts (sorted by frequency)
- `results` - Individual instruction locations for each match

### list-common-constants
Identifies the most frequently used constants in the program.

**Parameters:**
- `programPath` (required) - Path to the program
- `topN` (optional) - Number of constants to return (default: 50, max: 10000)
- `minValue` (optional) - Explicit minimum value filter
- `includeSmallValues` (optional) - Include values 0-255 (default: false, filters noise)

**Response includes:**
- `value` - Formatted value (hex and decimal)
- `decimal` - Raw decimal value
- `occurrences` - Total occurrence count
- `uniqueFunctions` - Number of different functions using this constant
- `description` - Human-readable description for known constants (if available)
- `sampleLocations` - Up to 5 sample addresses where constant appears

**Use cases:**
- Discovering important magic numbers
- Identifying frequently used sizes or flags
- Understanding program constants without noise

## Core Implementation Patterns

### Constant Value Parsing
The tool supports flexible constant value input:

```java
private long parseConstantValue(String valueStr) throws NumberFormatException {
    valueStr = valueStr.trim();

    // Handle hex (0x prefix)
    if (valueStr.toLowerCase().startsWith("0x")) {
        return Long.parseUnsignedLong(valueStr.substring(2), 16);
    }

    // Handle negative numbers
    if (valueStr.startsWith("-")) {
        return Long.parseLong(valueStr);
    }

    // Handle decimal
    return Long.parseUnsignedLong(valueStr);
}
```

**Supported formats:**
- Decimal: `123`, `65536`
- Hexadecimal: `0x7b`, `0xdeadbeef`
- Negative: `-1`, `-256`

### Signed vs Unsigned Comparison
Constants can be interpreted as both signed and unsigned. The tools check both representations:

```java
Scalar scalar = instr.getScalar(operandIndex);
long unsignedValue = scalar.getUnsignedValue();
long signedValue = scalar.getSignedValue();

// Check both interpretations
if (unsignedValue == targetValue) {
    // Match found (unsigned interpretation)
} else if (signedValue == targetValue) {
    // Match found (signed interpretation)
}
```

**Important:** Use `Long.compareUnsigned()` for proper unsigned comparisons:
```java
// Correct unsigned comparison
if (Long.compareUnsigned(unsignedValue, minValue) >= 0
        && Long.compareUnsigned(unsignedValue, maxValue) <= 0) {
    // In range
}

// WRONG - treats values as signed
if (unsignedValue >= minValue && unsignedValue <= maxValue) {
    // Incorrect for large unsigned values
}
```

### Noise Filtering
By default, `list-common-constants` filters out small values (0-255) and -1 as these are typically noise:

```java
private boolean isNoiseValue(long unsignedValue, long signedValue) {
    // Small unsigned values (0-255) are usually noise
    if (Long.compareUnsigned(unsignedValue, 255) <= 0) {
        return true;
    }
    // -1 in any representation
    if (signedValue == -1) {
        return true;
    }
    return false;
}
```

Users can override this with `includeSmallValues: true`.

### Value Formatting
Constants are formatted with both hex and decimal for clarity:

```java
private String formatValue(long value) {
    if (value == 0) {
        return "0";
    }
    return String.format("0x%x (%d)", value, value);
}
// Examples: "0x100 (256)", "0xdeadbeef (3735928559)"
```

## Constant Description System

The tool provides human-readable descriptions for well-known constants:

### Description Categories (in priority order)

1. **Common sizes** (checked first for specificity):
   - `1024` → "1 KB"
   - `4096` → "4 KB (page size)"
   - `0x100000` → "1 MB"

2. **Bit masks and limits**:
   - `0x7fffffff` → "INT32_MAX"
   - `0x80000000` → "INT32_MIN / sign bit"
   - `0xffffffff` → "32-bit mask / -1"

3. **Generic powers of 2** (after specific sizes):
   ```java
   if (value > 0 && (value & (value - 1)) == 0) {
       int power = Long.numberOfTrailingZeros(value);
       return "2^" + power + " (power of 2)";
   }
   ```

4. **HTTP status codes**: `100-599` → "Possible HTTP status code"

5. **Windows error codes**: `0x80000000-0x8000ffff` → "Possible HRESULT/NTSTATUS"

6. **Magic numbers**:
   - `0x5a4d` → "MZ header"
   - `0x4550` → "PE signature"
   - `0xdeadbeef` → "Debug marker"
   - `0xcafebabe` → "Java class / Mach-O FAT"

**Adding new descriptions:** Extend `describeConstant()` method, placing more specific checks before generic ones.

## Performance and Safety

### Safety Limits
```java
private static final int DEFAULT_TIMEOUT_SECONDS = 120;
private static final int DEFAULT_MAX_RESULTS = 500;
private static final int MAX_RESULTS_LIMIT = 10000;  // Prevents abuse
private static final int MAX_INSTRUCTIONS = 2_000_000;  // Prevents runaway on huge binaries
private static final int MAX_SAMPLE_LOCATIONS = 5;  // Per-constant sample limit
```

### Timeout Handling
All tools use `TimeoutTaskMonitor` to prevent hanging on large programs:

```java
private TaskMonitor createTimeoutMonitor() {
    return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
}

// Check cancellation in loops
while (instructions.hasNext()) {
    monitor.checkCancelled();  // Throws CancelledException on timeout
    // Process instruction
}
```

### Result Clamping
```java
private int clampMaxResults(int value) {
    if (value <= 0) {
        return DEFAULT_MAX_RESULTS;
    }
    return Math.min(value, MAX_RESULTS_LIMIT);
}
```

## Instruction Operand Iteration

### Scanning for Scalar Operands
```java
InstructionIterator instructions = listing.getInstructions(true);
while (instructions.hasNext()) {
    Instruction instr = instructions.next();

    // Check each operand for scalar values
    for (int i = 0; i < instr.getNumOperands(); i++) {
        Scalar scalar = instr.getScalar(i);
        if (scalar != null) {
            long unsignedValue = scalar.getUnsignedValue();
            long signedValue = scalar.getSignedValue();
            // Process constant
        }
    }
}
```

**Important:** Only count once per instruction to avoid duplicate results when multiple operands match.

## Response Patterns

### find-constant-uses Response
```json
{
  "programPath": "/program.exe",
  "searchedValue": "0xdeadbeef (3735928559)",
  "resultCount": 42,
  "truncated": false,
  "results": [
    {
      "address": "0x00401234",
      "mnemonic": "mov",
      "operandIndex": 1,
      "instruction": "MOV EAX, 0xdeadbeef",
      "value": "0xdeadbeef (3735928559)",
      "function": "main",
      "functionAddress": "0x00401000"
    }
  ]
}
```

### find-constants-in-range Response
```json
{
  "programPath": "/program.exe",
  "range": {
    "min": "0x190 (400)",
    "max": "0x257 (599)"
  },
  "uniqueValuesFound": 12,
  "totalOccurrences": 38,
  "truncated": false,
  "uniqueValues": [
    {
      "value": "0x194 (404)",
      "decimal": 404,
      "occurrences": 15
    }
  ],
  "results": [ /* instruction details */ ]
}
```

### list-common-constants Response
```json
{
  "programPath": "/program.exe",
  "totalUniqueConstants": 1523,
  "returned": 50,
  "filterApplied": "excluded noise values (0-255, -1)",
  "constants": [
    {
      "value": "0x1000 (4096)",
      "decimal": 4096,
      "occurrences": 127,
      "uniqueFunctions": 23,
      "description": "4 KB (page size)",
      "sampleLocations": [
        "0x00401234",
        "0x00401567",
        "0x00402000"
      ]
    }
  ]
}
```

## ConstantInfo Helper Class

Tracks statistics for a single constant value:

```java
private static class ConstantInfo {
    final long value;
    int count = 0;  // Total occurrences
    final List<String> locations = new ArrayList<>();  // Sample locations (max 5)
    final Set<String> functions = new HashSet<>();  // Unique function names

    void addOccurrence(Address addr, Program program) {
        count++;
        if (locations.size() < MAX_SAMPLE_LOCATIONS) {
            locations.add(AddressUtil.formatAddress(addr));
        }
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            functions.add(func.getName());
        }
    }
}
```

## Common Use Cases

### Finding Magic Numbers
```json
// Find all uses of a specific magic number
{
  "programPath": "/game.exe",
  "value": "0xdeadbeef"
}
```

### Identifying Error Code Ranges
```json
// Find HTTP error codes (400-599)
{
  "programPath": "/server.exe",
  "minValue": "400",
  "maxValue": "599"
}
```

### Discovering Important Constants
```json
// Get top 100 constants, excluding noise
{
  "programPath": "/program.exe",
  "topN": 100,
  "includeSmallValues": false
}
```

### Analyzing Large Constants Only
```json
// Find constants >= 1KB
{
  "programPath": "/program.exe",
  "minValue": "1024",
  "topN": 50
}
```

## Testing Considerations

### Test Data Requirements
- Programs with various constant types (sizes, flags, error codes, magic numbers)
- Both small (0-255) and large constants
- Negative constants
- Edge cases (INT_MAX, INT_MIN, bit masks)

### Integration Tests
- Verify both signed and unsigned value matching
- Test range queries with boundary conditions
- Validate noise filtering behavior
- Check timeout handling on large programs
- Ensure result truncation works correctly
- Test constant description accuracy

### Performance Tests
- Verify MAX_INSTRUCTIONS limit prevents runaway
- Check timeout behavior on large binaries
- Validate memory usage with many unique constants

## Important Notes

- **Dual interpretation:** Always check both signed and unsigned values for matching
- **Unsigned comparison:** Use `Long.compareUnsigned()` for proper unsigned range checks
- **Noise filtering:** Default filters 0-255 and -1, can be overridden
- **Sample locations:** Limited to 5 per constant to prevent memory bloat
- **Instruction limits:** Stops at 2M instructions to prevent runaway on huge binaries
- **Timeout protection:** 120-second timeout prevents hanging
- **Result clamping:** Max 10000 results to prevent abuse
- **Function context:** Includes function name/address when available
- **Description priority:** More specific descriptions checked before generic ones
- **Value formatting:** Always shows both hex and decimal (except for 0)
