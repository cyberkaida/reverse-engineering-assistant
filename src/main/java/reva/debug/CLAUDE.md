# CLAUDE.md - Debug Package

This package provides debug capture functionality for troubleshooting ReVa issues.

## Overview

The debug capture feature creates a zip file containing diagnostic information that can be shared when reporting issues. It captures system info, Ghidra config, ReVa status, open programs, and application logs.

## Components

### DebugInfoCollector

Collects debug information into Maps for JSON serialization:
- `collectSystemInfo()` - Java version, OS info
- `collectGhidraInfo()` - Ghidra version, installed extensions
- `collectRevaInfo()` - ReVa configuration settings
- `collectMcpServerInfo()` - Server status, tool providers
- `collectOpenPrograms()` - Open programs with metadata

### DebugCaptureService

Creates the debug zip file:
- Calls `DebugInfoCollector` to gather all info
- Writes `debug-info.json` with collected data
- Includes last 5000 lines of `application.log`
- Adds a `README.txt` summary

## Access

**Menu**: Tools -> ReVa -> Capture Debug Info

The menu action prompts for an optional message describing the issue, then creates the zip in the system temp directory.

## Output Format

```
reva-debug-YYYY-MM-DDTHH-mm-ss.zip
├── debug-info.json       # All collected info as JSON
├── application.log.txt   # Truncated Ghidra log
└── README.txt            # Summary of contents
```

## Adding New Information

To capture additional debug info:
1. Add a new method to `DebugInfoCollector`
2. Call it from `collectAll()`
3. Data will automatically be included in the JSON output
