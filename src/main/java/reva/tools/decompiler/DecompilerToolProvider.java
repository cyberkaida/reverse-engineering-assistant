/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.decompiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Matcher;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.UndefinedFunction;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.DecompilationContextUtil;
import reva.util.DecompilationDiffUtil;
import reva.util.DebugLogger;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for function decompilation operations.
 */
public class DecompilerToolProvider extends AbstractToolProvider {

    // Track which functions have been read by the LLM to enforce read-before-modify pattern
    private final Map<String, Long> readDecompilationTracker = new ConcurrentHashMap<>();

    /**
     * Constructor
     * @param server The MCP server
     */
    public DecompilerToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Clean up read tracking entries when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        String programPath = program.getDomainFile().getPathname();

        // Remove read tracking entries for the closed program using removeIf (thread-safe)
        int beforeSize = readDecompilationTracker.size();
        readDecompilationTracker.entrySet().removeIf(entry -> entry.getKey().startsWith(programPath + ":"));
        int removed = beforeSize - readDecompilationTracker.size();

        if (removed > 0) {
            logInfo("DecompilerToolProvider: Cleared " + removed +
                " read tracking entries for closed program: " + programPath);
        }
    }

    @Override
    public void registerTools() {
        registerGetDecompilationTool();
        registerSearchDecompilationTool();
        registerRenameVariablesTool();
        registerChangeVariableDataTypesTool();
        registerSetDecompilationCommentTool();
        registerGetCallersDecompiledTool();
        registerGetReferencersDecompiledTool();
    }

    /**
     * Creates a TaskMonitor with timeout configured from settings
     * @return TaskMonitor with timeout from configuration
     */
    private TaskMonitor createTimeoutMonitor() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager.getDecompilerTimeoutSeconds();
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private boolean isTimedOut(TaskMonitor monitor) {
        return monitor.isCancelled();
    }

    private int getTimeoutSeconds() {
        return RevaInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
    }

    // ============================================================================
    // Helper Infrastructure for Decompiler Operations
    // ============================================================================

    /** Expiry time for read tracking entries (30 minutes) */
    private static final long READ_TRACKING_EXPIRY_MS = TimeUnit.MINUTES.toMillis(30);

    /** Maximum callers to include in get-decompilation response */
    private static final int MAX_CALLERS_IN_DECOMPILATION = 50;

    /** Maximum callees to include in get-decompilation response */
    private static final int MAX_CALLEES_IN_DECOMPILATION = 50;

    /** Check timeout every N instructions during reference counting */
    private static final int TIMEOUT_CHECK_INSTRUCTION_INTERVAL = 100;

    /** Check timeout every N references during reference counting */
    private static final int TIMEOUT_CHECK_REFERENCE_INTERVAL = 50;

    /** Map of Ghidra comment types to their string names for JSON output */
    private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        CommentType.PRE, "pre",
        CommentType.EOL, "eol",
        CommentType.POST, "post",
        CommentType.PLATE, "plate",
        CommentType.REPEATABLE, "repeatable"
    );

    /**
     * Result of a safe decompilation attempt. Encapsulates either a successful
     * decompilation result or an error message.
     */
    private record DecompilationAttempt(
        DecompileResults results,
        String errorMessage,
        boolean success
    ) {
        static DecompilationAttempt success(DecompileResults results) {
            return new DecompilationAttempt(results, null, true);
        }

        static DecompilationAttempt failure(String message) {
            return new DecompilationAttempt(null, message, false);
        }
    }

    /**
     * Functional interface for processing high-level symbols during variable iteration.
     */
    @FunctionalInterface
    private interface SymbolProcessor {
        /**
         * Process a single symbol.
         * @param symbol The high-level symbol to process
         * @return true if processing was successful and changed something, false otherwise
         * @throws DuplicateNameException if a name conflict occurs
         * @throws InvalidInputException if the input is invalid
         */
        boolean process(HighSymbol symbol) throws DuplicateNameException, InvalidInputException;
    }

    /**
     * Creates and configures a DecompInterface for standard decompilation operations.
     * The caller is responsible for disposing the decompiler in a finally block.
     *
     * @param program The program to decompile
     * @param toolName The name of the tool (for logging)
     * @return A configured and initialized DecompInterface, or null if initialization failed
     */
    private DecompInterface createConfiguredDecompiler(Program program, String toolName) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            logError(toolName + ": Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    /**
     * Decompiles a function with timeout handling and consistent error reporting.
     *
     * @param decompiler The initialized decompiler to use
     * @param function The function to decompile
     * @param toolName The name of the tool (for logging)
     * @return DecompilationAttempt containing either the results or an error message
     */
    private DecompilationAttempt decompileFunctionSafely(
            DecompInterface decompiler,
            Function function,
            String toolName) {
        TaskMonitor timeoutMonitor = createTimeoutMonitor();
        DecompileResults results = decompiler.decompileFunction(function, 0, timeoutMonitor);

        if (isTimedOut(timeoutMonitor)) {
            String msg = "Decompilation timed out after " + getTimeoutSeconds() + " seconds";
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        return DecompilationAttempt.success(results);
    }

    /**
     * Gets updated decompilation after modifications and creates a diff against the original.
     *
     * @param program The program containing the function
     * @param function The function to re-decompile
     * @param beforeDecompilation The original decompilation text to compare against
     * @param toolName The name of the tool (for logging)
     * @return Map containing diff results or error information
     */
    private Map<String, Object> getDecompilationDiff(
            Program program,
            Function function,
            String beforeDecompilation,
            String toolName) {
        Map<String, Object> result = new HashMap<>();

        DecompInterface newDecompiler = createConfiguredDecompiler(program, toolName + "-diff");
        if (newDecompiler == null) {
            result.put("decompilationError", "Failed to initialize decompiler for diff");
            return result;
        }

        try {
            DecompilationAttempt attempt = decompileFunctionSafely(newDecompiler, function, toolName + "-diff");
            if (!attempt.success()) {
                result.put("decompilationError", attempt.errorMessage());
                return result;
            }

            String afterDecompilation = attempt.results().getDecompiledFunction().getC();
            DecompilationDiffUtil.DiffResult diff =
                DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);

            if (diff.hasChanges()) {
                result.put("changes", DecompilationDiffUtil.toMap(diff));
            } else {
                result.put("changes", Map.of(
                    "hasChanges", false,
                    "summary", "No changes detected in decompilation"
                ));
            }
        } catch (Exception e) {
            logError(toolName + "-diff: Error during diff decompilation", e);
            result.put("decompilationError", "Exception during decompilation: " + e.getMessage());
        } finally {
            newDecompiler.dispose();
        }

        return result;
    }

    /**
     * Processes all variables (local and global) in a high function using the provided processor.
     *
     * @param highFunction The high function containing the variables
     * @param processor The processor to apply to each symbol
     * @param toolName The name of the tool (for logging)
     * @return The number of symbols successfully processed
     */
    private int processAllVariables(HighFunction highFunction, SymbolProcessor processor, String toolName) {
        int processedCount = 0;

        // Process local variables
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                logError(toolName + ": Failed to process local variable " + symbol.getName(), e);
            }
        }

        // Process global variables
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                logError(toolName + ": Failed to process global variable " + symbol.getName(), e);
            }
        }

        return processedCount;
    }

    /**
     * Finds the address corresponding to a line number in decompiled code.
     *
     * @param program The program
     * @param clangLines The decompiled code lines
     * @param lineNumber The line number to find (1-based)
     * @return The address for the line, or null if not found
     */
    private Address findAddressForLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        for (ClangLine clangLine : clangLines) {
            if (clangLine.getLineNumber() == lineNumber) {
                List<ClangToken> tokens = clangLine.getAllTokens();

                // Find the first address on this line
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        return tokenAddr;
                    }
                }

                // If no direct address, find closest
                if (!tokens.isEmpty()) {
                    return DecompilerUtils.getClosestAddress(program, tokens.get(0));
                }
                break;
            }
        }
        return null;
    }

    /**
     * Processes variable data type changes for all variables in a high function.
     * This method handles the specific logic for data type changes including error collection.
     *
     * @param highFunction The high function containing the variables
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return The number of variables successfully changed
     */
    private int processVariableDataTypeChanges(
            HighFunction highFunction,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        int changedCount = 0;

        // Process local variables
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        // Process global variables
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        return changedCount;
    }

    /**
     * Processes a single data type change for a symbol.
     *
     * @param symbol The symbol to process
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return true if the data type was changed, false otherwise
     */
    private boolean processDataTypeChange(
            HighSymbol symbol,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        String varName = symbol.getName();
        String newDataTypeString = mappings.get(varName);

        if (newDataTypeString == null) {
            return false;
        }

        try {
            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                newDataTypeString, archiveName);

            if (newDataType == null) {
                errors.add("Could not find data type: " + newDataTypeString + " for variable " + varName);
                return false;
            }

            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
            logInfo(toolName + ": Changed data type of variable " + varName + " to " + newDataTypeString);
            return true;
        } catch (DuplicateNameException | InvalidInputException e) {
            errors.add("Failed to change data type of variable " + varName + " to " + newDataTypeString + ": " + e.getMessage());
        } catch (Exception e) {
            errors.add("Error parsing data type " + newDataTypeString + " for variable " + varName + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Result of counting call references with timeout handling.
     */
    private record CallCountResult(
        Map<Address, Integer> callCounts,
        boolean timedOut
    ) {}

    /**
     * Count call references for a function (either callers or callees) with timeout handling.
     * This method handles the iteration over instructions and references consistently.
     *
     * @param program The program
     * @param function The function to count calls for
     * @param countCallers true to count callers (references TO this function),
     *                     false to count callees (references FROM this function)
     * @return CallCountResult containing the counts and timeout status
     */
    private CallCountResult countCallsWithTimeout(Program program, Function function, boolean countCallers) {
        TaskMonitor monitor = createTimeoutMonitor();
        Map<Address, Integer> callCounts = new HashMap<>();
        boolean timedOut = false;

        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();
        AddressSetView functionBody = function.getBody();

        int instrCount = 0;
        int refCount = 0;

        for (Instruction instr : listing.getInstructions(functionBody, true)) {
            // Check timeout periodically on instruction boundary
            if (++instrCount % TIMEOUT_CHECK_INSTRUCTION_INTERVAL == 0 && monitor.isCancelled()) {
                timedOut = true;
                break;
            }

            if (countCallers) {
                // For callers: get references TO each instruction in this function
                ReferenceIterator refsTo = refManager.getReferencesTo(instr.getAddress());
                while (refsTo.hasNext()) {
                    // Check timeout in inner loop for addresses with many references
                    if (++refCount % TIMEOUT_CHECK_REFERENCE_INTERVAL == 0 && monitor.isCancelled()) {
                        timedOut = true;
                        break;
                    }
                    Reference ref = refsTo.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            callCounts.merge(caller.getEntryPoint(), 1, Integer::sum);
                        }
                    }
                }
                if (timedOut) break;
            } else {
                // For callees: get references FROM each instruction in this function
                // No inner-loop timeout check needed here because getReferencesFrom() typically
                // returns very few references per instruction (usually 0-1 call targets),
                // unlike getReferencesTo() which can return thousands for popular functions
                Reference[] refsFrom = instr.getReferencesFrom();
                for (Reference ref : refsFrom) {
                    if (ref.getReferenceType().isCall()) {
                        callCounts.merge(ref.getToAddress(), 1, Integer::sum);
                    }
                }
            }
        }

        return new CallCountResult(callCounts, timedOut);
    }

    /**
     * Build a list of caller/callee info maps for the result.
     *
     * @param functions The set of functions (callers or callees)
     * @param callCounts Map of entry point addresses to call counts
     * @param maxCount Maximum number to include
     * @param isCallers true if building caller info, false for callee info
     * @return List of function info maps
     */
    private List<Map<String, Object>> buildCallListInfo(
            Set<Function> functions,
            Map<Address, Integer> callCounts,
            int maxCount,
            boolean isCallers) {
        List<Map<String, Object>> resultList = new ArrayList<>();
        int count = 0;

        for (Function func : functions) {
            if (count >= maxCount) break;

            Map<String, Object> funcInfo = new HashMap<>();
            funcInfo.put("name", func.getName());
            funcInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
            funcInfo.put("signature", func.getSignature().getPrototypeString());
            funcInfo.put("callCount", callCounts.getOrDefault(func.getEntryPoint(), 0));

            resultList.add(funcInfo);
            count++;
        }

        return resultList;
    }

    // ============================================================================
    // Tool Registration Methods
    // ============================================================================

    /**
     * Register a tool to get decompiled code for a function with line range support (Claude Code style)
     */
    private void registerGetDecompilationTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to decompile (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be decompiled."
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Line number to start reading from (1-based). Defaults to 1.",
            "default", 1
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Number of lines to return. Defaults to 50 lines to conserve context. Use smaller chunks (10-20 lines) for initial exploration, then expand as needed.",
            "default", 50
        ));
        properties.put("includeDisassembly", Map.of(
            "type", "boolean",
            "description", "Whether to include assembly listing alongside decompilation for sync",
            "default", false
        ));
        properties.put("includeComments", Map.of(
            "type", "boolean",
            "description", "Whether to include comments in the decompilation output",
            "default", false
        ));
        properties.put("includeIncomingReferences", Map.of(
            "type", "boolean",
            "description", "Whether to include incoming cross references to this function on the function declaration line",
            "default", true
        ));
        properties.put("includeReferenceContext", Map.of(
            "type", "boolean",
            "description", "Whether to include code context snippets from calling functions (requires includeIncomingReferences)",
            "default", true
        ));
        properties.put("includeCallers", Map.of(
            "type", "boolean",
            "description", "Include list of functions that call this one (name, address, signature). Use for understanding function usage without bulk decompilation.",
            "default", false
        ));
        properties.put("includeCallees", Map.of(
            "type", "boolean",
            "description", "Include list of functions this one calls (name, address, signature). Use for understanding function dependencies without bulk decompilation.",
            "default", false
        ));
        properties.put("signatureOnly", Map.of(
            "type", "boolean",
            "description", "Return only signature/metadata without decompiled code. Saves output tokens.",
            "default", false
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-decompilation")
            .title("Get Function Decompilation")
            .description("Get decompiled code for a function with line range support. Defaults to 50 lines to conserve context - start with small chunks (10-20 lines) then expand as needed using offset/limit. Updating variable data types and names can significantly improve decompilation quality. Use includeCallers/includeCallees to get caller/callee lists in one call (avoids separate tool invocations).")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters using helper methods
            Program program = getProgramFromArgs(request);
            String functionNameOrAddress = getString(request, "functionNameOrAddress");
            int offset = getOptionalInt(request, "offset", 1);
            Integer limit = getOptionalInteger(request.arguments(), "limit", 50); // Default to 50 lines for context conservation
            boolean includeDisassembly = getOptionalBoolean(request, "includeDisassembly", false);
            boolean includeComments = getOptionalBoolean(request, "includeComments", false);
            boolean includeIncomingReferences = getOptionalBoolean(request, "includeIncomingReferences", true);
            boolean includeReferenceContext = getOptionalBoolean(request, "includeReferenceContext", true);
            boolean includeCallers = getOptionalBoolean(request, "includeCallers", false);
            boolean includeCallees = getOptionalBoolean(request, "includeCallees", false);
            boolean signatureOnly = getOptionalBoolean(request, "signatureOnly", false);

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());

            Function function = null;
            boolean isUndefinedFunction = false;
            Address resolvedAddress = null;

            // First try to resolve as address or symbol
            Address address = AddressUtil.resolveAddressOrSymbol(program, functionNameOrAddress);
            if (address != null) {
                resolvedAddress = address;
                // Get the containing function for this address
                function = AddressUtil.getContainingFunction(program, address);
                if (function != null) {
                    resultData.put("functionName", function.getName());
                    resultData.put("resolvedFrom", "address/symbol");
                    resultData.put("inputAddress", AddressUtil.formatAddress(address));
                }
            }

            // If not found by address, try by function name
            if (function == null) {
                FunctionManager functionManager = program.getFunctionManager();

                // First try an exact match
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext()) {
                    Function f = functions.next();
                    if (f.getName().equals(functionNameOrAddress)) {
                        function = f;
                        resultData.put("functionName", function.getName());
                        resultData.put("resolvedFrom", "name-exact");
                        break;
                    }
                }

                // If no exact match, try case-insensitive
                if (function == null) {
                    functions = functionManager.getFunctions(true);
                    while (functions.hasNext()) {
                        Function f = functions.next();
                        if (f.getName().equalsIgnoreCase(functionNameOrAddress)) {
                            function = f;
                            resultData.put("functionName", function.getName());
                            resultData.put("resolvedFrom", "name-case-insensitive");
                            break;
                        }
                    }
                }
            }

            // If still no function found and we have an address, try UndefinedFunction
            if (function == null && resolvedAddress != null) {
                // Validate address is in executable memory
                MemoryBlock block = program.getMemory().getBlock(resolvedAddress);
                if (block == null) {
                    return createErrorResult("Address " + AddressUtil.formatAddress(resolvedAddress) +
                        " is not in any memory block");
                }
                if (!block.isExecute()) {
                    return createErrorResult("Address " + AddressUtil.formatAddress(resolvedAddress) +
                        " is not in executable memory (block: " + block.getName() + ")");
                }

                // Check if there's an instruction at the address
                Instruction instr = program.getListing().getInstructionAt(resolvedAddress);
                if (instr == null) {
                    return createErrorResult("No instruction at address " +
                        AddressUtil.formatAddress(resolvedAddress) +
                        ". The address may need to be disassembled first, or it may be in the middle of an instruction.");
                }

                // Try to create a temporary function using UndefinedFunction
                // Use timeout monitor to prevent hanging on complex code
                TaskMonitor undefinedFuncMonitor = createTimeoutMonitor();
                function = UndefinedFunction.findFunction(program, resolvedAddress, undefinedFuncMonitor);
                if (function != null) {
                    isUndefinedFunction = true;
                    resultData.put("functionName", function.getName());
                    resultData.put("resolvedFrom", "undefined-function");
                    resultData.put("inputAddress", AddressUtil.formatAddress(resolvedAddress));
                    logInfo("get-decompilation: Created temporary function at " +
                        AddressUtil.formatAddress(resolvedAddress));
                } else if (undefinedFuncMonitor.isCancelled()) {
                    return createErrorResult("Operation timed out while analyzing undefined function at " +
                        AddressUtil.formatAddress(resolvedAddress));
                }
            }

            if (function == null) {
                return createErrorResult("Function not found: " + functionNameOrAddress + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. If this is an undefined address, ensure it's in executable memory with valid instructions.");
            }

            // Mark if this is an undefined/temporary function
            resultData.put("isUndefinedFunction", isUndefinedFunction);
            if (isUndefinedFunction) {
                resultData.put("undefinedFunctionNote",
                    "This is a temporary function created for decompilation preview. " +
                    "Variable modifications are not supported. Use create-function to define it permanently.");
            }

            // Add function details
            resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));

            // Get function metadata
            Map<String, String> metadata = new HashMap<>();
            metadata.put("signature", function.getSignature().toString());
            metadata.put("returnType", function.getReturnType().toString());
            metadata.put("callingConvention", function.getCallingConventionName());
            metadata.put("isExternal", Boolean.toString(function.isExternal()));
            metadata.put("isThunk", Boolean.toString(function.isThunk()));

            // Get parameters info
            List<Map<String, String>> parameters = new ArrayList<>();
            for (int i = 0; i < function.getParameterCount(); i++) {
                Map<String, String> paramInfo = new HashMap<>();
                paramInfo.put("name", function.getParameter(i).getName());
                paramInfo.put("dataType", function.getParameter(i).getDataType().toString());
                paramInfo.put("ordinal", Integer.toString(i));
                parameters.add(paramInfo);
            }
            metadata.put("parameterCount", Integer.toString(function.getParameterCount()));
            resultData.put("metadata", metadata);
            resultData.put("parameters", parameters);

            // Get function bounds
            AddressSetView body = function.getBody();
            resultData.put("startAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            resultData.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            resultData.put("sizeInBytes", body.getNumAddresses());

            // If signatureOnly is true, return early without decompilation
            if (signatureOnly) {
                resultData.put("signatureOnly", true);
                return createJsonResult(resultData);
            }

            // Get decompilation using helper methods
            final String toolName = "get-decompilation";
            logInfo(toolName + ": Starting decompilation for function " + function.getName() +
                    " at " + AddressUtil.formatAddress(function.getEntryPoint()) + " in " + program.getName());

            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);
            if (decompiler == null) {
                resultData.put("decompilationError", "Failed to initialize decompiler");
                resultData.put("decompilation", "");
                return createJsonResult(resultData);
            }

            try {
                DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, toolName);
                if (!attempt.success()) {
                    return createErrorResult(attempt.errorMessage());
                }

                // Get the decompiled code and markup
                DecompiledFunction decompiledFunction = attempt.results().getDecompiledFunction();
                ClangTokenGroup markup = attempt.results().getCCodeMarkup();

                // Get synchronized decompilation with optional assembly listing and comments
                Map<String, Object> syncedContent = getSynchronizedContent(program, markup, decompiledFunction.getC(),
                    offset, limit, includeDisassembly, includeComments, includeIncomingReferences, includeReferenceContext, function);

                // Add content to results
                resultData.putAll(syncedContent);

                // Get additional details like high-level function signature
                resultData.put("decompSignature", decompiledFunction.getSignature());

                // Track that this function's decompilation has been read
                String programPath = getString(request, "programPath");
                String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());
                readDecompilationTracker.put(functionKey, System.currentTimeMillis());

                logInfo(toolName + ": Successfully decompiled " + function.getName());

            } catch (Exception e) {
                logError(toolName + ": Exception during decompilation of " + function.getName(), e);
                resultData.put("decompilationError", "Exception during decompilation: " + e.getMessage());
                resultData.put("decompilation", "");
            } finally {
                decompiler.dispose();
            }

            // Add caller/callee information if requested (outside decompiler scope)
            if (includeCallers && !isUndefinedFunction) {
                TaskMonitor callerMonitor = createTimeoutMonitor();
                Set<Function> callers = function.getCallingFunctions(callerMonitor);

                if (callerMonitor.isCancelled()) {
                    resultData.put("callersError", "Operation timed out while getting callers");
                } else {
                    int totalCallers = callers.size();

                    // Count calls using shared helper (separate timeout monitor)
                    CallCountResult countResult = countCallsWithTimeout(program, function, true);
                    List<Map<String, Object>> callersList = buildCallListInfo(
                        callers, countResult.callCounts(), MAX_CALLERS_IN_DECOMPILATION, true);

                    resultData.put("callers", callersList);
                    resultData.put("callerCount", callersList.size());
                    resultData.put("totalCallerCount", totalCallers);
                    if (totalCallers > MAX_CALLERS_IN_DECOMPILATION) {
                        resultData.put("callersLimited", true);
                    }
                    if (countResult.timedOut()) {
                        resultData.put("callerCallCountsIncomplete", true);
                    }
                }
            }

            if (includeCallees && !isUndefinedFunction) {
                TaskMonitor calleeMonitor = createTimeoutMonitor();
                Set<Function> callees = function.getCalledFunctions(calleeMonitor);

                if (calleeMonitor.isCancelled()) {
                    resultData.put("calleesError", "Operation timed out while getting callees");
                } else {
                    int totalCallees = callees.size();

                    // Count calls using shared helper (separate timeout monitor)
                    CallCountResult countResult = countCallsWithTimeout(program, function, false);
                    List<Map<String, Object>> calleesList = buildCallListInfo(
                        callees, countResult.callCounts(), MAX_CALLEES_IN_DECOMPILATION, false);

                    resultData.put("callees", calleesList);
                    resultData.put("calleeCount", calleesList.size());
                    resultData.put("totalCalleeCount", totalCallees);
                    if (totalCallees > MAX_CALLEES_IN_DECOMPILATION) {
                        resultData.put("calleesLimited", true);
                    }
                    if (countResult.timedOut()) {
                        resultData.put("calleeCallCountsIncomplete", true);
                    }
                }
            }

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to search decompilation across all functions
     */
    private void registerSearchDecompilationTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program to search"
        ));
        properties.put("pattern", Map.of(
            "type", "string",
            "description", "Regular expression pattern to search for in decompiled functions"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of search results to return",
            "default", 50
        ));
        properties.put("caseSensitive", Map.of(
            "type", "boolean",
            "description", "Whether the search should be case sensitive",
            "default", false
        ));
        properties.put("overrideMaxFunctionsLimit", Map.of(
            "type", "boolean",
            "description", "Whether to override the maximum function limit for decompiler searches. Use with caution as large programs may take a long time to search.",
            "default", false
        ));

        List<String> required = List.of("programPath", "pattern");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("search-decompilation")
            .title("Search Function Decompilations")
            .description("Search for patterns across all function decompilations in a program. Returns function names and line numbers where patterns match. If looking for calls or references to data, try the cross reference tools first.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get arguments using helper methods
            Program program = getProgramFromArgs(request);
            String pattern = getString(request, "pattern");
            int maxResults = getOptionalInt(request, "maxResults", 50);
            boolean caseSensitive = getOptionalBoolean(request, "caseSensitive", false);
            boolean overrideMaxFunctionsLimit = getOptionalBoolean(request, "overrideMaxFunctionsLimit", false);

            // Validate pattern
            if (pattern.trim().isEmpty()) {
                return createErrorResult("Search pattern cannot be empty");
            }

            // Get the config manager
            ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
            int maxFunctions = config.getMaxDecompilerSearchFunctions();
            if (program.getFunctionManager().getFunctionCount() > maxFunctions && !overrideMaxFunctionsLimit) {
                return createErrorResult("Program has " + program.getFunctionManager().getFunctionCount() +
                    " functions, which exceeds the maximum limit of " + maxFunctions +
                    ". Use 'overrideMaxFunctionsLimit' to bypass this check, but be aware it may take a long time. If possible, try the cross reference tools.");
            }

            // Perform the search with progress reporting
            List<Map<String, Object>> searchResults = searchDecompilationInProgram(program, pattern, maxResults, caseSensitive, exchange);

            // Create result data
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("pattern", pattern);
            resultData.put("caseSensitive", caseSensitive);
            resultData.put("resultsCount", searchResults.size());
            resultData.put("maxResults", maxResults);
            resultData.put("results", searchResults);

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to rename variables in a decompiled function
     */
    private void registerRenameVariablesTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to rename variables in (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be used."
        ));
        properties.put("variableMappings", Map.of(
            "type", "object",
            "description", "Mapping of old variable names to new variable names. Only rename the variables that need to be changed.",
            "additionalProperties", Map.of("type", "string")
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress", "variableMappings");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("rename-variables")
            .title("Rename Function Variables")
            .description("Rename variables in a decompiled function")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Map<String, String> mappings = getStringMap(request.arguments(), "variableMappings");

            // Validate arguments
            if (mappings == null || mappings.isEmpty()) {
                return createErrorResult("No variable mappings provided");
            }

            // Get function using helper method
            Function function;
            String functionNameOrAddress = getString(request, "functionNameOrAddress");
            try {
                function = getFunctionFromArgs(request.arguments(), program);
            } catch (IllegalArgumentException e) {
                // Check if this might be an undefined function location
                if (AddressUtil.isUndefinedFunctionAddress(program, functionNameOrAddress)) {
                    return createErrorResult("Cannot rename variables at " + functionNameOrAddress +
                        ": this address has code but no defined function. " +
                        "Variable modifications require a defined function. " +
                        "Use create-function to define it first, then retry the rename.");
                }
                return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. Check you are not using the mangled name and the namespace is correct.");
            }

            // Validate that the LLM has read the decompilation for this function first
            String programPath = getString(request, "programPath");
            String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());
            if (!hasReadDecompilation(functionKey)) {
                return createErrorResult("You must read the decompilation for function '" + function.getName() +
                    "' using get-decompilation tool before making variable changes. This ensures you understand the current state of the code.");
            }

            // Initialize the decompiler using helper methods
            final String toolName = "rename-variables";
            logInfo(toolName + ": Starting variable rename for function " + function.getName() + " in " + program.getName());

            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            String beforeDecompilation;
            int renamedCount = 0;

            try {
                // Decompile the function to get the "before" state
                DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, toolName);
                if (!attempt.success()) {
                    return createErrorResult(attempt.errorMessage());
                }

                // Capture the original decompilation for diff comparison
                beforeDecompilation = attempt.results().getDecompiledFunction().getC();

                // Process variable mappings
                int transactionId = program.startTransaction("Rename Variables");
                try {
                    HighFunction highFunction = attempt.results().getHighFunction();

                    // Process all variables using helper
                    renamedCount = processAllVariables(highFunction, symbol -> {
                        String newName = mappings.get(symbol.getName());
                        if (newName != null) {
                            HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                            logInfo(toolName + ": Renamed variable " + symbol.getName() + " to " + newName);
                            return true;
                        }
                        return false;
                    }, toolName);

                    program.endTransaction(transactionId, true);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    logError(toolName + ": Error during variable renaming", e);
                    return createErrorResult("Failed to rename variables: " + e.getMessage());
                }
            } finally {
                decompiler.dispose();
            }

            if (renamedCount == 0) {
                return createErrorResult("No matching variables found to rename");
            }

            // Build result and get diff using helper
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("functionName", function.getName());
            resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
            resultData.put("variablesRenamed", true);
            resultData.put("renamedCount", renamedCount);

            // Get updated decompilation and create diff using helper
            resultData.putAll(getDecompilationDiff(program, function, beforeDecompilation, toolName));

            return createJsonResult(resultData);
        });
    }

    /**
     * Register a tool to change variable data types in a decompiled function
     */
    private void registerChangeVariableDataTypesTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol to change variable data types in (e.g. 'main', '0x00401000', or 'start'). For addresses pointing inside a function, the containing function will be used."
        ));
        properties.put("datatypeMappings", Map.of(
            "type", "object",
            "description", "Mapping of variable names to new data type strings (e.g., 'char*', 'int[10]'). Only change the variables that need new data types.",
            "additionalProperties", Map.of("type", "string")
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search for data types. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress", "datatypeMappings");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("change-variable-datatypes")
            .title("Change Variable Data Types")
            .description("Change data types of variables in a decompiled function")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Map<String, String> mappings = getStringMap(request.arguments(), "datatypeMappings");
            String archiveName = getOptionalString(request, "archiveName", "");

            // Validate arguments
            if (mappings == null || mappings.isEmpty()) {
                return createErrorResult("No datatype mappings provided");
            }

            // Get function using helper method
            Function function;
            String functionNameOrAddress = getString(request, "functionNameOrAddress");
            try {
                function = getFunctionFromArgs(request.arguments(), program);
            } catch (IllegalArgumentException e) {
                // Check if this might be an undefined function location
                if (AddressUtil.isUndefinedFunctionAddress(program, functionNameOrAddress)) {
                    return createErrorResult("Cannot change variable datatypes at " + functionNameOrAddress +
                        ": this address has code but no defined function. " +
                        "Variable modifications require a defined function. " +
                        "Use create-function to define it first, then retry the datatype change.");
                }
                return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName() +
                    ". Tried as address/symbol and function name. Check you are not using the mangled name and the namespace is correct.");
            }

            // Validate that the LLM has read the decompilation for this function first
            String programPath = getString(request, "programPath");
            String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());
            if (!hasReadDecompilation(functionKey)) {
                return createErrorResult("You must read the decompilation for function '" + function.getName() +
                    "' using get-decompilation tool before making datatype changes. This ensures you understand the current state of the code.");
            }

            // Initialize the decompiler using helper methods
            final String toolName = "change-variable-datatypes";
            logInfo(toolName + ": Starting datatype change for function " + function.getName() + " in " + program.getName());

            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            String beforeDecompilation;
            List<String> errors = new ArrayList<>();
            int changedCount = 0;

            try {
                // Decompile the function to get the "before" state
                DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, toolName);
                if (!attempt.success()) {
                    return createErrorResult(attempt.errorMessage());
                }

                // Capture the original decompilation for diff comparison
                beforeDecompilation = attempt.results().getDecompiledFunction().getC();

                // Process variable mappings
                int transactionId = program.startTransaction("Change Variable Data Types");
                boolean transactionSuccess = false;
                try {
                    HighFunction highFunction = attempt.results().getHighFunction();

                    // Process all variables - need custom logic here due to error collection
                    changedCount = processVariableDataTypeChanges(
                        highFunction, mappings, archiveName, errors, toolName);

                    transactionSuccess = true;
                } catch (Exception e) {
                    logError(toolName + ": Error during variable data type changes", e);
                    return createErrorResult("Failed to change variable data types: " + e.getMessage());
                } finally {
                    program.endTransaction(transactionId, transactionSuccess);
                }
            } finally {
                decompiler.dispose();
            }

            if (changedCount == 0 && errors.isEmpty()) {
                return createErrorResult("No matching variables found to change data types");
            }

            // Build result and get diff using helper
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("programName", program.getName());
            resultData.put("functionName", function.getName());
            resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
            resultData.put("dataTypesChanged", changedCount > 0);
            resultData.put("changedCount", changedCount);

            if (!errors.isEmpty()) {
                resultData.put("errors", errors);
            }

            // Get updated decompilation and create diff using helper
            resultData.putAll(getDecompilationDiff(program, function, beforeDecompilation, toolName));

            return createJsonResult(resultData);
        });
    }

    /**
     * Get synchronized decompilation content with optional assembly listing, comments, and incoming references
     * @param program The program
     * @param markup The Clang token markup from decompilation
     * @param fullDecompCode The full decompiled C code
     * @param offset Line number to start from (1-based)
     * @param limit Number of lines to return (null for all)
     * @param includeDisassembly Whether to include synchronized assembly
     * @param includeComments Whether to include comments
     * @param includeIncomingReferences Whether to include incoming cross references
     * @param includeReferenceContext Whether to include code context for references
     * @param function The function being decompiled
     * @return Map containing synchronized content
     */
    private Map<String, Object> getSynchronizedContent(Program program, ClangTokenGroup markup,
            String fullDecompCode, int offset, Integer limit, boolean includeDisassembly,
            boolean includeComments, boolean includeIncomingReferences, boolean includeReferenceContext, Function function) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Convert markup to lines
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
            String[] decompLines = fullDecompCode.split("\n");

            // Calculate range
            int totalLines = decompLines.length;
            int startIdx = Math.max(0, offset - 1); // Convert to 0-based
            int endIdx = limit != null ? Math.min(totalLines, startIdx + limit) : totalLines;

            result.put("totalLines", totalLines);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }

            // Include incoming references at the top level if requested
            if (includeIncomingReferences) {
                // Limit references early to avoid expensive decompilation of calling functions
                int maxIncomingRefs = 10;

                // First, count total references quickly (without decompilation context)
                int totalRefCount = 0;
                var refIterator = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
                while (refIterator.hasNext()) {
                    refIterator.next();
                    totalRefCount++;
                }

                // Now get the limited set with context (this is the expensive part)
                List<Map<String, Object>> incomingRefs = DecompilationContextUtil
                    .getEnhancedIncomingReferences(program, function, includeReferenceContext, maxIncomingRefs);

                if (!incomingRefs.isEmpty()) {
                    result.put("incomingReferences", incomingRefs);
                    result.put("totalIncomingReferences", totalRefCount);

                    if (totalRefCount > maxIncomingRefs) {
                        result.put("incomingReferencesLimited", true);
                        result.put("incomingReferencesMessage", String.format(
                            "Showing first %d of %d references. Use 'find-cross-references' tool with location='%s' and direction='to' to see all references.",
                            maxIncomingRefs, totalRefCount, function.getName()
                        ));
                    }
                }
            }

            if (includeDisassembly) {
                // Create synchronized content with assembly mapping
                List<Map<String, Object>> syncedLines = new ArrayList<>();

                for (int i = startIdx; i < endIdx; i++) {
                    Map<String, Object> lineInfo = new HashMap<>();
                    int lineNumber = i + 1;

                    // Add decompiled line (endIdx is already constrained by decompLines.length)
                    String decompLine = decompLines[i];
                    lineInfo.put("lineNumber", lineNumber);
                    lineInfo.put("decompilation", decompLine);

                    // Find corresponding assembly instructions
                    List<String> assemblyLines = getAssemblyForDecompLine(program, clangLines, lineNumber);
                    lineInfo.put("assembly", assemblyLines);

                    // Include comments if requested
                    if (includeComments) {
                        List<Map<String, Object>> lineComments = getCommentsForDecompLine(
                            program, clangLines, lineNumber);
                        if (!lineComments.isEmpty()) {
                            lineInfo.put("comments", lineComments);
                        }
                    }

                    syncedLines.add(lineInfo);
                }

                result.put("synchronizedContent", syncedLines);
            } else {
                // Just return ranged decompilation
                StringBuilder rangedDecomp = new StringBuilder();
                for (int i = startIdx; i < endIdx; i++) {
                    // endIdx is already constrained by decompLines.length
                    rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
                }
                result.put("decompilation", rangedDecomp.toString());

                // Include all comments for the function if requested
                if (includeComments) {
                    List<Map<String, Object>> functionComments = getAllCommentsInFunction(program, function);
                    if (!functionComments.isEmpty()) {
                        result.put("comments", functionComments);
                    }
                }
            }

        } catch (Exception e) {
            logError("Error creating synchronized content", e);
            // Fallback to simple line range
            result.put("decompilation", applyLineRange(fullDecompCode, offset, limit));
            result.put("totalLines", fullDecompCode.split("\n").length);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }
        }

        return result;
    }

    /**
     * Get assembly instructions corresponding to a decompiled line
     * @param program The program
     * @param clangLines List of ClangLine objects
     * @param lineNumber The line number (1-based)
     * @return List of assembly instruction strings
     */
    private List<String> getAssemblyForDecompLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        List<String> assemblyLines = new ArrayList<>();

        try {
            // Find the ClangLine for this line number
            ClangLine targetLine = null;
            for (ClangLine clangLine : clangLines) {
                if (clangLine.getLineNumber() == lineNumber) {
                    targetLine = clangLine;
                    break;
                }
            }

            if (targetLine != null) {
                // Get all tokens on this line
                List<ClangToken> tokens = targetLine.getAllTokens();

                // Find addresses associated with tokens on this line
                AddressSet lineAddresses = new AddressSet();
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        lineAddresses.add(tokenAddr);
                    }
                }

                // If no direct addresses, find closest address
                if (lineAddresses.isEmpty() && !tokens.isEmpty()) {
                    Address closestAddress = DecompilerUtils.getClosestAddress(program, tokens.get(0));
                    if (closestAddress != null) {
                        lineAddresses.add(closestAddress);
                    }
                }

                // Get assembly instructions for these addresses
                Listing listing = program.getListing();
                for (Address addr : lineAddresses.getAddresses(true)) {
                    Instruction instruction = listing.getInstructionAt(addr);
                    if (instruction != null) {
                        assemblyLines.add(String.format("0x%s: %s",
                            instruction.getAddress().toString(),
                            instruction.toString()));
                    }
                }
            }
        } catch (Exception e) {
            logError("Error mapping line to assembly", e);
        }

        return assemblyLines;
    }

    /**
     * Apply line range to text (Claude Code Read tool style)
     * @param text The full text
     * @param offset Line number to start from (1-based)
     * @param limit Number of lines to return (null for all)
     * @return Formatted text with line numbers
     */
    private String applyLineRange(String text, int offset, Integer limit) {
        String[] lines = text.split("\n");
        int startIdx = Math.max(0, offset - 1); // Convert to 0-based
        int endIdx = limit != null ? Math.min(lines.length, startIdx + limit) : lines.length;

        StringBuilder result = new StringBuilder();
        for (int i = startIdx; i < endIdx; i++) {
            // endIdx is already constrained by lines.length
            result.append(String.format("%4d\t%s\n", i + 1, lines[i]));
        }

        return result.toString();
    }

    /**
     * Search decompilation across all functions in a program
     * @param program The program to search
     * @param pattern Regular expression pattern
     * @param maxResults Maximum number of results
     * @param caseSensitive Whether search is case sensitive
     * @return List of search results
     */
    private List<Map<String, Object>> searchDecompilationInProgram(Program program, String pattern,
            int maxResults, boolean caseSensitive, io.modelcontextprotocol.server.McpSyncServerExchange exchange) {
        List<Map<String, Object>> results = new ArrayList<>();
        final String toolName = "search-decompilation";

        logInfo(toolName + ": Starting search in " + program.getName() + " for pattern: " + pattern);

        try {
            // Compile the regex pattern
            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            Pattern regex = Pattern.compile(pattern, flags);

            // Initialize decompiler using helper
            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);
            if (decompiler == null) {
                return results; // Failed to initialize decompiler
            }

            try {
                // Count total functions for progress tracking
                int totalFunctions = program.getFunctionManager().getFunctionCount();
                int processedFunctions = 0;

                // Generate unique progress token for this search
                String progressToken = "search-" + System.currentTimeMillis();

                // Send initial progress notification
                if (exchange != null) {
                    exchange.progressNotification(new McpSchema.ProgressNotification(
                        progressToken, 0.0, (double) totalFunctions, "Starting decompilation search..."));
                }

                // Iterate through all functions
                FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                while (functions.hasNext() && results.size() < maxResults) {
                    Function function = functions.next();
                    processedFunctions++;

                    // Skip external functions
                    if (function.isExternal()) {
                        continue;
                    }

                    try {
                        // Use inline decompilation here instead of decompileFunctionSafely because:
                        // 1. We want to continue to the next function on timeout (not return an error)
                        // 2. We don't need the DecompilationAttempt wrapper for this use case
                        TaskMonitor functionTimeoutMonitor = createTimeoutMonitor();
                        DecompileResults decompileResults = decompiler.decompileFunction(function, 0, functionTimeoutMonitor);
                        if (isTimedOut(functionTimeoutMonitor)) {
                            Msg.warn(DecompilerToolProvider.class, toolName + ": Decompilation timed out for function " +
                                function.getName() + " after " + getTimeoutSeconds() + " seconds");
                            continue; // Skip this function and continue with the next one
                        }

                        if (decompileResults.decompileCompleted()) {
                            // Search the decompiled code for matches
                            searchDecompiledCode(function, decompileResults, regex, results, maxResults);
                        }
                    } catch (Exception e) {
                        // Skip this function if decompilation fails
                        logError(toolName + ": Failed to decompile function: " + function.getName(), e);
                        continue;
                    }

                    // Send progress update every 10 functions or when search is complete
                    sendSearchProgress(exchange, progressToken, processedFunctions, totalFunctions,
                        results.size(), maxResults, functions.hasNext());
                }
            } finally {
                decompiler.dispose();
            }

        } catch (PatternSyntaxException e) {
            logError(toolName + ": Invalid regex pattern: " + pattern, e);
        } catch (Exception e) {
            logError(toolName + ": Error during decompilation search", e);
        }

        return results;
    }

    /**
     * Searches decompiled code for regex matches and adds results to the list.
     */
    private void searchDecompiledCode(Function function, DecompileResults decompileResults,
            Pattern regex, List<Map<String, Object>> results, int maxResults) {
        DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
        String decompCode = decompiledFunction.getC();

        // Search each line
        String[] lines = decompCode.split("\n");
        for (int i = 0; i < lines.length && results.size() < maxResults; i++) {
            String line = lines[i];
            Matcher matcher = regex.matcher(line);

            if (matcher.find()) {
                Map<String, Object> result = new HashMap<>();
                result.put("functionName", function.getName());
                result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                result.put("lineNumber", i + 1);
                result.put("lineContent", line.trim());
                result.put("matchStart", matcher.start());
                result.put("matchEnd", matcher.end());
                result.put("matchedText", matcher.group());

                results.add(result);
            }
        }
    }

    /**
     * Sends progress notification for search operation.
     */
    private void sendSearchProgress(io.modelcontextprotocol.server.McpSyncServerExchange exchange,
            String progressToken, int processedFunctions, int totalFunctions,
            int resultsCount, int maxResults, boolean hasMoreFunctions) {
        if (exchange == null || (processedFunctions % 10 != 0 && resultsCount < maxResults && hasMoreFunctions)) {
            return;
        }

        String message;
        if (resultsCount >= maxResults) {
            message = String.format("Found %d matches (max results reached)", resultsCount);
        } else if (!hasMoreFunctions) {
            message = String.format("Search complete - found %d matches", resultsCount);
        } else {
            message = String.format("Processed %d/%d functions - found %d matches so far",
                processedFunctions, totalFunctions, resultsCount);
        }

        exchange.progressNotification(new McpSchema.ProgressNotification(
            progressToken, (double) processedFunctions, (double) totalFunctions, message));
    }

    /**
     * Check if the LLM has read the decompilation for a specific function
     * @param functionKey The function key (programPath:functionName)
     * @return true if decompilation has been read recently, false otherwise
     */
    private boolean hasReadDecompilation(String functionKey) {
        Long lastReadTime = readDecompilationTracker.get(functionKey);
        if (lastReadTime == null) {
            return false;
        }

        // Consider decompilation "read" if it was accessed within the expiry window
        long expiryThreshold = System.currentTimeMillis() - READ_TRACKING_EXPIRY_MS;
        return lastReadTime > expiryThreshold;
    }

    /**
     * Get comments associated with a specific decompilation line
     * @param program The program
     * @param clangLines List of ClangLine objects
     * @param lineNumber The line number (1-based)
     * @return List of comment objects
     */
    private List<Map<String, Object>> getCommentsForDecompLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        List<Map<String, Object>> comments = new ArrayList<>();

        try {
            // Find the ClangLine for this line number
            ClangLine targetLine = clangLines.stream()
                .filter(clangLine -> clangLine.getLineNumber() == lineNumber)
                .findFirst()
                .orElse(null);

            if (targetLine != null) {
                // Get all tokens on this line
                List<ClangToken> tokens = targetLine.getAllTokens();

                // Find addresses associated with tokens on this line
                Set<Address> lineAddresses = new HashSet<>();
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        lineAddresses.add(tokenAddr);
                    }
                }

                // Get comments at these addresses
                Listing listing = program.getListing();
                for (Address addr : lineAddresses) {
                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu != null) {
                        for (Map.Entry<CommentType, String> entry : COMMENT_TYPE_NAMES.entrySet()) {
                            addCommentIfExists(comments, cu, entry.getKey(), entry.getValue(), addr);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logError("Error getting comments for decompilation line", e);
        }

        return comments;
    }

    /**
     * Get all comments in a function
     * @param program The program
     * @param function The function
     * @return List of comment objects
     */
    private List<Map<String, Object>> getAllCommentsInFunction(Program program, Function function) {
        List<Map<String, Object>> comments = new ArrayList<>();

        try {
            Listing listing = program.getListing();
            AddressSetView body = function.getBody();

            CodeUnitIterator codeUnits = listing.getCodeUnits(body, true);
            while (codeUnits.hasNext()) {
                CodeUnit cu = codeUnits.next();
                Address addr = cu.getAddress();

                // Check all comment types
                for (Map.Entry<CommentType, String> entry : COMMENT_TYPE_NAMES.entrySet()) {
                    addCommentIfExists(comments, cu, entry.getKey(), entry.getValue(), addr);
                }
            }
        } catch (Exception e) {
            logError("Error getting all comments in function", e);
        }

        return comments;
    }

    /**
     * Add a comment to the list if it exists
     * @param comments The comment list to add to
     * @param cu The code unit
     * @param commentType The comment type constant
     * @param typeString The comment type string
     * @param address The address
     */
    private void addCommentIfExists(List<Map<String, Object>> comments, CodeUnit cu,
            CommentType commentType, String typeString, Address address) {
        String comment = cu.getComment(commentType);
        if (comment != null && !comment.isEmpty()) {
            Map<String, Object> commentInfo = new HashMap<>();
            commentInfo.put("address", address.toString());
            commentInfo.put("type", typeString);
            commentInfo.put("comment", comment);
            comments.add(commentInfo);
        }
    }

    /**
     * Register a tool to set a comment from decompilation context
     */
    private void registerSetDecompilationCommentTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the function"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Function name, address, or symbol (e.g. 'main', '0x00401000', or 'start')"
        ));
        properties.put("lineNumber", Map.of(
            "type", "integer",
            "description", "Line number in the decompiled function (1-based)"
        ));
        properties.put("commentType", Map.of(
            "type", "string",
            "description", "Type of comment: 'pre' or 'eol' (end-of-line)",
            "default", "eol"
        ));
        properties.put("comment", Map.of(
            "type", "string",
            "description", "The comment text to set"
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress", "lineNumber", "comment");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-decompilation-comment")
            .title("Add Decompilation Comment")
            .description("Set a comment at a specific line in decompiled code. The comment will be placed at the address corresponding to the decompilation line.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            int lineNumber = getInt(request, "lineNumber");
            String commentTypeStr = getOptionalString(request, "commentType", "eol");
            String comment = getString(request, "comment");

            // Validate comment type
            CommentType commentType;
            if ("pre".equals(commentTypeStr)) {
                commentType = CommentType.PRE;
            } else if ("eol".equals(commentTypeStr)) {
                commentType = CommentType.EOL;
            } else {
                return createErrorResult("Invalid comment type: " + commentTypeStr +
                    ". Must be 'pre' or 'eol' for decompilation comments.");
            }

            // Get function using helper method
            Function function;
            String functionNameOrAddress = getString(request, "functionNameOrAddress");
            try {
                function = getFunctionFromArgs(request.arguments(), program);
            } catch (IllegalArgumentException e) {
                // Check if this might be an undefined function location
                if (AddressUtil.isUndefinedFunctionAddress(program, functionNameOrAddress)) {
                    return createErrorResult("Cannot set comment at " + functionNameOrAddress +
                        ": this address has code but no defined function. " +
                        "Comments require a defined function. " +
                        "Use create-function to define it first, then retry.");
                }
                return createErrorResult("Function not found: " + e.getMessage());
            }

            // Validate that the LLM has read the decompilation for this function first
            String programPath = getString(request, "programPath");
            String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());
            if (!hasReadDecompilation(functionKey)) {
                return createErrorResult("You must read the decompilation for function '" + function.getName() +
                    "' using get-decompilation tool before setting comments. This ensures you understand the current state of the code.");
            }

            // Initialize the decompiler using helper methods
            final String toolName = "set-decompilation-comment";
            logInfo(toolName + ": Setting comment for function " + function.getName() +
                    " line " + lineNumber + " in " + program.getName());

            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            try {
                // Decompile the function
                DecompilationAttempt attempt = decompileFunctionSafely(decompiler, function, toolName);
                if (!attempt.success()) {
                    return createErrorResult(attempt.errorMessage());
                }

                // Get the decompiled code and markup
                ClangTokenGroup markup = attempt.results().getCCodeMarkup();
                List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

                // Find the address for the specified line number
                Address targetAddress = findAddressForLine(program, clangLines, lineNumber);

                if (targetAddress == null) {
                    return createErrorResult("Could not find an address for line " + lineNumber +
                        " in decompiled function. The line may not correspond to any actual code.");
                }

                // Set the comment
                int transactionId = program.startTransaction("Set Decompilation Comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(targetAddress, commentType, comment);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("functionName", function.getName());
                    result.put("lineNumber", lineNumber);
                    result.put("address", targetAddress.toString());
                    result.put("commentType", commentTypeStr);
                    result.put("comment", comment);

                    program.endTransaction(transactionId, true);

                    logInfo(toolName + ": Successfully set comment at " + targetAddress);
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(transactionId, false);
                    throw e;
                }
            } catch (Exception e) {
                logError(toolName + ": Error setting comment for " + function.getName(), e);
                return createErrorResult("Failed to set comment: " + e.getMessage());
            } finally {
                decompiler.dispose();
            }
        });
    }

    // ============================================================================
    // Bulk Decompilation Tools
    // ============================================================================

    /**
     * Register a tool to get decompilation of all functions that call a target function.
     * This is a bulk operation that combines cross-reference lookup with decompilation.
     */
    private void registerGetCallersDecompiledTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionNameOrAddress", Map.of(
            "type", "string",
            "description", "Target function name or address to find callers for"
        ));
        properties.put("maxCallers", Map.of(
            "type", "integer",
            "description", "Maximum number of calling functions to decompile (default: 10)",
            "default", 10
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("includeCallContext", Map.of(
            "type", "boolean",
            "description", "Whether to highlight the line containing the call in each decompilation",
            "default", true
        ));

        List<String> required = List.of("programPath", "functionNameOrAddress");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-callers-decompiled")
            .title("Get Callers Decompiled")
            .description("Decompile all functions that call a target function. Returns bulk decompilation results with optional call site highlighting. Use for understanding how a function is used throughout the codebase.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            final String toolName = "get-callers-decompiled";

            Program program = getProgramFromArgs(request);
            int maxCallers = getOptionalInt(request, "maxCallers", 10);
            int startIndex = getOptionalInt(request, "startIndex", 0);
            boolean includeCallContext = getOptionalBoolean(request, "includeCallContext", true);

            // Validate parameters
            if (maxCallers <= 0 || maxCallers > 50) {
                return createErrorResult("maxCallers must be between 1 and 50");
            }
            if (startIndex < 0) {
                return createErrorResult("startIndex must be non-negative");
            }

            // Resolve the target function using standard helper
            Function targetFunction;
            try {
                targetFunction = getFunctionFromArgs(request.arguments(), program, "functionNameOrAddress");
            } catch (IllegalArgumentException e) {
                return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName() +
                    ". Tried as address/symbol and function name.");
            }

            // Get all references to this function
            ReferenceManager refManager = program.getReferenceManager();
            ReferenceIterator refIter = refManager.getReferencesTo(targetFunction.getEntryPoint());

            // Collect unique calling functions (with a max limit to prevent memory issues)
            final int MAX_TOTAL_CALLERS = 500;
            Set<Function> callingFunctions = new HashSet<>();
            Map<Function, List<Address>> callSites = new HashMap<>();

            while (refIter.hasNext() && callingFunctions.size() < MAX_TOTAL_CALLERS) {
                Reference ref = refIter.next();
                if (ref.getReferenceType().isCall() || ref.getReferenceType().isFlow()) {
                    Address fromAddr = ref.getFromAddress();
                    Function caller = program.getFunctionManager().getFunctionContaining(fromAddr);
                    if (caller != null && !caller.equals(targetFunction)) {
                        callingFunctions.add(caller);
                        callSites.computeIfAbsent(caller, k -> new ArrayList<>()).add(fromAddr);
                    }
                }
            }

            // Convert to list for pagination
            List<Function> callerList = new ArrayList<>(callingFunctions);
            int totalCallers = callerList.size();

            // Apply pagination
            int endIndex = Math.min(startIndex + maxCallers, totalCallers);
            List<Function> pageCallers = startIndex < totalCallers
                ? callerList.subList(startIndex, endIndex)
                : List.of();

            // Get program path for tracking
            String programPath = program.getDomainFile().getPathname();

            // Decompile each caller
            List<Map<String, Object>> decompilations = new ArrayList<>();
            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);

            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            try {
                for (Function caller : pageCallers) {
                    Map<String, Object> callerResult = new HashMap<>();
                    callerResult.put("functionName", caller.getName());
                    callerResult.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                    callerResult.put("callSites", callSites.get(caller).stream()
                        .map(AddressUtil::formatAddress)
                        .toList());

                    DecompilationAttempt attempt = decompileFunctionSafely(decompiler, caller, toolName);
                    if (attempt.success()) {
                        String decompCode = attempt.results().getDecompiledFunction().getC();
                        callerResult.put("decompilation", decompCode);
                        callerResult.put("success", true);

                        // Find call line numbers if requested
                        if (includeCallContext) {
                            List<Integer> callLineNumbers = findCallLineNumbers(
                                attempt.results(), callSites.get(caller));
                            callerResult.put("callLineNumbers", callLineNumbers);
                        }

                        // Track that this function's decompilation has been read
                        String functionKey = programPath + ":" + AddressUtil.formatAddress(caller.getEntryPoint());
                        readDecompilationTracker.put(functionKey, System.currentTimeMillis());
                    } else {
                        callerResult.put("success", false);
                        callerResult.put("error", attempt.errorMessage());
                    }

                    decompilations.add(callerResult);
                }
            } finally {
                decompiler.dispose();
            }

            // Build result
            Map<String, Object> result = new HashMap<>();
            result.put("programPath", programPath);
            result.put("targetFunction", targetFunction.getName());
            result.put("targetAddress", AddressUtil.formatAddress(targetFunction.getEntryPoint()));
            result.put("totalCallers", totalCallers);
            result.put("startIndex", startIndex);
            result.put("returnedCount", decompilations.size());
            result.put("nextStartIndex", startIndex + decompilations.size());
            result.put("hasMore", endIndex < totalCallers);
            result.put("callers", decompilations);

            return createJsonResult(result);
        });
    }

    /**
     * Register a tool to get decompilation of all functions that reference an address.
     * This handles both code and data references.
     */
    private void registerGetReferencersDecompiledTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Target address or symbol name to find references to (e.g., '0x00401000', 'global_var', 'my_label')"
        ));
        properties.put("maxReferencers", Map.of(
            "type", "integer",
            "description", "Maximum number of referencing functions to decompile (default: 10)",
            "default", 10
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("includeDataRefs", Map.of(
            "type", "boolean",
            "description", "Whether to include data references (reads/writes), not just calls",
            "default", true
        ));
        properties.put("includeRefContext", Map.of(
            "type", "boolean",
            "description", "Whether to include reference line numbers in decompilation",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-referencers-decompiled")
            .title("Get Referencers Decompiled")
            .description("Decompile all functions that reference a specific address or symbol. Useful for understanding how global variables, data, or code locations are used. Includes both code and data references by default.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            final String toolName = "get-referencers-decompiled";

            Program program = getProgramFromArgs(request);
            String addressOrSymbol = getString(request, "addressOrSymbol");
            int maxReferencers = getOptionalInt(request, "maxReferencers", 10);
            int startIndex = getOptionalInt(request, "startIndex", 0);
            boolean includeDataRefs = getOptionalBoolean(request, "includeDataRefs", true);
            boolean includeRefContext = getOptionalBoolean(request, "includeRefContext", true);

            // Validate parameters
            if (maxReferencers <= 0 || maxReferencers > 50) {
                return createErrorResult("maxReferencers must be between 1 and 50");
            }
            if (startIndex < 0) {
                return createErrorResult("startIndex must be non-negative");
            }

            // Resolve the target address
            Address targetAddress = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);
            if (targetAddress == null) {
                return createErrorResult("Could not resolve address or symbol: " + addressOrSymbol +
                    " in program " + program.getName());
            }

            // Get all references to this address
            ReferenceManager refManager = program.getReferenceManager();
            ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);

            // Collect unique referencing functions with their reference addresses (with max limit)
            final int MAX_TOTAL_REFERENCERS = 500;
            Set<Function> referencingFunctions = new HashSet<>();
            Map<Function, List<Map<String, Object>>> refDetails = new HashMap<>();
            // Also store raw addresses for line number lookup
            Map<Function, List<Address>> refAddressesMap = new HashMap<>();

            while (refIter.hasNext() && referencingFunctions.size() < MAX_TOTAL_REFERENCERS) {
                Reference ref = refIter.next();

                // Filter by reference type if requested
                if (!includeDataRefs && !ref.getReferenceType().isFlow()) {
                    continue;
                }

                Address fromAddr = ref.getFromAddress();
                Function refFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (refFunc != null) {
                    referencingFunctions.add(refFunc);

                    Map<String, Object> refInfo = new HashMap<>();
                    refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddr));
                    refInfo.put("refType", ref.getReferenceType().toString());
                    refInfo.put("isCall", ref.getReferenceType().isCall());
                    refInfo.put("isData", ref.getReferenceType().isData());
                    refInfo.put("isRead", ref.getReferenceType().isRead());
                    refInfo.put("isWrite", ref.getReferenceType().isWrite());

                    refDetails.computeIfAbsent(refFunc, k -> new ArrayList<>()).add(refInfo);
                    // Store raw address for line number lookup
                    refAddressesMap.computeIfAbsent(refFunc, k -> new ArrayList<>()).add(fromAddr);
                }
            }

            // Convert to list for pagination
            List<Function> refList = new ArrayList<>(referencingFunctions);
            int totalReferencers = refList.size();

            // Apply pagination
            int endIndex = Math.min(startIndex + maxReferencers, totalReferencers);
            List<Function> pageRefs = startIndex < totalReferencers
                ? refList.subList(startIndex, endIndex)
                : List.of();

            // Get program path for tracking
            String programPath = program.getDomainFile().getPathname();

            // Decompile each referencing function
            List<Map<String, Object>> decompilations = new ArrayList<>();
            DecompInterface decompiler = createConfiguredDecompiler(program, toolName);

            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            try {
                for (Function refFunc : pageRefs) {
                    Map<String, Object> funcResult = new HashMap<>();
                    funcResult.put("functionName", refFunc.getName());
                    funcResult.put("address", AddressUtil.formatAddress(refFunc.getEntryPoint()));
                    funcResult.put("references", refDetails.get(refFunc));

                    DecompilationAttempt attempt = decompileFunctionSafely(decompiler, refFunc, toolName);
                    if (attempt.success()) {
                        String decompCode = attempt.results().getDecompiledFunction().getC();
                        funcResult.put("decompilation", decompCode);
                        funcResult.put("success", true);

                        // Find reference line numbers if requested using pre-collected addresses
                        if (includeRefContext) {
                            List<Address> refAddresses = refAddressesMap.get(refFunc);
                            if (refAddresses != null) {
                                List<Integer> refLineNumbers = findCallLineNumbers(attempt.results(), refAddresses);
                                funcResult.put("referenceLineNumbers", refLineNumbers);
                            }
                        }

                        // Track that this function's decompilation has been read
                        String functionKey = programPath + ":" + AddressUtil.formatAddress(refFunc.getEntryPoint());
                        readDecompilationTracker.put(functionKey, System.currentTimeMillis());
                    } else {
                        funcResult.put("success", false);
                        funcResult.put("error", attempt.errorMessage());
                    }

                    decompilations.add(funcResult);
                }
            } finally {
                decompiler.dispose();
            }

            // Build result
            Map<String, Object> result = new HashMap<>();
            result.put("programPath", programPath);
            result.put("targetAddress", AddressUtil.formatAddress(targetAddress));
            result.put("resolvedFrom", addressOrSymbol);
            result.put("totalReferencers", totalReferencers);
            result.put("startIndex", startIndex);
            result.put("returnedCount", decompilations.size());
            result.put("nextStartIndex", startIndex + decompilations.size());
            result.put("hasMore", endIndex < totalReferencers);
            result.put("includeDataRefs", includeDataRefs);
            result.put("referencers", decompilations);

            return createJsonResult(result);
        });
    }

    /**
     * Find line numbers in decompiled code that correspond to specific addresses.
     */
    private List<Integer> findCallLineNumbers(DecompileResults results, List<Address> addresses) {
        List<Integer> lineNumbers = new ArrayList<>();

        if (results == null || addresses == null || addresses.isEmpty()) {
            return lineNumbers;
        }

        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup == null) {
            return lineNumbers;
        }

        Set<Address> addressSet = new HashSet<>(addresses);
        List<ClangLine> lines = DecompilerUtils.toLines(markup);

        for (ClangLine line : lines) {
            for (ClangToken token : line.getAllTokens()) {
                Address tokenAddr = token.getMinAddress();
                if (tokenAddr != null && addressSet.contains(tokenAddr)) {
                    lineNumbers.add(line.getLineNumber());
                    break; // Only add line once
                }
            }
        }

        return lineNumbers;
    }
}
