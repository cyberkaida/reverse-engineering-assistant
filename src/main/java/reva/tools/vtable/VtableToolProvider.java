package reva.tools.vtable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;

/**
 * Tool provider for vtable (virtual function table) analysis.
 * Provides tools for analyzing vtable structures and finding indirect calls
 * through vtable slots, which is essential for understanding C++ virtual
 * method dispatch in reverse engineering.
 */
public class VtableToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_MAX_VTABLE_ENTRIES = 200;
    private static final int DEFAULT_MAX_RESULTS = 500;
    private static final int DEFAULT_TIMEOUT_SECONDS = 120;
    private static final int MAX_SLOT_SEARCH_LIMIT = 1000;
    private static final int MAX_ENTRIES_LIMIT = 1000;
    private static final int MAX_RESULTS_LIMIT = 10000;

    // Vtable detection heuristics
    private static final int VTABLE_PROBE_ENTRIES = 5;      // Number of entries to check when probing for vtable
    private static final int MIN_VTABLE_FUNCTION_POINTERS = 2;  // Minimum function pointers to consider it a vtable

    // Patterns for extracting offsets from operand representations (x86/x64 instruction formats)
    // Matches: [RAX + 0x20], [RBX+0x10], [ECX + 0x8]
    private static final Pattern HEX_OFFSET_PATTERN = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)\\s*\\]");
    // Matches: [RAX + 32], [RBX+16], [ECX + 8]
    private static final Pattern DEC_OFFSET_PATTERN = Pattern.compile("\\+\\s*(\\d+)\\s*\\]");
    // Matches: [RAX], [RBX], [ECX] (zero offset indirect calls)
    private static final Pattern ZERO_OFFSET_PATTERN = Pattern.compile("\\[\\s*[A-Za-z]+\\s*\\]");

    /**
     * Creates a new VtableToolProvider.
     * @param server The MCP server to register tools with
     */
    public VtableToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerAnalyzeVtableTool();
        registerFindVtableCallersTool();
        registerFindVtablesContainingFunctionTool();
    }

    // ========================================================================
    // Tool Registration
    // ========================================================================

    private void registerAnalyzeVtableTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("vtableAddress", Map.of(
            "type", "string",
            "description", "Address of the vtable to analyze"
        ));
        properties.put("maxEntries", Map.of(
            "type", "integer",
            "description", "Maximum number of vtable entries to read (default: 200)",
            "default", DEFAULT_MAX_VTABLE_ENTRIES
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analyze-vtable")
            .title("Analyze Vtable")
            .description("Analyze a virtual function table (vtable) at the given address. " +
                "Returns the list of function pointers with their slot indices and offsets. " +
                "Useful for understanding C++ class hierarchies and virtual method dispatch.")
            .inputSchema(createSchema(properties, List.of("programPath", "vtableAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address vtableAddr = getAddressFromArgs(request, program, "vtableAddress");
            int maxEntries = getOptionalInt(request, "maxEntries", DEFAULT_MAX_VTABLE_ENTRIES);

            return analyzeVtable(program, vtableAddr, maxEntries);
        });
    }

    private void registerFindVtableCallersTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddress", Map.of(
            "type", "string",
            "description", "Address or name of the function that is called via vtable"
        ));
        properties.put("vtableAddress", Map.of(
            "type", "string",
            "description", "Address of the vtable containing the function (optional - will search if not provided)"
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of results to return (default: 500)",
            "default", DEFAULT_MAX_RESULTS
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-vtable-callers")
            .title("Find Vtable Callers")
            .description("Find all indirect calls that could be calling a function through its vtable slot. " +
                "Given a function that appears in a vtable, finds all indirect call instructions " +
                "with the matching offset. If vtableAddress is not provided, will first search for " +
                "vtables containing the function. Essential for finding callers of virtual methods. " +
                "Note: Offset extraction patterns are optimized for x86/x64 instruction formats.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address functionAddr = getAddressFromArgs(request, program, "functionAddress");
            String vtableAddrStr = getOptionalString(request, "vtableAddress", null);
            int maxResults = getOptionalInt(request, "maxResults", DEFAULT_MAX_RESULTS);

            Address vtableAddr = null;
            if (vtableAddrStr != null && !vtableAddrStr.isEmpty()) {
                vtableAddr = AddressUtil.resolveAddressOrSymbol(program, vtableAddrStr);
                if (vtableAddr == null) {
                    return createErrorResult("Invalid vtable address or symbol: " + vtableAddrStr);
                }
            }

            return findVtableCallers(program, functionAddr, vtableAddr, maxResults);
        });
    }

    private void registerFindVtablesContainingFunctionTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddress", Map.of(
            "type", "string",
            "description", "Address or name of the function to search for in vtables"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-vtables-containing-function")
            .title("Find Vtables Containing Function")
            .description("Find all vtables that contain a pointer to the given function. " +
                "Returns the vtable addresses and slot indices where the function appears. " +
                "Useful for discovering which classes implement a virtual method.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddress")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address functionAddr = getAddressFromArgs(request, program, "functionAddress");

            return findVtablesContainingFunction(program, functionAddr);
        });
    }

    // ========================================================================
    // Core Analysis Methods
    // ========================================================================

    private McpSchema.CallToolResult analyzeVtable(Program program, Address vtableAddr, int maxEntries) {
        // Validate and clamp parameters
        maxEntries = clampValue(maxEntries, 1, MAX_ENTRIES_LIMIT);

        int pointerSize = program.getDefaultPointerSize();
        Listing listing = program.getListing();

        // Check if there's already a structure defined at this address
        Data existingData = listing.getDataAt(vtableAddr);
        Structure existingStructure = null;
        String structureName = null;

        if (existingData != null) {
            DataType dataType = existingData.getDataType();
            if (dataType instanceof Structure) {
                existingStructure = (Structure) dataType;
                structureName = existingStructure.getName();
            }
        }

        List<Map<String, Object>> entries;
        if (existingStructure != null) {
            // Use the existing structure definition
            entries = analyzeVtableFromStructure(program, vtableAddr, existingStructure, maxEntries);
        } else {
            // Fall back to raw memory analysis
            entries = analyzeVtableFromMemory(program, vtableAddr, maxEntries);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("vtableAddress", AddressUtil.formatAddress(vtableAddr));
        result.put("pointerSize", pointerSize);
        result.put("entryCount", entries.size());

        if (structureName != null) {
            result.put("structureName", structureName);
            result.put("hasStructure", true);
        } else {
            result.put("hasStructure", false);
            result.put("note", "No structure defined at this address. Use create-structure to define one.");
        }

        result.put("entries", entries);

        return createJsonResult(result);
    }

    /**
     * Analyze a vtable using an existing structure definition.
     */
    private List<Map<String, Object>> analyzeVtableFromStructure(Program program, Address vtableAddr,
            Structure structure, int maxEntries) {

        List<Map<String, Object>> entries = new ArrayList<>();
        FunctionManager funcMgr = program.getFunctionManager();
        Memory memory = program.getMemory();
        int pointerSize = program.getDefaultPointerSize();

        DataTypeComponent[] components = structure.getComponents();
        int slot = 0;

        for (DataTypeComponent component : components) {
            // Respect maxEntries limit
            if (entries.size() >= maxEntries) {
                break;
            }
            Map<String, Object> entry = new HashMap<>();
            entry.put("slot", slot);
            entry.put("offset", String.format("0x%x", component.getOffset()));
            entry.put("fieldName", component.getFieldName());

            DataType fieldType = component.getDataType();
            entry.put("fieldType", fieldType.getDisplayName());

            // Try to read the actual pointer value and resolve the function
            try {
                Address fieldAddr = vtableAddr.add(component.getOffset());
                long pointerValue = readPointer(memory, fieldAddr, pointerSize);
                Address targetAddr = toAddress(program, pointerValue);

                entry.put("address", AddressUtil.formatAddress(targetAddr));

                Function func = funcMgr.getFunctionAt(targetAddr);
                if (func != null) {
                    entry.put("functionName", func.getName());
                    String signature = func.getSignature().getPrototypeString();
                    if (signature != null) {
                        entry.put("signature", signature);
                    }
                } else {
                    entry.put("functionName", null);
                    // Check if the field type suggests it should be a function pointer
                    if (fieldType instanceof Pointer) {
                        entry.put("note", "Pointer does not point to a function");
                    }
                }
            } catch (MemoryAccessException e) {
                entry.put("address", null);
                entry.put("note", "Could not read memory");
            }

            entries.add(entry);
            slot++;
        }

        return entries;
    }

    /**
     * Analyze a vtable by reading raw memory (no structure defined).
     */
    private List<Map<String, Object>> analyzeVtableFromMemory(Program program, Address vtableAddr,
            int maxEntries) {

        List<Map<String, Object>> entries = new ArrayList<>();
        int pointerSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();

        Address current = vtableAddr;
        int consecutiveNonFunction = 0;

        for (int slot = 0; slot < maxEntries; slot++) {
            try {
                long pointerValue = readPointer(memory, current, pointerSize);
                Address targetAddr = toAddress(program, pointerValue);

                Function func = funcMgr.getFunctionAt(targetAddr);

                if (func != null) {
                    consecutiveNonFunction = 0;

                    Map<String, Object> entry = new HashMap<>();
                    entry.put("slot", slot);
                    entry.put("offset", String.format("0x%x", slot * pointerSize));
                    entry.put("address", AddressUtil.formatAddress(targetAddr));
                    entry.put("functionName", func.getName());

                    // Add signature if available
                    String signature = func.getSignature().getPrototypeString();
                    if (signature != null) {
                        entry.put("signature", signature);
                    }

                    entries.add(entry);
                } else {
                    // Not a function pointer - could be end of vtable or RTTI pointer
                    consecutiveNonFunction++;

                    // Allow one non-function entry (could be RTTI), but stop after two
                    if (consecutiveNonFunction > 1) {
                        break;
                    }

                    // Record as potential RTTI or unknown entry
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("slot", slot);
                    entry.put("offset", String.format("0x%x", slot * pointerSize));
                    entry.put("address", AddressUtil.formatAddress(targetAddr));
                    entry.put("functionName", null);
                    entry.put("note", "Not a function - possibly RTTI or end of vtable");
                    entries.add(entry);
                }

                current = current.add(pointerSize);
            } catch (MemoryAccessException e) {
                break; // End of readable memory
            }
        }

        return entries;
    }

    private McpSchema.CallToolResult findVtableCallers(Program program, Address functionAddr,
            Address vtableAddr, int maxResults) {

        // Validate and clamp parameters
        maxResults = clampValue(maxResults, 1, MAX_RESULTS_LIMIT);

        TaskMonitor monitor = createTimeoutMonitor();
        int pointerSize = program.getDefaultPointerSize();
        Function targetFunc = program.getFunctionManager().getFunctionAt(functionAddr);

        if (targetFunc == null) {
            targetFunc = program.getFunctionManager().getFunctionContaining(functionAddr);
        }
        if (targetFunc == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(functionAddr));
        }

        // If no vtable provided, find vtables containing this function
        List<VtableSlotInfo> vtableSlots = new ArrayList<>();
        try {
            if (vtableAddr != null) {
                int slotIndex = findSlotIndex(program, functionAddr, vtableAddr, monitor);
                if (slotIndex >= 0) {
                    vtableSlots.add(new VtableSlotInfo(vtableAddr, slotIndex, slotIndex * pointerSize));
                } else {
                    return createErrorResult("Function not found in specified vtable");
                }
            } else {
                // Search for vtables containing this function
                vtableSlots = findVtableSlotsForFunction(program, functionAddr, monitor);
                if (vtableSlots.isEmpty()) {
                    return createErrorResult("No vtables found containing this function. " +
                        "The function may not be virtual, or vtables haven't been identified yet.");
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Collect unique offsets to search for
        Set<Integer> targetOffsets = new HashSet<>();
        for (VtableSlotInfo slot : vtableSlots) {
            targetOffsets.add(slot.offset());
        }

        // Find indirect calls with matching offsets
        List<Map<String, Object>> callers = new ArrayList<>();
        try {
            callers = findIndirectCallsWithOffsets(program, targetOffsets, maxResults, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Build vtable info for response
        List<Map<String, Object>> vtableInfo = new ArrayList<>();
        for (VtableSlotInfo slot : vtableSlots) {
            Map<String, Object> info = new HashMap<>();
            info.put("vtableAddress", AddressUtil.formatAddress(slot.vtableAddr()));
            info.put("slotIndex", slot.slotIndex());
            info.put("slotOffset", String.format("0x%x", slot.offset()));
            vtableInfo.add(info);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("functionAddress", AddressUtil.formatAddress(functionAddr));
        result.put("functionName", targetFunc.getName());
        result.put("vtables", vtableInfo);
        result.put("potentialCallerCount", callers.size());
        result.put("note", !callers.isEmpty()
            ? "These are indirect calls with matching offsets - verify vtable usage at each site"
            : "No indirect calls found with matching vtable slot offsets");
        result.put("potentialCallers", callers);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult findVtablesContainingFunction(Program program, Address functionAddr) {
        TaskMonitor monitor = createTimeoutMonitor();
        Function targetFunc = program.getFunctionManager().getFunctionAt(functionAddr);

        if (targetFunc == null) {
            targetFunc = program.getFunctionManager().getFunctionContaining(functionAddr);
        }
        if (targetFunc == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(functionAddr));
        }

        List<VtableSlotInfo> vtableSlots;
        try {
            vtableSlots = findVtableSlotsForFunction(program, functionAddr, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        List<Map<String, Object>> vtables = new ArrayList<>();
        for (VtableSlotInfo slot : vtableSlots) {
            Map<String, Object> vtableInfo = new HashMap<>();
            vtableInfo.put("vtableAddress", AddressUtil.formatAddress(slot.vtableAddr()));
            vtableInfo.put("slotIndex", slot.slotIndex());
            vtableInfo.put("slotOffset", String.format("0x%x", slot.offset()));

            // Try to identify the class name from nearby symbols or RTTI
            String className = guessClassNameFromVtable(program, slot.vtableAddr());
            if (className != null) {
                vtableInfo.put("possibleClassName", className);
            }

            vtables.add(vtableInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("functionAddress", AddressUtil.formatAddress(functionAddr));
        result.put("functionName", targetFunc.getName());
        result.put("vtableCount", vtables.size());
        result.put("vtables", vtables);

        return createJsonResult(result);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private List<VtableSlotInfo> findVtableSlotsForFunction(Program program, Address functionAddr,
            TaskMonitor monitor) throws CancelledException {

        List<VtableSlotInfo> results = new ArrayList<>();
        Set<String> seen = new HashSet<>(); // Deduplication: vtableAddr:slotIndex
        int pointerSize = program.getDefaultPointerSize();
        ReferenceManager refMgr = program.getReferenceManager();

        // Find all data references to this function (vtable entries are data refs)
        ReferenceIterator refs = refMgr.getReferencesTo(functionAddr);
        while (refs.hasNext()) {
            monitor.checkCancelled();
            Reference ref = refs.next();

            if (!ref.getReferenceType().isData()) {
                continue;
            }

            Address refAddr = ref.getFromAddress();

            // Try to find the start of the vtable by walking backwards
            Address vtableStart = findVtableStart(program, refAddr, monitor);

            // Calculate and validate slot index
            long slotOffset = refAddr.subtract(vtableStart);
            if (slotOffset < 0 || slotOffset > Integer.MAX_VALUE) {
                continue; // Invalid offset
            }
            int slotIndex = (int) (slotOffset / pointerSize);

            // Deduplication check
            String key = AddressUtil.formatAddress(vtableStart) + ":" + slotIndex;
            if (seen.contains(key)) {
                continue;
            }

            // Verify this looks like a vtable
            if (isLikelyVtable(program, vtableStart)) {
                // Calculate offset with overflow check
                long offset = (long) slotIndex * pointerSize;
                if (offset > Integer.MAX_VALUE) {
                    continue; // Skip entries with unreasonably large offsets
                }
                seen.add(key);
                results.add(new VtableSlotInfo(vtableStart, slotIndex, (int) offset));
            }
        }

        return results;
    }

    private Address findVtableStart(Program program, Address pointerAddr, TaskMonitor monitor)
            throws CancelledException {

        int pointerSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();

        Address current = pointerAddr;
        int backtrackLimit = 100; // Don't go back more than 100 entries

        for (int i = 0; i < backtrackLimit; i++) {
            monitor.checkCancelled();

            // Check bounds before subtract
            Address prev;
            try {
                prev = current.subtractNoWrap(pointerSize);
            } catch (ghidra.program.model.address.AddressOverflowException e) {
                return current; // At address space boundary
            }

            try {
                long pointerValue = readPointer(memory, prev, pointerSize);
                Address targetAddr = toAddress(program, pointerValue);

                // Check if previous entry points to a function
                if (funcMgr.getFunctionAt(targetAddr) == null) {
                    // Previous entry is not a function pointer
                    // Could be RTTI, so check one more back
                    Address prevPrev;
                    try {
                        prevPrev = prev.subtractNoWrap(pointerSize);
                    } catch (ghidra.program.model.address.AddressOverflowException e) {
                        return current;
                    }
                    try {
                        long prevPrevValue = readPointer(memory, prevPrev, pointerSize);
                        Address prevPrevTarget = toAddress(program, prevPrevValue);
                        if (funcMgr.getFunctionAt(prevPrevTarget) == null) {
                            // Two non-functions in a row, current is likely the start
                            return current;
                        }
                    } catch (MemoryAccessException e) {
                        return current;
                    }
                }

                current = prev;
            } catch (MemoryAccessException e) {
                return current;
            }
        }

        return current;
    }

    /**
     * Determine if an address likely points to a vtable by checking for consecutive function pointers.
     */
    private boolean isLikelyVtable(Program program, Address addr) {
        int pointerSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();

        int functionPointers = 0;

        for (int i = 0; i < VTABLE_PROBE_ENTRIES; i++) {
            try {
                Address checkAddr = addr.add(i * pointerSize);
                long pointerValue = readPointer(memory, checkAddr, pointerSize);
                Address targetAddr = toAddress(program, pointerValue);

                if (funcMgr.getFunctionAt(targetAddr) != null) {
                    functionPointers++;
                }
            } catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
                break;
            }
        }

        return functionPointers >= MIN_VTABLE_FUNCTION_POINTERS;
    }

    /**
     * Find the slot index of a function within a vtable.
     * @return The slot index, or -1 if not found
     */
    private int findSlotIndex(Program program, Address functionAddr, Address vtableAddr,
            TaskMonitor monitor) throws CancelledException {
        int pointerSize = program.getDefaultPointerSize();
        Memory memory = program.getMemory();

        Address current = vtableAddr;
        for (int slot = 0; slot < MAX_SLOT_SEARCH_LIMIT; slot++) {
            monitor.checkCancelled();
            try {
                long pointerValue = readPointer(memory, current, pointerSize);

                if (pointerValue == functionAddr.getOffset()) {
                    return slot;
                }

                // Check if still in vtable
                Address targetAddr = toAddress(program, pointerValue);
                if (program.getFunctionManager().getFunctionAt(targetAddr) == null) {
                    // Allow one non-function (RTTI), but stop after that if still no match
                    if (slot > 0) {
                        try {
                            Address nextAddr = current.add(pointerSize);
                            long nextValue = readPointer(memory, nextAddr, pointerSize);
                            Address nextTarget = toAddress(program, nextValue);
                            if (program.getFunctionManager().getFunctionAt(nextTarget) == null) {
                                break; // End of vtable
                            }
                        } catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
                            break;
                        }
                    }
                }

                current = current.add(pointerSize);
            } catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
                break;
            }
        }

        return -1;
    }

    private List<Map<String, Object>> findIndirectCallsWithOffsets(Program program,
            Set<Integer> targetOffsets, int maxResults, TaskMonitor monitor) throws CancelledException {

        List<Map<String, Object>> results = new ArrayList<>();
        Listing listing = program.getListing();

        InstructionIterator iter = listing.getInstructions(true);
        while (iter.hasNext() && results.size() < maxResults) {
            monitor.checkCancelled();
            Instruction instr = iter.next();

            // Check if this is an indirect call
            FlowType flowType = instr.getFlowType();
            if (!flowType.isCall() || !flowType.isComputed()) {
                continue;
            }

            // Extract offset from operand
            String operandRep = instr.getDefaultOperandRepresentation(0);
            Integer offset = extractOffsetFromOperand(operandRep);

            if (offset != null && targetOffsets.contains(offset)) {
                Map<String, Object> caller = new HashMap<>();
                caller.put("address", AddressUtil.formatAddress(instr.getAddress()));
                caller.put("instruction", instr.toString());
                caller.put("operand", operandRep);
                caller.put("offset", String.format("0x%x", offset));

                Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                if (func != null) {
                    caller.put("function", func.getName());
                    caller.put("functionAddress", AddressUtil.formatAddress(func.getEntryPoint()));
                }

                results.add(caller);
            }
        }

        return results;
    }

    private Integer extractOffsetFromOperand(String operandRep) {
        if (operandRep == null) {
            return null;
        }

        // Check for [REG] pattern (offset 0)
        if (ZERO_OFFSET_PATTERN.matcher(operandRep).matches()) {
            return 0;
        }

        // Check for hex offset pattern like [RAX + 0x20]
        Matcher hexMatcher = HEX_OFFSET_PATTERN.matcher(operandRep);
        if (hexMatcher.find()) {
            try {
                return Integer.parseInt(hexMatcher.group(1), 16);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // Check for decimal offset pattern like [RAX + 32]
        Matcher decMatcher = DEC_OFFSET_PATTERN.matcher(operandRep);
        if (decMatcher.find()) {
            try {
                return Integer.parseInt(decMatcher.group(1));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        return null;
    }

    private String guessClassNameFromVtable(Program program, Address vtableAddr) {
        // Try to find a symbol at or near the vtable address
        var symbol = program.getSymbolTable().getPrimarySymbol(vtableAddr);
        if (symbol != null) {
            String name = symbol.getName();
            // Common vtable symbol patterns
            if (name.contains("vtable") || name.contains("vftable") || name.startsWith("??_7")) {
                return name;
            }
        }

        // Check for RTTI pointer before vtable (common in MSVC)
        int pointerSize = program.getDefaultPointerSize();
        try {
            Address rttiAddr = vtableAddr.subtractNoWrap(pointerSize);
            var rttiSymbol = program.getSymbolTable().getPrimarySymbol(rttiAddr);
            if (rttiSymbol != null) {
                String name = rttiSymbol.getName();
                if (name.contains("RTTI") || name.contains("TypeDescriptor")) {
                    return name;
                }
            }
        } catch (ghidra.program.model.address.AddressOverflowException e) {
            // At address space boundary - ignore
        }

        return null;
    }

    private long readPointer(Memory memory, Address addr, int pointerSize) throws MemoryAccessException {
        if (pointerSize == 8) {
            return memory.getLong(addr);
        } else {
            return memory.getInt(addr) & 0xFFFFFFFFL;
        }
    }

    /**
     * Convert a raw pointer value to an Address.
     * Note: Always uses the default address space. For programs with multiple
     * address spaces (overlays, segments), this may resolve to the wrong space.
     * This is acceptable for typical vtable analysis on standard executables.
     */
    private Address toAddress(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private TaskMonitor createTimeoutMonitor() {
        return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Clamp a value to be within a specified range.
     */
    private int clampValue(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    // ========================================================================
    // Helper Classes
    // ========================================================================

    /**
     * Information about a function's slot within a vtable.
     * @param vtableAddr The address of the vtable
     * @param slotIndex The index of the slot within the vtable
     * @param offset The byte offset from the vtable start
     */
    private record VtableSlotInfo(Address vtableAddr, int slotIndex, int offset) {}
}
