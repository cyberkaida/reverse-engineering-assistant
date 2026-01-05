package reva.tools.dataflow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for data flow analysis operations.
 * Provides tools for tracing how values flow through a function.
 *
 * <p>Uses Ghidra's SSA (Static Single Assignment) form from the decompiler
 * to trace data dependencies via Varnode def-use chains.</p>
 */
public class DataFlowToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_DECOMPILER_TIMEOUT_SECS = 30;
    private static final int MAX_SLICE_SIZE = 500;

    public DataFlowToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerTraceBackwardTool();
        registerTraceForwardTool();
        registerFindVariableAccessesTool();
    }

    // ========================================================================
    // Tool Registration
    // ========================================================================

    private void registerTraceBackwardTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address within a function to trace backward from"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("trace-data-flow-backward")
            .title("Trace Data Flow Backward")
            .description("Trace where a value at an address comes from. " +
                "Follows the data dependency chain backward to find origins " +
                "(constants, parameters, memory loads, etc.).")
            .inputSchema(createSchema(properties, List.of("programPath", "address")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "address");

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return createErrorResult("No function contains address: " +
                    AddressUtil.formatAddress(address));
            }

            return traceDataFlow(program, function, address, SliceDirection.BACKWARD);
        });
    }

    private void registerTraceForwardTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address within a function to trace forward from"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("trace-data-flow-forward")
            .title("Trace Data Flow Forward")
            .description("Trace where a value at an address flows to. " +
                "Follows the data dependency chain forward to find uses " +
                "(stores, function calls, returns, etc.).")
            .inputSchema(createSchema(properties, List.of("programPath", "address")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "address");

            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return createErrorResult("No function contains address: " +
                    AddressUtil.formatAddress(address));
            }

            return traceDataFlow(program, function, address, SliceDirection.FORWARD);
        });
    }

    private void registerFindVariableAccessesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("functionAddress", Map.of(
            "type", "string",
            "description", "Address of the function to analyze"
        ));
        properties.put("variableName", Map.of(
            "type", "string",
            "description", "Name of the variable to find accesses for"
        ));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("find-variable-accesses")
            .title("Find Variable Accesses")
            .description("Find all reads and writes to a variable within a function. " +
                "Useful for understanding how a variable is used throughout a function.")
            .inputSchema(createSchema(properties, List.of("programPath", "functionAddress", "variableName")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address functionAddress = getAddressFromArgs(request, program, "functionAddress");
            String variableName = getString(request, "variableName");

            Function function = program.getFunctionManager().getFunctionAt(functionAddress);
            if (function == null) {
                function = program.getFunctionManager().getFunctionContaining(functionAddress);
            }
            if (function == null) {
                return createErrorResult("No function at address: " +
                    AddressUtil.formatAddress(functionAddress));
            }

            return findVariableAccesses(program, function, variableName);
        });
    }

    // ========================================================================
    // Core Analysis Methods
    // ========================================================================

    private McpSchema.CallToolResult traceDataFlow(Program program, Function function,
            Address targetAddress, SliceDirection direction) {

        DecompInterface decompiler = createConfiguredDecompiler(program);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }
        try {
            DecompileResults results = decompileFunction(decompiler, function);
            if (results == null || !results.decompileCompleted()) {
                String error = results != null ? results.getErrorMessage() : "unknown";
                return createErrorResult("Decompilation failed: " + error);
            }

            HighFunction hf = results.getHighFunction();
            if (hf == null) {
                return createErrorResult("Could not get high-level function representation");
            }

            // Find varnodes at the target address
            List<Varnode> seedVarnodes = findVarnodesAtAddress(hf, targetAddress);
            if (seedVarnodes.isEmpty()) {
                return createErrorResult("No data flow information at address: " +
                    AddressUtil.formatAddress(targetAddress) +
                    ". Try an address with an instruction that uses or defines a value.");
            }

            // Perform the slice
            Set<PcodeOp> sliceOps;
            if (direction == SliceDirection.BACKWARD) {
                sliceOps = collectBackwardSlice(seedVarnodes);
            } else {
                sliceOps = collectForwardSlice(seedVarnodes);
            }

            // Build the response
            List<Map<String, Object>> operations = buildOperationList(sliceOps);
            List<Map<String, Object>> terminators = findTerminators(sliceOps, direction);

            Map<String, Object> result = new HashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("startAddress", AddressUtil.formatAddress(targetAddress));
            result.put("direction", direction.toString().toLowerCase());
            result.put("operationCount", operations.size());
            result.put("operations", operations);
            result.put("terminators", terminators);

            return createJsonResult(result);

        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult findVariableAccesses(Program program, Function function,
            String variableName) {

        DecompInterface decompiler = createConfiguredDecompiler(program);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }
        try {
            DecompileResults results = decompileFunction(decompiler, function);
            if (results == null || !results.decompileCompleted()) {
                String error = results != null ? results.getErrorMessage() : "unknown";
                return createErrorResult("Decompilation failed: " + error);
            }

            HighFunction hf = results.getHighFunction();
            if (hf == null) {
                return createErrorResult("Could not get high-level function representation");
            }

            // Find the variable by name (searches both local and global symbols)
            HighVariable targetVar = findVariableByName(hf, variableName);
            if (targetVar == null) {
                List<String> availableVars = getAvailableVariableNames(hf);
                return createErrorResult("Variable not found: " + variableName +
                    ". Available variables: " + String.join(", ", availableVars));
            }

            // Collect all accesses
            List<Map<String, Object>> accesses = collectVariableAccesses(targetVar);

            // Build response
            Map<String, Object> result = new HashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("variableName", variableName);
            result.put("variableType", getVariableType(targetVar));
            if (targetVar.getDataType() != null) {
                result.put("dataType", targetVar.getDataType().getDisplayName());
            }
            result.put("accessCount", accesses.size());
            result.put("accesses", accesses);

            return createJsonResult(result);

        } finally {
            decompiler.dispose();
        }
    }

    // ========================================================================
    // Decompiler Setup
    // ========================================================================

    private DecompInterface createConfiguredDecompiler(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(false);  // Don't need C code for data flow
        decompiler.toggleSyntaxTree(true);  // CRITICAL: Required for SSA/data flow analysis
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            return null;
        }
        return decompiler;
    }

    // ========================================================================
    // Slice Collection
    // ========================================================================

    private Set<PcodeOp> collectBackwardSlice(List<Varnode> seedVarnodes) {
        Set<PcodeOp> result = new HashSet<>();
        outer:
        for (Varnode seed : seedVarnodes) {
            Set<PcodeOp> slice = DecompilerUtils.getBackwardSliceToPCodeOps(seed);
            if (slice != null) {
                for (PcodeOp op : slice) {
                    result.add(op);
                    if (result.size() >= MAX_SLICE_SIZE) break outer;
                }
            }
        }
        return result;
    }

    private Set<PcodeOp> collectForwardSlice(List<Varnode> seedVarnodes) {
        Set<PcodeOp> result = new HashSet<>();
        outer:
        for (Varnode seed : seedVarnodes) {
            Set<PcodeOp> slice = DecompilerUtils.getForwardSliceToPCodeOps(seed);
            if (slice != null) {
                for (PcodeOp op : slice) {
                    result.add(op);
                    if (result.size() >= MAX_SLICE_SIZE) break outer;
                }
            }
        }
        return result;
    }

    // ========================================================================
    // Varnode and Variable Finding
    // ========================================================================

    private List<Varnode> findVarnodesAtAddress(HighFunction hf, Address targetAddress) {
        List<Varnode> varnodes = new ArrayList<>();

        Iterator<PcodeOpAST> ops = hf.getPcodeOps(targetAddress);
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();

            // Add output varnode
            Varnode output = op.getOutput();
            if (output != null) {
                varnodes.add(output);
            }

            // Add input varnodes (skip constants for forward slice seeds)
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input != null && !input.isConstant()) {
                    varnodes.add(input);
                }
            }
        }

        return varnodes;
    }

    private HighVariable findVariableByName(HighFunction hf, String variableName) {
        // Search local symbols first
        LocalSymbolMap localSymbols = hf.getLocalSymbolMap();
        Iterator<HighSymbol> localIter = localSymbols.getSymbols();
        while (localIter.hasNext()) {
            HighSymbol sym = localIter.next();
            if (sym.getName().equals(variableName)) {
                return sym.getHighVariable();
            }
        }

        // Also search global symbols
        GlobalSymbolMap globalSymbols = hf.getGlobalSymbolMap();
        Iterator<HighSymbol> globalIter = globalSymbols.getSymbols();
        while (globalIter.hasNext()) {
            HighSymbol sym = globalIter.next();
            if (sym.getName().equals(variableName)) {
                return sym.getHighVariable();
            }
        }

        return null;
    }

    private List<String> getAvailableVariableNames(HighFunction hf) {
        List<String> names = new ArrayList<>();
        LocalSymbolMap localSymbols = hf.getLocalSymbolMap();
        Iterator<HighSymbol> symbols = localSymbols.getSymbols();

        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            names.add(sym.getName());
        }

        return names;
    }

    // ========================================================================
    // Variable Access Collection
    // ========================================================================

    private List<Map<String, Object>> collectVariableAccesses(HighVariable var) {
        List<Map<String, Object>> accesses = new ArrayList<>();
        Set<Address> seenAddresses = new HashSet<>();

        Varnode[] instances = var.getInstances();
        if (instances == null) {
            return accesses;
        }
        for (Varnode instance : instances) {
            // Check for writes (definitions)
            PcodeOp def = instance.getDef();
            if (def != null) {
                Address addr = getOperationAddress(def);
                if (addr != null && !seenAddresses.contains(addr)) {
                    seenAddresses.add(addr);
                    accesses.add(buildAccessInfo(addr, "WRITE", def));
                }
            }

            // Check for reads (uses)
            Iterator<PcodeOp> uses = instance.getDescendants();
            while (uses.hasNext()) {
                PcodeOp use = uses.next();
                Address addr = getOperationAddress(use);
                if (addr != null && !seenAddresses.contains(addr)) {
                    seenAddresses.add(addr);
                    accesses.add(buildAccessInfo(addr, "READ", use));
                }
            }
        }

        // Sort by address
        accesses.sort((a, b) -> compareAddresses(
            (String) a.get("address"),
            (String) b.get("address")));

        return accesses;
    }

    private Map<String, Object> buildAccessInfo(Address addr, String accessType, PcodeOp op) {
        Map<String, Object> info = new HashMap<>();
        info.put("address", AddressUtil.formatAddress(addr));
        info.put("accessType", accessType);
        info.put("operation", op.getMnemonic());
        return info;
    }

    // ========================================================================
    // Operation Building
    // ========================================================================

    private List<Map<String, Object>> buildOperationList(Set<PcodeOp> ops) {
        List<Map<String, Object>> operations = new ArrayList<>();

        for (PcodeOp op : ops) {
            Map<String, Object> opInfo = new HashMap<>();

            Address addr = getOperationAddress(op);
            if (addr != null) {
                opInfo.put("address", AddressUtil.formatAddress(addr));
            }

            opInfo.put("opcode", op.getMnemonic());

            // Add output info
            Varnode output = op.getOutput();
            if (output != null) {
                opInfo.put("output", buildVarnodeInfo(output));
            }

            // Add input info
            List<Map<String, Object>> inputs = new ArrayList<>();
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input != null) {
                    inputs.add(buildVarnodeInfo(input));
                }
            }
            if (!inputs.isEmpty()) {
                opInfo.put("inputs", inputs);
            }

            operations.add(opInfo);
        }

        // Sort by address
        operations.sort((a, b) -> compareAddresses(
            (String) a.getOrDefault("address", ""),
            (String) b.getOrDefault("address", "")));

        return operations;
    }

    private Map<String, Object> buildVarnodeInfo(Varnode vn) {
        Map<String, Object> info = new HashMap<>();

        if (vn.isConstant()) {
            info.put("type", "constant");
            info.put("value", "0x" + Long.toHexString(vn.getOffset()));
        } else if (vn.isRegister()) {
            info.put("type", "register");
            info.put("offset", vn.getOffset());
            info.put("size", vn.getSize());
        } else if (vn.isUnique()) {
            info.put("type", "temporary");
        } else if (vn.isAddress()) {
            info.put("type", "memory");
            info.put("address", AddressUtil.formatAddress(vn.getAddress()));
        } else {
            info.put("type", "other");
        }

        // Add high variable name if available
        HighVariable high = vn.getHigh();
        if (high != null && high.getName() != null) {
            info.put("variableName", high.getName());
        }

        return info;
    }

    // ========================================================================
    // Terminator Finding
    // ========================================================================

    private List<Map<String, Object>> findTerminators(Set<PcodeOp> ops, SliceDirection direction) {
        List<Map<String, Object>> terminators = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (PcodeOp op : ops) {
            Map<String, Object> terminator = null;

            if (direction == SliceDirection.BACKWARD) {
                terminator = findBackwardTerminator(op);
            } else {
                terminator = findForwardTerminator(op);
            }

            if (terminator != null) {
                // Create a stable key for deduplication
                String key = terminator.get("type") + ":" +
                    terminator.getOrDefault("address",
                        terminator.getOrDefault("value",
                            terminator.getOrDefault("name", "")));
                if (!seen.contains(key)) {
                    seen.add(key);
                    terminators.add(terminator);
                }
            }
        }

        return terminators;
    }

    private Map<String, Object> findBackwardTerminator(PcodeOp op) {
        int opcode = op.getOpcode();

        // Check for constant inputs
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null && input.isConstant()) {
                Map<String, Object> term = new HashMap<>();
                term.put("type", "CONSTANT");
                term.put("value", "0x" + Long.toHexString(input.getOffset()));
                return term;
            }
        }

        // Check for parameter
        Varnode output = op.getOutput();
        if (output != null) {
            HighVariable high = output.getHigh();
            if (high instanceof HighParam) {
                Map<String, Object> term = new HashMap<>();
                term.put("type", "PARAMETER");
                term.put("name", high.getName());
                term.put("slot", ((HighParam) high).getSlot());
                return term;
            }
            if (high instanceof HighGlobal) {
                Map<String, Object> term = new HashMap<>();
                term.put("type", "GLOBAL");
                term.put("name", high.getName());
                if (high.getRepresentative() != null) {
                    term.put("address", AddressUtil.formatAddress(high.getRepresentative().getAddress()));
                }
                return term;
            }
        }

        // Check for memory load
        if (opcode == PcodeOp.LOAD) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "MEMORY_LOAD");
            Address addr = getOperationAddress(op);
            if (addr != null) {
                term.put("address", AddressUtil.formatAddress(addr));
            }
            return term;
        }

        return null;
    }

    private Map<String, Object> findForwardTerminator(PcodeOp op) {
        int opcode = op.getOpcode();

        if (opcode == PcodeOp.STORE) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "MEMORY_STORE");
            Address addr = getOperationAddress(op);
            if (addr != null) {
                term.put("address", AddressUtil.formatAddress(addr));
            }
            return term;
        }

        if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "FUNCTION_CALL");
            Varnode target = op.getInput(0);
            if (target != null && target.isAddress()) {
                term.put("targetAddress", AddressUtil.formatAddress(target.getAddress()));
            }
            Address addr = getOperationAddress(op);
            if (addr != null) {
                term.put("address", AddressUtil.formatAddress(addr));
            }
            return term;
        }

        if (opcode == PcodeOp.RETURN) {
            Map<String, Object> term = new HashMap<>();
            term.put("type", "RETURN");
            Address addr = getOperationAddress(op);
            if (addr != null) {
                term.put("address", AddressUtil.formatAddress(addr));
            }
            return term;
        }

        return null;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    private DecompileResults decompileFunction(DecompInterface decompiler, Function function) {
        int timeout = getDecompilerTimeout();
        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.SECONDS);
        return decompiler.decompileFunction(function, timeout, monitor);
    }

    private int getDecompilerTimeout() {
        try {
            ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
            if (configManager != null) {
                return configManager.getDecompilerTimeoutSeconds();
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return DEFAULT_DECOMPILER_TIMEOUT_SECS;
    }

    private Address getOperationAddress(PcodeOp op) {
        if (op.getSeqnum() != null) {
            return op.getSeqnum().getTarget();
        }
        return null;
    }

    private int compareAddresses(String addrA, String addrB) {
        if (addrA == null || addrA.isEmpty()) return addrB == null || addrB.isEmpty() ? 0 : 1;
        if (addrB == null || addrB.isEmpty()) return -1;
        try {
            // Parse "0x" prefixed hex addresses numerically
            long valA = Long.parseUnsignedLong(addrA.startsWith("0x") ? addrA.substring(2) : addrA, 16);
            long valB = Long.parseUnsignedLong(addrB.startsWith("0x") ? addrB.substring(2) : addrB, 16);
            return Long.compareUnsigned(valA, valB);
        } catch (NumberFormatException e) {
            // Fall back to string comparison if not valid hex
            return addrA.compareTo(addrB);
        }
    }

    private String getVariableType(HighVariable var) {
        if (var instanceof HighParam) {
            return "parameter";
        } else if (var instanceof HighLocal) {
            return "local";
        } else if (var instanceof HighGlobal) {
            return "global";
        }
        return "unknown";
    }

    // ========================================================================
    // Enums
    // ========================================================================

    private enum SliceDirection {
        FORWARD,
        BACKWARD
    }
}
