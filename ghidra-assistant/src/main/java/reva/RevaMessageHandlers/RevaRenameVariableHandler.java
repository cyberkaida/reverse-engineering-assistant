package reva.RevaMessageHandlers;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import reva.RevaService;
import reva.RevaProtocol.RevaGetDecompilationResponse;
import reva.RevaProtocol.RevaGetDecompilationResponse.RevaVariable;
import reva.RevaProtocol.RevaGetFunctionCount;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import reva.RevaProtocol.RevaRenameVariable;
import reva.RevaProtocol.RevaRenameVariableResponse;

import java.util.Iterator;

public class RevaRenameVariableHandler extends RevaMessageHandler {
    FlatProgramAPI api;
    FlatDecompilerAPI decompiler;

    public RevaRenameVariableHandler(RevaService service) {
        super(service);
        api = new FlatProgramAPI(service.currentProgram);
        decompiler = new FlatDecompilerAPI(api);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        RevaRenameVariable request = (RevaRenameVariable) message;
        RevaRenameVariableResponse response = new RevaRenameVariableResponse(request);
        Msg.info(this, "Renaming variable " + request.variable.name + " to " + request.new_name + " in function " + request.function_name);
        Function function = this.findFunction(request.function_name);
        if (function == null) {
            Msg.warn(this, "No function found with name " + request.function_name + " in " + service.currentProgram.getName());
            response.error_message = "No function found with name " + request.function_name;
            return response;
        }

        // Let's get the decompilation of the function, then get the high variables
        // and rename those!
        try {
            decompiler.initialize();
        } catch (Exception e) {
            response.error_message = "Failed to initialize decompiler: " + e.getMessage();
            return response;
        }

        TaskMonitor monitor = new TaskMonitorAdapter();
        DecompInterface decompilerInterface =  decompiler.getDecompiler();
        DecompileResults decompiled = decompilerInterface.decompileFunction(function, 60, monitor);
        if (decompiled == null) {
            response.error_message = "Failed to decompile function " + function.getName(true);
            return response;
        }

        boolean renamed = false;

        DecompiledFunction decompiledFunction = decompiled.getDecompiledFunction();
        GlobalSymbolMap globalMap = decompiled.getHighFunction().getGlobalSymbolMap();
        LocalSymbolMap localMap = decompiled.getHighFunction().getLocalSymbolMap();

        Iterator<HighSymbol> highSymbolIterator = localMap.getSymbols();

        while (highSymbolIterator.hasNext()) {
            HighSymbol highSymbol = highSymbolIterator.next();
            Msg.info(this, "Checking " + highSymbol.getName() + " for " + request.variable.name);
            if (highSymbol.getName().equals(request.variable.name)) {
                try {
                    HighFunctionDBUtil.updateDBVariable(highSymbol, request.new_name, null, SourceType.ANALYSIS);
                    renamed = true;
                    return response;
                } catch (DuplicateNameException | InvalidInputException e) {
                    response.error_message = "Failed to rename variable: " + e.getMessage();
                    return response;
                }
            }
        }


        if (!renamed) {
            response.error_message = "No variable found with name " + request.variable.name + " in function " + function.getName(true);
            return response;
        }

        return null;
    }
}
