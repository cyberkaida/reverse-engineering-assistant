package reva.RevaMessageHandlers;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import reva.RevaService;
import reva.RevaProtocol.RevaGetDecompilation;
import reva.RevaProtocol.RevaGetDecompilationResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import reva.RevaProtocol.RevaGetDecompilationResponse.RevaVariable;

import java.util.ArrayList;
import java.util.Iterator;

public class RevaGetDecompilationHandler extends RevaMessageHandler {
    FlatProgramAPI api;
    FlatDecompilerAPI decompiler;


    public RevaGetDecompilationHandler(RevaService service) {
        super(service);

        api = new FlatProgramAPI(service.currentProgram);
        decompiler = new FlatDecompilerAPI(api);
    }

    @Override
    public RevaMessageResponse handleMessage(RevaMessage message) {
        Msg.info(this, "Getting decompilation for " + message.toJson());
        TaskMonitor monitor = new TaskMonitorAdapter();

        RevaGetDecompilation decompilationMessage = (RevaGetDecompilation) message;
        RevaGetDecompilationResponse response = new RevaGetDecompilationResponse(decompilationMessage);
        Function function = null;

        if (decompilationMessage.address != null) {
            Address address = service.currentProgram.getAddressFactory().getAddress(decompilationMessage.address);
            function = service.currentProgram.getFunctionManager().getFunctionContaining(address);

            if (function == null) {
                // There was nothing there...
                response.error_message = "No function found at address " + decompilationMessage.address;
                return response;
            }

        } else if (decompilationMessage.function != null) {

            function = this.findFunction(decompilationMessage.function);

            if (function == null) {
                // There was nothing there...
                response.error_message = "No function found with name " + decompilationMessage.function;
                return response;
            }
        }

        response.incoming_calls = new ArrayList<String>();
        for (Function caller : function.getCallingFunctions(monitor)) {
            response.incoming_calls.add(caller.getName());
        }

        response.outgoing_calls = new ArrayList<String>();
        for (Function callee : function.getCalledFunctions(monitor)) {
            response.outgoing_calls.add(callee.getName());
        }
        response.address = function.getEntryPoint().getUnsignedOffset();
        response.function = function.getName();
        response.function_signature = function.getPrototypeString(true, true);

        try {
            decompiler.initialize();
        } catch (Exception e) {
            // Not a problem
        }

        DecompInterface decompilerInterface =  decompiler.getDecompiler();
        if (decompilerInterface != null) {
            Msg.info(this, "Using decompiler interface");
            DecompileResults decompiled = decompilerInterface.decompileFunction(function, 60, monitor);
            if (decompiled == null) {
                Boolean isThunk = function.isThunk();
                response.error_message = "Failed to decompile function " + function.getName();
                if (isThunk) {
                    // If the thing is a thunk, we cannot decompile it (no implementation)
                    // and we need to tell the LLM about it so it does not try again.
                    response.error_message += " is a thunk";
                }
                return response;
            }
            DecompiledFunction decompiledFunction = decompiled.getDecompiledFunction();
            if (decompiledFunction == null) {
                Boolean isThunk = function.isThunk();
                response.error_message = "Failed to decompile function " + function.getName();
                if (isThunk) {
                    // If the thing is a thunk, we cannot decompile it (no implementation)
                    // and we need to tell the LLM about it so it does not try again.
                    response.error_message += " is a thunk";
                }
                return response;
            }
            response.decompilation = decompiledFunction.getC();
            LocalSymbolMap symbolMap = decompiled.getHighFunction().getLocalSymbolMap();
            Iterator<HighSymbol> symbolIterator = symbolMap.getSymbols();
            while (symbolIterator.hasNext()) {
                HighSymbol symbol = symbolIterator.next();
                String name = symbol.getName();
                String data_type = symbol.getDataType().toString();
                String storage = symbol.getStorage().toString();
                int size = symbol.getSize();
                Msg.info(this, "Symbol: " + name + " " + data_type + " " + storage + " " + size);
                RevaGetDecompilationResponse.RevaVariable variable = response.new RevaVariable();
                variable.name = name;
                variable.data_type = data_type;
                variable.storage = storage;
                variable.size = size;
                response.variables.add(variable);
            }
        } else {
            // Get the decompilation
            Msg.info(this, "Using flat decompiler");
            try {
                response.decompilation = decompiler.decompile(function);
            } catch (Exception e) {
                response.error_message = "Failed to decompile function " + function.getName();
                Msg.error(this, "Failed to decompile function " + function.getName(), e);
            }
        }

        return response;
    }
}
