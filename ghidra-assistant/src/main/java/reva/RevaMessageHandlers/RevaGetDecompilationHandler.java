package reva.RevaMessageHandlers;

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import reva.RevaService;
import reva.RevaProtocol.RevaGetDecompilation;
import reva.RevaProtocol.RevaGetDecompilationResponse;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

import java.util.ArrayList;

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

            for (Function f : service.currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName(true).equals(decompilationMessage.function)) {
                    function = f;
                    break;
                }
            }

            if (function == null) {
                // Let's find the function by symbol
                for (Symbol symbol : service.currentProgram.getSymbolTable().getAllSymbols(true)) {
                    if (symbol.getName().equals(decompilationMessage.function)) {
                        function = service.currentProgram.getFunctionManager().getFunctionAt(symbol.getAddress());
                        if (function != null) {
                            break;
                        }
                    }
                }
            }

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

        // Get the decompilation
        try {

            response.decompilation = decompiler.decompile(function);
        } catch (Exception e) {
            response.error_message = "Failed to decompile function " + function.getName();
            Msg.error(this, "Failed to decompile function " + function.getName(), e);
        }

        return response;
    }
}
